#Requires -Version 5.0
<#
.SYNOPSIS
  Security Vitals installer for Windows - no admin rights required.

.DESCRIPTION
  Security Vitals runs INSIDE WSL (its triggers use bash / tmNIDS / curl) and serves
  a local web UI you open in the Windows browser. This installer:
    * finds a WSL distro and a Python 3.8+ inside it; if Python is missing it installs
      it into the distro (as root, no password prompt - apt/dnf/apk/pacman),
    * copies the app into the WSL distro (native filesystem, fast),
    * writes a Windows launcher that starts the server in WSL and opens the browser,
    * creates Start Menu / Desktop shortcuts to that launcher,
    * registers in Settings > Apps ("Add/Remove Programs") with an uninstaller.

  It does NOT install WSL itself (that needs admin + a reboot). If WSL is missing it
  tells you how: run 'wsl --install' in an elevated PowerShell, reboot, then re-run this.

  Run it by double-clicking install.bat, or directly:
    powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1

.PARAMETER InstallDir
  Windows folder for the launcher + shortcuts (default %LOCALAPPDATA%\Programs\SecVitals).
.PARAMETER WslDir
  Folder inside WSL for the app (default ~/.local/share/secvitals in the distro).
.PARAMETER Distro
  WSL distro to target (default: the WSL default distro).
.PARAMETER Port
  Loopback port the console serves on (default 8787).
.PARAMETER NoGui
  Use console output instead of the setup window.
.PARAMETER Silent
  No window, no prompts (implies -NoGui).
.PARAMETER NoDesktopShortcut / -NoStartMenuShortcut
  Skip that shortcut.
.PARAMETER SkipPythonInstall
  Never install Python into WSL; fail instead if a usable one isn't found.
.PARAMETER Branch
  Git branch to fetch when downloading from GitHub (default: main).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\SecVitals",
    [string]$WslDir = "",
    [string]$Distro = "",
    [int]$Port = 8787,
    [switch]$NoGui,
    [switch]$Silent,
    [switch]$NoDesktopShortcut,
    [switch]$NoStartMenuShortcut,
    [switch]$SkipPythonInstall,
    [string]$Branch = "main"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$AppName = "Security Vitals"
$AppKey  = "SecVitals"                 # registry key + folder name
$Repo    = "robertsonc/secvitals"
$RepoUrl = "https://github.com/$Repo"
# App files copied INTO WSL (the app runs there). Installer files stay on Windows.
$AppItems = @("secvitals.py", "config", "assets", "docs", "README.md", "requirements.txt")

if ($Silent) { $NoGui = $true }
$env:WSL_UTF8 = "1"                    # make wsl.exe emit UTF-8, not UTF-16

# script-scoped install context (filled by the probe / GUI)
$script:Distro  = $Distro
$script:WslHome = ""
$script:WslDir  = $WslDir
$script:Port    = $Port

# PS 5.1 defaults to TLS 1.0 - GitHub requires TLS 1.2+.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# ---------------------------------------------------------------------------
# Logging - console by default; the GUI redirects this into its log box.
# ---------------------------------------------------------------------------
$script:GuiLogBox = $null
function Write-Log {
    param([string]$Message)
    if ($script:GuiLogBox -ne $null) {
        $script:GuiLogBox.AppendText($Message + [Environment]::NewLine)
        [System.Windows.Forms.Application]::DoEvents()
    } else {
        Write-Host $Message
    }
}

# ---------------------------------------------------------------------------
# WSL discovery + Python-in-WSL
# ---------------------------------------------------------------------------
function Get-DefaultDistro {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $null }
    # Prefer the distro marked default ('*') in `wsl -l -v`.
    try {
        foreach ($ln in (& wsl.exe -l -v 2>$null)) {
            if ("$ln" -match '^\s*\*\s+(\S+)') { return $Matches[1] }
        }
    } catch {}
    try {
        foreach ($ln in (& wsl.exe -l -q 2>$null)) {
            $t = "$ln".Trim(); if ($t) { return $t }
        }
    } catch {}
    return $null
}

function Invoke-Wsl {
    # Run a bash -lc command in the target distro. Returns stdout lines.
    param([string]$Command, [switch]$AsRoot)
    $a = @("-d", $script:Distro)
    if ($AsRoot) { $a += @("-u", "root") }
    $a += @("-e", "bash", "-lc", $Command)
    return (& wsl.exe @a)
}

function Test-Wsl {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }
    if (-not $script:Distro) { $script:Distro = Get-DefaultDistro }
    if (-not $script:Distro) { return $false }
    try {
        $ok = (Invoke-Wsl -Command "echo __wsl_ok__" | Where-Object { "$_".Trim() -eq "__wsl_ok__" })
        return [bool]$ok
    } catch { return $false }
}

function Get-WslHome {
    $h = (Invoke-Wsl -Command 'printf %s "$HOME"' | Select-Object -First 1)
    $h = "$h".Trim()
    if (-not $h) { $h = "/root" }
    return $h
}

function Get-WslPython {
    # Returns a version string like "3.12", or $null. Security Vitals needs no Tkinter.
    try {
        $out = Invoke-Wsl -Command 'command -v python3 >/dev/null 2>&1 && python3 -c "import sys;print(\"%d.%d\"%tuple(sys.version_info[:2]))"'
    } catch { return $null }
    $v = ($out | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) | Select-Object -First 1
    if ($v -and ($v -match '^(\d+)\.(\d+)$')) {
        if (([int]$Matches[1] -gt 3) -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 8)) { return $v }
    }
    return $null
}

function Install-WslPython {
    Write-Log "Installing python3 into WSL distro '$($script:Distro)' (as root) ..."
    $sh = 'set -e; ' +
          'if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y python3; ' +
          'elif command -v dnf >/dev/null 2>&1; then dnf install -y python3; ' +
          'elif command -v apk >/dev/null 2>&1; then apk add --no-cache python3; ' +
          'elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm python; ' +
          'else echo NO_PKG_MGR; exit 1; fi'
    Invoke-Wsl -Command $sh -AsRoot | ForEach-Object { if ("$_".Trim()) { Write-Log "  $_" } }
    $v = Get-WslPython
    if (-not $v) {
        throw "Could not install python3 in WSL automatically. Open the '$($script:Distro)' distro and install it (e.g. 'sudo apt install python3'), then re-run setup."
    }
    Write-Log "python3 $v ready in WSL."
    return $v
}

function Resolve-WslPython {
    $v = Get-WslPython
    if ($v) { Write-Log "Found Python $v in WSL '$($script:Distro)'."; return $v }
    if ($SkipPythonInstall) { throw "No Python 3.8+ in WSL and -SkipPythonInstall was given." }
    Write-Log "No usable Python in WSL - installing it for you."
    return Install-WslPython
}

# ---------------------------------------------------------------------------
# App source (local folder next to this script, or the GitHub branch zip)
# ---------------------------------------------------------------------------
function Get-RemoteFile {
    param([string]$Url, [string]$Destination, [string]$What)
    Write-Log "Downloading $What ..."
    Write-Log "  $Url"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "secvitals-installer")
    try {
        $task = $wc.DownloadFileTaskAsync($Url, $Destination)
        while (-not $task.IsCompleted) {
            Start-Sleep -Milliseconds 100
            if ($script:GuiLogBox -ne $null) { [System.Windows.Forms.Application]::DoEvents() }
        }
        if ($task.IsFaulted) { throw $task.Exception.InnerException }
    } finally {
        $wc.Dispose()
    }
    $mb = [math]::Round((Get-Item $Destination).Length / 1MB, 2)
    Write-Log "  done ($mb MB)."
}

function Get-SourceDir {
    if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "secvitals.py"))) {
        Write-Log "Installing from local folder: $PSScriptRoot"
        return $PSScriptRoot
    }
    $safe = $Branch -replace '[\\/:*?"<>|]', '-'
    $zip = Join-Path $env:TEMP "secvitals-$safe.zip"
    $dst = Join-Path $env:TEMP "secvitals-unzip"
    Get-RemoteFile -Url "https://codeload.github.com/$Repo/zip/refs/heads/$Branch" `
                   -Destination $zip -What "$AppName ($Branch branch)"
    if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $dst -Force
    Remove-Item $zip -ErrorAction SilentlyContinue
    $inner = Get-ChildItem -Path $dst -Directory | Select-Object -First 1
    if (-not $inner -or -not (Test-Path (Join-Path $inner.FullName "secvitals.py"))) {
        throw "Downloaded archive doesn't contain secvitals.py - wrong branch?"
    }
    return $inner.FullName
}

function Get-AppVersion {
    param([string]$Dir)
    $m = Select-String -Path (Join-Path $Dir "secvitals.py") `
                       -Pattern '^__version__\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return "0.0.0"
}

function Install-AppFiles {
    param([string]$SourceDir)
    Write-Log "Copying application files into WSL: $($script:WslDir)"
    # Translate the Windows source dir to a /mnt path inside WSL (wslpath handles the
    # backslashes; do NOT route the raw Windows path through bash).
    $wslSrc = (& wsl.exe -d $script:Distro -e wslpath -a "$SourceDir" | Select-Object -First 1)
    $wslSrc = "$wslSrc".Trim().TrimEnd('/')
    if (-not $wslSrc) { throw "could not translate the source path into WSL." }
    $items = ($AppItems | ForEach-Object { "'$_'" }) -join ' '
    $sh = "set -e; dst='$($script:WslDir)'; src='$wslSrc'; mkdir -p `"`$dst`"; " +
          "for it in $items; do if [ -e `"`$src/`$it`" ]; then cp -rf `"`$src/`$it`" `"`$dst/`"; fi; done; " +
          "echo copied"
    $r = Invoke-Wsl -Command $sh
    if (-not ($r | Where-Object { "$_".Trim() -eq "copied" })) { throw "copy into WSL failed." }
}

# ---------------------------------------------------------------------------
# Windows launcher + shortcuts + Add/Remove Programs
# ---------------------------------------------------------------------------
function New-Launcher {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    # Delays a moment, then opens the default browser (kept separate to avoid cmd
    # nested-quote pitfalls).
    $opener = @(
        "@echo off",
        "ping -n 4 127.0.0.1 >nul",
        "start `"`" http://127.0.0.1:$($script:Port)/"
    ) -join "`r`n"
    Set-Content -Path (Join-Path $InstallDir "open-browser.cmd") -Value $opener -Encoding ASCII

    # The launcher: start the browser opener in the background, then run the server in
    # WSL in THIS window. Closing the window stops the console.
    $launch = @(
        "@echo off",
        "title $AppName",
        "echo Starting $AppName in WSL ($($script:Distro)) ...",
        "echo A browser tab opens at http://127.0.0.1:$($script:Port)/  -  close THIS window to stop.",
        "start `"`" /b `"%~dp0open-browser.cmd`"",
        "wsl.exe -d $($script:Distro) -e bash -lc `"cd '$($script:WslDir)' && exec python3 secvitals.py --no-browser --port $($script:Port)`""
    ) -join "`r`n"
    Set-Content -Path (Join-Path $InstallDir "launch.cmd") -Value $launch -Encoding ASCII

    # Updater: runs the app's hardened, signed self-update inside WSL.
    $upd = @(
        "@echo off",
        "title $AppName updater",
        "wsl.exe -d $($script:Distro) -e bash -lc `"cd '$($script:WslDir)' && python3 secvitals.py --update`"",
        "pause"
    ) -join "`r`n"
    Set-Content -Path (Join-Path $InstallDir "update.cmd") -Value $upd -Encoding ASCII

    # install-info.txt: read by uninstall.ps1 to remove the WSL files too.
    $info = @("Distro=$($script:Distro)", "WslDir=$($script:WslDir)", "Port=$($script:Port)") -join "`r`n"
    Set-Content -Path (Join-Path $InstallDir "install-info.txt") -Value $info -Encoding ASCII
}

function Copy-InstallerFiles {
    param([string]$SourceDir)
    foreach ($f in @("uninstall.ps1", "install.ps1", "install.bat")) {
        $src = Join-Path $SourceDir $f
        if (Test-Path $src) { Copy-Item $src -Destination $InstallDir -Force }
    }
    $ico = Join-Path $SourceDir "assets\secvitals.ico"
    if (Test-Path $ico) { Copy-Item $ico -Destination $InstallDir -Force }
}

function New-AppShortcut {
    param([string]$LinkPath)
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($LinkPath)
    $lnk.TargetPath = Join-Path $InstallDir "launch.cmd"
    $lnk.WorkingDirectory = $InstallDir
    $lnk.Description = "$AppName - local security-trigger console (runs in WSL)"
    $ico = Join-Path $InstallDir "secvitals.ico"
    if (Test-Path $ico) { $lnk.IconLocation = "$ico,0" }
    $lnk.Save()
    Write-Log "Shortcut: $LinkPath"
}

function Install-Shortcuts {
    if (-not $NoStartMenuShortcut) {
        $programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
        New-AppShortcut -LinkPath (Join-Path $programs "$AppName.lnk")
    }
    if (-not $NoDesktopShortcut) {
        $desktop = [Environment]::GetFolderPath("Desktop")
        New-AppShortcut -LinkPath (Join-Path $desktop "$AppName.lnk")
    }
}

function Register-App {
    param([string]$Version)
    $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppKey"
    New-Item -Path $reg -Force | Out-Null
    $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $uninst = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
    $sizeKB = [int]((Get-ChildItem -Path $InstallDir -Recurse -File |
                     Measure-Object -Property Length -Sum).Sum / 1KB)
    Set-ItemProperty -Path $reg -Name "DisplayName" -Value $AppName
    Set-ItemProperty -Path $reg -Name "DisplayVersion" -Value $Version
    Set-ItemProperty -Path $reg -Name "Publisher" -Value $AppName
    Set-ItemProperty -Path $reg -Name "InstallLocation" -Value $InstallDir
    Set-ItemProperty -Path $reg -Name "DisplayIcon" -Value "$InstallDir\secvitals.ico"
    Set-ItemProperty -Path $reg -Name "UninstallString" -Value $uninst
    Set-ItemProperty -Path $reg -Name "QuietUninstallString" -Value "$uninst -Silent"
    Set-ItemProperty -Path $reg -Name "URLInfoAbout" -Value $RepoUrl
    Set-ItemProperty -Path $reg -Name "HelpLink" -Value $RepoUrl
    Set-ItemProperty -Path $reg -Name "InstallDate" -Value (Get-Date -Format "yyyyMMdd")
    Set-ItemProperty -Path $reg -Name "NoModify" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "NoRepair" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "EstimatedSize" -Value $sizeKB -Type DWord
    Write-Log "Registered in Settings > Apps (uninstall from there any time)."
}

# ---------------------------------------------------------------------------
# The install itself (shared by GUI and console modes)
# ---------------------------------------------------------------------------
function Invoke-Install {
    Write-Log "=== $AppName setup ==="
    if (-not (Test-Wsl)) {
        throw "WSL was not found. Install it first: open an elevated PowerShell, run 'wsl --install', reboot, then re-run this setup."
    }
    if (-not $script:WslHome) { $script:WslHome = Get-WslHome }
    if (-not $script:WslDir) { $script:WslDir = "$($script:WslHome)/.local/share/secvitals" }
    Write-Log "Target: WSL distro '$($script:Distro)', folder $($script:WslDir)"
    $pyv = Resolve-WslPython
    $srcDir = Get-SourceDir
    $version = Get-AppVersion -Dir $srcDir
    Write-Log "Installing $AppName $version ..."
    Install-AppFiles -SourceDir $srcDir
    New-Launcher
    Copy-InstallerFiles -SourceDir $srcDir
    Install-Shortcuts
    Register-App -Version $version
    Write-Log ""
    Write-Log "$AppName $version installed."
    Write-Log "  App (WSL):  $($script:WslDir)"
    Write-Log "  Launcher:   $InstallDir\launch.cmd"
    Write-Log "Start it from the Start Menu ('$AppName'): the console starts in WSL and"
    Write-Log "your browser opens at http://127.0.0.1:$($script:Port)/ ."
    return [pscustomobject]@{ Version = $version; Python = $pyv }
}

function Start-App {
    Start-Process -FilePath (Join-Path $InstallDir "launch.cmd") -WorkingDirectory $InstallDir
}

# ---------------------------------------------------------------------------
# WinForms setup window (default). Falls back to console when unavailable.
# ---------------------------------------------------------------------------
function Show-InstallerGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $bg     = [System.Drawing.Color]::FromArgb(26, 29, 33)
    $panel  = [System.Drawing.Color]::FromArgb(35, 39, 46)
    $txtCol = [System.Drawing.Color]::FromArgb(242, 244, 245)
    $dimCol = [System.Drawing.Color]::FromArgb(154, 163, 173)
    $warn   = [System.Drawing.Color]::FromArgb(255, 131, 0)
    $green  = [System.Drawing.Color]::FromArgb(1, 169, 130)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$AppName setup"
    $form.ClientSize = New-Object System.Drawing.Size(560, 462)
    $form.BackColor = $bg
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.StartPosition = "CenterScreen"

    $title = New-Object System.Windows.Forms.Label
    $title.Text = "$AppName setup"
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $title.ForeColor = $txtCol; $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(20, 14)
    $form.Controls.Add($title)

    $sub = New-Object System.Windows.Forms.Label
    $sub.Text = "Fires security-trigger traffic; reads the local result. Runs in WSL, opens in your browser."
    $sub.Font = New-Object System.Drawing.Font("Segoe UI", 9); $sub.ForeColor = $dimCol
    $sub.AutoSize = $true; $sub.Location = New-Object System.Drawing.Point(22, 44)
    $form.Controls.Add($sub)

    $wslLabel = New-Object System.Windows.Forms.Label
    $wslLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9); $wslLabel.MaximumSize = New-Object System.Drawing.Size(516, 0)
    $wslLabel.AutoSize = $true; $wslLabel.Location = New-Object System.Drawing.Point(22, 70)
    $wslReady = $false
    if (Test-Wsl) {
        if (-not $script:WslHome) { $script:WslHome = Get-WslHome }
        if (-not $script:WslDir) { $script:WslDir = "$($script:WslHome)/.local/share/secvitals" }
        $pyv = Get-WslPython
        if ($pyv) {
            $wslLabel.Text = "WSL '$($script:Distro)' with Python $pyv found - ready to install."
            $wslLabel.ForeColor = $green; $wslReady = $true
        } else {
            $wslLabel.Text = "WSL '$($script:Distro)' found; Python 3 will be added to it (per-user, apt/dnf/apk)."
            $wslLabel.ForeColor = $dimCol; $wslReady = $true
        }
    } else {
        $wslLabel.Text = "WSL not found. In an elevated PowerShell run 'wsl --install', reboot, then re-run this setup."
        $wslLabel.ForeColor = $warn
    }
    $form.Controls.Add($wslLabel)

    $dirLabel = New-Object System.Windows.Forms.Label
    $dirLabel.Text = "Install folder (inside WSL):"; $dirLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dirLabel.ForeColor = $txtCol; $dirLabel.AutoSize = $true
    $dirLabel.Location = New-Object System.Drawing.Point(22, 100)
    $form.Controls.Add($dirLabel)

    $dirBox = New-Object System.Windows.Forms.TextBox
    $dirBox.Text = $(if ($script:WslDir) { $script:WslDir } else { "~/.local/share/secvitals" })
    $dirBox.Font = New-Object System.Drawing.Font("Consolas", 9); $dirBox.BackColor = $panel
    $dirBox.ForeColor = $txtCol; $dirBox.BorderStyle = "FixedSingle"
    $dirBox.Location = New-Object System.Drawing.Point(24, 120); $dirBox.Size = New-Object System.Drawing.Size(516, 24)
    $form.Controls.Add($dirBox)

    $portLabel = New-Object System.Windows.Forms.Label
    $portLabel.Text = "Port:"; $portLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $portLabel.ForeColor = $txtCol; $portLabel.AutoSize = $true
    $portLabel.Location = New-Object System.Drawing.Point(22, 152)
    $form.Controls.Add($portLabel)

    $portBox = New-Object System.Windows.Forms.TextBox
    $portBox.Text = "$($script:Port)"; $portBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $portBox.BackColor = $panel; $portBox.ForeColor = $txtCol; $portBox.BorderStyle = "FixedSingle"
    $portBox.Location = New-Object System.Drawing.Point(62, 150); $portBox.Size = New-Object System.Drawing.Size(56, 24)
    $form.Controls.Add($portBox)

    $cbStart = New-Object System.Windows.Forms.CheckBox
    $cbStart.Text = "Start Menu shortcut"; $cbStart.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cbStart.ForeColor = $txtCol; $cbStart.Checked = -not $NoStartMenuShortcut; $cbStart.AutoSize = $true
    $cbStart.Location = New-Object System.Drawing.Point(150, 152)
    $form.Controls.Add($cbStart)

    $cbDesk = New-Object System.Windows.Forms.CheckBox
    $cbDesk.Text = "Desktop shortcut"; $cbDesk.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cbDesk.ForeColor = $txtCol; $cbDesk.Checked = -not $NoDesktopShortcut; $cbDesk.AutoSize = $true
    $cbDesk.Location = New-Object System.Drawing.Point(330, 152)
    $form.Controls.Add($cbDesk)

    $log = New-Object System.Windows.Forms.TextBox
    $log.Multiline = $true; $log.ReadOnly = $true; $log.ScrollBars = "Vertical"
    $log.Font = New-Object System.Drawing.Font("Consolas", 8.5); $log.BackColor = $panel
    $log.ForeColor = $txtCol; $log.BorderStyle = "FixedSingle"
    $log.Location = New-Object System.Drawing.Point(24, 182); $log.Size = New-Object System.Drawing.Size(516, 198)
    $form.Controls.Add($log)

    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Style = "Continuous"
    $bar.Location = New-Object System.Drawing.Point(24, 388); $bar.Size = New-Object System.Drawing.Size(516, 6)
    $form.Controls.Add($bar)

    $btnInstall = New-Object System.Windows.Forms.Button
    $btnInstall.Text = "Install"; $btnInstall.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnInstall.FlatStyle = "Flat"; $btnInstall.BackColor = $green; $btnInstall.ForeColor = [System.Drawing.Color]::White
    $btnInstall.FlatAppearance.BorderSize = 0
    $btnInstall.Location = New-Object System.Drawing.Point(430, 406); $btnInstall.Size = New-Object System.Drawing.Size(110, 36)
    $btnInstall.Enabled = $wslReady
    $form.Controls.Add($btnInstall)

    $btnLaunch = New-Object System.Windows.Forms.Button
    $btnLaunch.Text = "Launch"; $btnLaunch.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnLaunch.FlatStyle = "Flat"; $btnLaunch.BackColor = $green; $btnLaunch.ForeColor = [System.Drawing.Color]::White
    $btnLaunch.FlatAppearance.BorderSize = 0
    $btnLaunch.Location = New-Object System.Drawing.Point(430, 406); $btnLaunch.Size = New-Object System.Drawing.Size(110, 36)
    $btnLaunch.Visible = $false
    $form.Controls.Add($btnLaunch)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"; $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnClose.FlatStyle = "Flat"; $btnClose.BackColor = $panel; $btnClose.ForeColor = $txtCol
    $btnClose.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(54, 59, 68)
    $btnClose.Location = New-Object System.Drawing.Point(330, 406); $btnClose.Size = New-Object System.Drawing.Size(90, 36)
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)

    $script:Installing = $false
    $form.Add_FormClosing({
        param($sender, $e)
        if ($script:Installing) {
            [System.Windows.Forms.MessageBox]::Show(
                "Setup is still running - let it finish first.", "$AppName setup",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            $e.Cancel = $true
        }
    })
    $btnInstall.Add_Click({
        $p = 0
        if (-not [int]::TryParse($portBox.Text.Trim(), [ref]$p) -or $p -lt 1 -or $p -gt 65535) {
            [System.Windows.Forms.MessageBox]::Show("Port must be a number between 1 and 65535.", "$AppName setup",
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            return
        }
        $btnInstall.Enabled = $false; $btnClose.Enabled = $false
        $dirBox.Enabled = $false; $portBox.Enabled = $false; $cbStart.Enabled = $false; $cbDesk.Enabled = $false
        $script:Installing = $true
        $script:WslDir = $dirBox.Text.Trim()
        $script:Port = $p
        $script:NoStartMenuShortcut = -not $cbStart.Checked
        $script:NoDesktopShortcut = -not $cbDesk.Checked
        $script:GuiLogBox = $log
        $bar.Style = "Marquee"
        try {
            [void](Invoke-Install)
            $bar.Style = "Continuous"; $bar.Value = 100
            $btnInstall.Visible = $false; $btnLaunch.Visible = $true
        } catch {
            $bar.Style = "Continuous"; $bar.Value = 0
            Write-Log ""; Write-Log "INSTALL FAILED: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "$AppName setup",
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            $btnInstall.Enabled = $true; $dirBox.Enabled = $true; $portBox.Enabled = $true
            $cbStart.Enabled = $true; $cbDesk.Enabled = $true
        } finally {
            $script:Installing = $false; $btnClose.Enabled = $true
        }
    })
    $btnLaunch.Add_Click({ Start-App; $form.Close() })

    [System.Windows.Forms.Application]::EnableVisualStyles()
    $form.Add_Shown({ $form.Activate() }) | Out-Null
    [void]$form.ShowDialog()
    $form.Dispose()
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
$useGui = -not $NoGui
if ($useGui) {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        if (-not [Environment]::UserInteractive) { $useGui = $false }
    } catch { $useGui = $false }
}

if ($useGui) {
    Show-InstallerGui
} else {
    if (-not $Silent) {
        Write-Host "=== $AppName setup (console) ==="
        Write-Host "WSL distro     : $(if ($script:Distro) { $script:Distro } else { '(default)' })"
        Write-Host "Windows folder : $InstallDir"
        Write-Host "Port           : $($script:Port)"
        $answer = Read-Host "Proceed? [Y/n]"
        if ($answer -and $answer.Trim().ToLower().StartsWith("n")) { Write-Host "Cancelled."; exit 1 }
    }
    [void](Invoke-Install)
    if (-not $Silent) {
        $answer = Read-Host "Launch $AppName now? [Y/n]"
        if (-not ($answer -and $answer.Trim().ToLower().StartsWith("n"))) { Start-App }
    }
}
