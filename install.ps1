#Requires -Version 5.0
<#
.SYNOPSIS
  Security Vitals installer for Windows - no admin rights required.

.DESCRIPTION
  Installs Security Vitals for the current user:
    * finds Windows Python 3.8+ WITH Tkinter (the console is a Tkinter window); if
      none, downloads the official python.org installer and installs it per-user,
    * verifies WSL and makes sure python3 exists inside the target distro - each
      fired trigger runs a short-lived worker there (native bash / curl, on the
      SD-WAN egress path). Nothing is copied into the distro; the console streams
      its own source to `python3 -` over stdin,
    * copies the app to the install folder and pins the verified WSL distro into
      config\settings.yaml,
    * creates Start Menu / Desktop shortcuts that open the window (pythonw.exe, so
      no console window),
    * registers in Settings > Apps ("Add/Remove Programs") with an uninstaller.

  Run it by double-clicking install.bat, or directly:
    powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1

.PARAMETER InstallDir
  Where to install (default: %LOCALAPPDATA%\Programs\SecVitals).
.PARAMETER Distro
  WSL distro to run the worker in (default: wsl.exe's default distro).
.PARAMETER NoGui
  Use console output instead of the setup window.
.PARAMETER Silent
  No window, no prompts - install with the given options (implies -NoGui).
.PARAMETER NoDesktopShortcut
  Skip the desktop shortcut.
.PARAMETER NoStartMenuShortcut
  Skip the Start Menu shortcut.
.PARAMETER SkipPythonInstall
  Never install Python (Windows or WSL); fail / warn instead.
.PARAMETER Branch
  Git branch to fetch when downloading from GitHub (default: main).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\SecVitals",
    [string]$Distro = "",
    [switch]$NoGui,
    [switch]$Silent,
    [switch]$NoDesktopShortcut,
    [switch]$NoStartMenuShortcut,
    [switch]$SkipPythonInstall,
    [string]$Branch = "main"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:WSL_UTF8 = "1"

$AppName       = "Security Vitals"
$AppKey        = "SecVitals"   # registry key + folder name
$Repo          = "robertsonc/secvitals"
$RepoUrl       = "https://github.com/$Repo"
$PythonVersion = "3.12.10"     # installed only when no usable Windows Python exists
$AppFiles      = @("secvitals.py", "install.ps1", "uninstall.ps1", "install.bat",
                   "README.md", "requirements.txt")
$AppDirs       = @("config", "assets", "docs")

$script:Distro    = $Distro
$script:WslPython = "python3"

if ($Silent) { $NoGui = $true }

# PS 5.1 defaults to TLS 1.0 - python.org and GitHub require TLS 1.2+.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12
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
# Windows Python discovery / install (needs Tkinter - the console is a Tk window)
# ---------------------------------------------------------------------------
function Test-PythonExe {
    # Probe one candidate interpreter. Returns $null or an object with
    # Exe / Version / HasTk. A temp probe file sidesteps every PowerShell
    # argument-quoting pitfall, and real execution filters out the
    # Microsoft Store stub (which exits non-zero when given arguments).
    param([string]$Command, [string[]]$PreArgs = @())
    $probe = Join-Path $env:TEMP "secv-pyprobe.py"
    Set-Content -Path $probe -Encoding ASCII -Value @(
        "import sys, importlib.util",
        "print('%d.%d' % sys.version_info[:2])",
        "print(sys.executable)",
        "print(1 if importlib.util.find_spec('_tkinter') else 0)"
    )
    try {
        $out = & $Command @PreArgs $probe 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $lines = @($out | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($lines.Count -lt 3) { return $null }
        $ver = $null
        if (-not [Version]::TryParse($lines[0], [ref]$ver)) { return $null }
        return [pscustomobject]@{
            Exe     = $lines[1]
            Version = $ver
            HasTk   = ($lines[2] -eq "1")
        }
    } catch {
        return $null
    } finally {
        Remove-Item $probe -ErrorAction SilentlyContinue
    }
}

function Find-Python {
    # Try the py launcher, then PATH names, then the default per-user and
    # per-machine install folders (a just-installed Python isn't on THIS
    # process's PATH yet - the environment was read at startup).
    $tries = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $tries += ,@("py", @("-3"))
    }
    foreach ($name in @("python", "python3")) {
        if (Get-Command $name -ErrorAction SilentlyContinue) {
            $tries += ,@($name, @())
        }
    }
    foreach ($root in @("$env:LOCALAPPDATA\Programs\Python",
                        $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        foreach ($exe in (Get-ChildItem -Path "$root\Python3*\python.exe" `
                          -ErrorAction SilentlyContinue |
                          Sort-Object FullName -Descending)) {
            $tries += ,@($exe.FullName, @())
        }
    }
    $best = $null
    foreach ($t in $tries) {
        $found = Test-PythonExe -Command $t[0] -PreArgs $t[1]
        if (-not $found) { continue }
        if ($found.Version -lt [Version]"3.8") { continue }
        if ($found.HasTk) { return $found }        # ideal: take it
        if (-not $best) { $best = $found }         # remember a tk-less one
    }
    return $best  # may be $null, or a Python without Tkinter
}

function Get-RemoteFile {
    # Async download + message pump so the GUI stays responsive.
    param([string]$Url, [string]$Destination, [string]$What)
    Write-Log "Downloading $What ..."
    Write-Log "  $Url"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "secvitals-installer")
    try {
        $task = $wc.DownloadFileTaskAsync($Url, $Destination)
        while (-not $task.IsCompleted) {
            Start-Sleep -Milliseconds 100
            if ($script:GuiLogBox -ne $null) {
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
        if ($task.IsFaulted) { throw $task.Exception.InnerException }
    } finally {
        $wc.Dispose()
    }
    $mb = [math]::Round((Get-Item $Destination).Length / 1MB, 1)
    Write-Log "  done ($mb MB)."
}

function Install-Python {
    # Silent per-user install from python.org: no admin, includes Tkinter,
    # pip and the py launcher, and adds Python to the user PATH.
    $suffix = switch ($env:PROCESSOR_ARCHITECTURE) {
        "ARM64" { "-arm64" }
        "AMD64" { "-amd64" }
        default { "" }       # 32-bit x86
    }
    $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion$suffix.exe"
    $tmp = Join-Path $env:TEMP "python-$PythonVersion-setup.exe"
    Get-RemoteFile -Url $url -Destination $tmp -What "Python $PythonVersion"
    Write-Log "Installing Python $PythonVersion (current user, this takes a minute or two) ..."
    $arguments = @("/quiet", "InstallAllUsers=0", "InstallLauncherAllUsers=0",
                   "PrependPath=1", "Include_tcltk=1", "Include_pip=1",
                   "Include_test=0", "AssociateFiles=0")
    $proc = Start-Process -FilePath $tmp -ArgumentList $arguments -PassThru
    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds 250
        if ($script:GuiLogBox -ne $null) {
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        throw "Python installer failed (exit code $($proc.ExitCode))."
    }
    $py = Find-Python
    if (-not $py) { throw "Python was installed but can't be located - open a NEW terminal and re-run the installer." }
    if (-not $py.HasTk) { throw "Python was installed but Tkinter is missing - re-run the python.org installer and enable 'tcl/tk and IDLE'." }
    Write-Log "Installed Python $($py.Version) -> $($py.Exe)"
    return $py
}

function Resolve-Python {
    $py = Find-Python
    if ($py -and $py.HasTk) {
        Write-Log "Found Windows Python $($py.Version) with Tkinter -> $($py.Exe)"
        return $py
    }
    if ($py -and -not $py.HasTk) {
        Write-Log "Found Python $($py.Version) at $($py.Exe), but WITHOUT Tkinter (the GUI toolkit)."
        if ($SkipPythonInstall) {
            throw "Python lacks Tkinter and -SkipPythonInstall was given. Re-run the python.org installer and enable 'tcl/tk and IDLE'."
        }
        Write-Log "Installing a separate per-user Python $PythonVersion that includes it ..."
        return Install-Python
    }
    if ($SkipPythonInstall) {
        throw "No Python 3.8+ found and -SkipPythonInstall was given."
    }
    Write-Log "No usable Windows Python found - installing Python $PythonVersion for the current user."
    return Install-Python
}

# ---------------------------------------------------------------------------
# WSL discovery + python3-in-distro (where each fired trigger's worker runs)
# ---------------------------------------------------------------------------
function Get-DefaultDistro {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $null }
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
    # Run a bash command in the target distro. The script is base64-encoded so its own
    # quoting survives the PowerShell -> wsl.exe -> bash argument boundary intact: Windows
    # PowerShell mangles embedded double quotes when passing native-exe arguments, which
    # otherwise breaks any command containing quotes (the version probe, the pkg install).
    param([string]$Command, [switch]$AsRoot)
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Command))
    $a = @("-d", $script:Distro)
    if ($AsRoot) { $a += @("-u", "root") }
    $a += @("-e", "bash", "-lc", "echo $b64 | base64 -d | bash")
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

function Get-WslPython {
    # Returns a version string like "3.12", or $null. The worker needs no Tkinter in WSL.
    # `python3 --version` avoids embedded quotes; scanning every line means a login-shell
    # banner can't be mistaken for the version.
    try {
        $out = Invoke-Wsl -Command 'command -v python3 >/dev/null 2>&1 && python3 --version 2>&1 || true'
    } catch { return $null }
    foreach ($line in @($out)) {
        if ("$line" -match 'Python\s+(\d+)\.(\d+)') {
            if (([int]$Matches[1] -gt 3) -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 8)) {
                return "$($Matches[1]).$($Matches[2])"
            }
        }
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

function Resolve-WslWorker {
    # Best-effort: verify WSL + python3 in the distro so triggers can fire. WSL problems
    # DON'T block the install (the window still opens; firing shows a clear error) - they
    # are surfaced as warnings so the SE can fix WSL and try again without reinstalling.
    if (-not (Test-Wsl)) {
        Write-Log "WARNING: WSL was not detected (or has no default distro)."
        Write-Log "  Security Vitals fires each trigger through WSL. Install WSL (`"wsl --install`")"
        Write-Log "  and a distro, then re-run setup. The window will still open meanwhile."
        return $false
    }
    Write-Log "Using WSL distro '$($script:Distro)' for the trigger worker."
    $v = Get-WslPython
    if (-not $v) {
        if ($SkipPythonInstall) {
            Write-Log "WARNING: no python3 in WSL '$($script:Distro)' and -SkipPythonInstall was given."
            Write-Log "  Install it later with 'sudo apt install python3' inside the distro."
            return $false
        }
        try {
            $v = Install-WslPython
        } catch {
            Write-Log "WARNING: $($_.Exception.Message)"
            return $false
        }
    } else {
        Write-Log "Found python3 $v in WSL '$($script:Distro)'."
    }
    return $true
}

# ---------------------------------------------------------------------------
# App files
# ---------------------------------------------------------------------------
function Get-SourceDir {
    # A repo checkout / release download has secvitals.py next to this script -
    # install offline from there. Otherwise fetch the branch zip.
    if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "secvitals.py"))) {
        Write-Log "Installing from local folder: $PSScriptRoot"
        return $PSScriptRoot
    }
    $safe = $Branch -replace '[\\/:*?"<>|]', '-'   # branch names may contain /
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
                       -Pattern '^__version__\s*=\s*"([^"]+)"' |
         Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return "0.0.0"
}

function Install-AppFiles {
    param([string]$SourceDir)
    Write-Log "Copying application files to $InstallDir ..."
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    foreach ($f in $AppFiles) {
        $src = Join-Path $SourceDir $f
        if (Test-Path $src) { Copy-Item $src -Destination $InstallDir -Force }
    }
    foreach ($d in $AppDirs) {
        $src = Join-Path $SourceDir $d
        if (Test-Path $src) { Copy-Item $src -Destination $InstallDir -Recurse -Force }
    }
}

function Set-WslDistroInSettings {
    # Pin the verified distro into the INSTALLED settings.yaml, but only if the user
    # hasn't already set one (shipped value is an empty string).
    param([string]$DistroName)
    if (-not $DistroName) { return }
    $path = Join-Path $InstallDir "config\settings.yaml"
    if (-not (Test-Path $path)) { return }
    try {
        $text = Get-Content -Path $path -Raw
        $patched = [regex]::Replace($text, '(?m)^(\s*distro:\s*)""\s*$', "`${1}`"$DistroName`"", 1)
        if ($patched -ne $text) {
            Set-Content -Path $path -Value $patched -Encoding UTF8
            Write-Log "Pinned WSL distro '$DistroName' in config\settings.yaml."
        }
    } catch {
        Write-Log "NOTE: could not pin the WSL distro in settings.yaml ($($_.Exception.Message)); the app will use the default distro."
    }
}

# ---------------------------------------------------------------------------
# Shortcuts + Add/Remove Programs registration
# ---------------------------------------------------------------------------
function New-AppShortcut {
    param([string]$LinkPath, [string]$PythonwExe)
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($LinkPath)
    $lnk.TargetPath = $PythonwExe
    $lnk.Arguments = "`"$InstallDir\secvitals.py`""
    $lnk.WorkingDirectory = $InstallDir
    $lnk.Description = "$AppName - fire EdgeConnect security triggers and classify the result"
    $ico = Join-Path $InstallDir "assets\secvitals.ico"
    if (Test-Path $ico) { $lnk.IconLocation = "$ico,0" }
    $lnk.Save()
    Write-Log "Shortcut: $LinkPath"
}

function Install-Shortcuts {
    param($Python)
    # pythonw.exe runs the Tkinter window with no console window behind it.
    $pythonw = Join-Path (Split-Path $Python.Exe) "pythonw.exe"
    if (-not (Test-Path $pythonw)) { $pythonw = $Python.Exe }
    if (-not $NoStartMenuShortcut) {
        $programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
        New-AppShortcut -LinkPath (Join-Path $programs "$AppName.lnk") -PythonwExe $pythonw
    }
    if (-not $NoDesktopShortcut) {
        $desktop = [Environment]::GetFolderPath("Desktop")
        New-AppShortcut -LinkPath (Join-Path $desktop "$AppName.lnk") -PythonwExe $pythonw
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
    Set-ItemProperty -Path $reg -Name "DisplayIcon" -Value "$InstallDir\assets\secvitals.ico"
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

function Write-InstallInfo {
    param([string]$Version)
    # A small record the uninstaller reads (Windows-only footprint; the app deploys
    # nothing inside WSL, so there is no WSL folder to remove).
    $info = @("AppName = $AppName", "Version = $Version",
              "InstallDir = $InstallDir", "Distro = $($script:Distro)")
    Set-Content -Path (Join-Path $InstallDir "install-info.txt") -Value $info -Encoding UTF8
}

# ---------------------------------------------------------------------------
# The install itself (shared by GUI and console modes)
# ---------------------------------------------------------------------------
function Invoke-Install {
    Write-Log "=== $AppName setup ==="
    $py = Resolve-Python
    $null = Resolve-WslWorker            # best-effort; warnings only
    $srcDir = Get-SourceDir
    $version = Get-AppVersion -Dir $srcDir
    Write-Log "Installing $AppName $version ..."
    Install-AppFiles -SourceDir $srcDir
    Set-WslDistroInSettings -DistroName $script:Distro
    Install-Shortcuts -Python $py
    Register-App -Version $version
    Write-InstallInfo -Version $version
    Write-Log ""
    Write-Log "$AppName $version installed to:"
    Write-Log "  $InstallDir"
    Write-Log "Start it from the Start Menu ('$AppName'). Click a trigger's Fire button,"
    Write-Log "then verify the detection on the Orchestrator / EdgeConnect dashboard."
    return [pscustomobject]@{ Python = $py; Version = $version }
}

function Start-App {
    param($Python)
    $pythonw = Join-Path (Split-Path $Python.Exe) "pythonw.exe"
    if (-not (Test-Path $pythonw)) { $pythonw = $Python.Exe }
    Start-Process -FilePath $pythonw -ArgumentList "`"$InstallDir\secvitals.py`"" `
                  -WorkingDirectory $InstallDir
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
    $green  = [System.Drawing.Color]::FromArgb(1, 169, 130)
    $amber  = [System.Drawing.Color]::FromArgb(255, 131, 0)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$AppName setup"
    $form.ClientSize = New-Object System.Drawing.Size(560, 500)
    $form.BackColor = $bg
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.StartPosition = "CenterScreen"

    $title = New-Object System.Windows.Forms.Label
    $title.Text = "$AppName setup"
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $title.ForeColor = $txtCol
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(20, 16)
    $form.Controls.Add($title)

    $sub = New-Object System.Windows.Forms.Label
    $sub.Text = "Fire EdgeConnect security triggers on a click and classify the result."
    $sub.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $sub.ForeColor = $dimCol
    $sub.AutoSize = $true
    $sub.Location = New-Object System.Drawing.Point(22, 48)
    $form.Controls.Add($sub)

    $pyLabel = New-Object System.Windows.Forms.Label
    $pyLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $pyLabel.AutoSize = $true
    $pyLabel.Location = New-Object System.Drawing.Point(22, 74)
    $pyProbe = Find-Python
    if ($pyProbe -and $pyProbe.HasTk) {
        $pyLabel.Text = "Windows Python $($pyProbe.Version) with Tkinter found - nothing extra to install."
        $pyLabel.ForeColor = $green
    } elseif ($pyProbe) {
        $pyLabel.Text = "Python $($pyProbe.Version) found but without Tkinter - Python $PythonVersion will be added (per-user, python.org)."
        $pyLabel.ForeColor = $dimCol
    } else {
        $pyLabel.Text = "Python not found - Python $PythonVersion will be installed for you (per-user, from python.org)."
        $pyLabel.ForeColor = $dimCol
    }
    $form.Controls.Add($pyLabel)

    $wslLabel = New-Object System.Windows.Forms.Label
    $wslLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $wslLabel.AutoSize = $true
    $wslLabel.Location = New-Object System.Drawing.Point(22, 94)
    if (-not $script:Distro) { $script:Distro = Get-DefaultDistro }
    if ($script:Distro) {
        $wslLabel.Text = "WSL distro '$($script:Distro)' will run the trigger worker (python3 added if missing)."
        $wslLabel.ForeColor = $dimCol
    } else {
        $wslLabel.Text = "WSL not detected - triggers need it. Install with 'wsl --install'; the window still opens."
        $wslLabel.ForeColor = $amber
    }
    $form.Controls.Add($wslLabel)

    $dirLabel = New-Object System.Windows.Forms.Label
    $dirLabel.Text = "Install folder:"
    $dirLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dirLabel.ForeColor = $txtCol
    $dirLabel.AutoSize = $true
    $dirLabel.Location = New-Object System.Drawing.Point(22, 124)
    $form.Controls.Add($dirLabel)

    $dirBox = New-Object System.Windows.Forms.TextBox
    $dirBox.Text = $InstallDir
    $dirBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dirBox.BackColor = $panel
    $dirBox.ForeColor = $txtCol
    $dirBox.BorderStyle = "FixedSingle"
    $dirBox.Location = New-Object System.Drawing.Point(24, 144)
    $dirBox.Size = New-Object System.Drawing.Size(430, 24)
    $form.Controls.Add($dirBox)

    $browse = New-Object System.Windows.Forms.Button
    $browse.Text = "Browse..."
    $browse.FlatStyle = "Flat"
    $browse.BackColor = $panel
    $browse.ForeColor = $txtCol
    $browse.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(54, 59, 68)
    $browse.Location = New-Object System.Drawing.Point(462, 143)
    $browse.Size = New-Object System.Drawing.Size(78, 25)
    $browse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = "Choose the parent folder ('$AppKey' is created inside it)"
        if ($dlg.ShowDialog() -eq "OK") {
            $dirBox.Text = Join-Path $dlg.SelectedPath $AppKey
        }
    })
    $form.Controls.Add($browse)

    $cbStart = New-Object System.Windows.Forms.CheckBox
    $cbStart.Text = "Start Menu shortcut"
    $cbStart.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cbStart.ForeColor = $txtCol
    $cbStart.Checked = -not $NoStartMenuShortcut
    $cbStart.AutoSize = $true
    $cbStart.Location = New-Object System.Drawing.Point(24, 178)
    $form.Controls.Add($cbStart)

    $cbDesk = New-Object System.Windows.Forms.CheckBox
    $cbDesk.Text = "Desktop shortcut"
    $cbDesk.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cbDesk.ForeColor = $txtCol
    $cbDesk.Checked = -not $NoDesktopShortcut
    $cbDesk.AutoSize = $true
    $cbDesk.Location = New-Object System.Drawing.Point(200, 178)
    $form.Controls.Add($cbDesk)

    $log = New-Object System.Windows.Forms.TextBox
    $log.Multiline = $true
    $log.ReadOnly = $true
    $log.ScrollBars = "Vertical"
    $log.Font = New-Object System.Drawing.Font("Consolas", 8.5)
    $log.BackColor = $panel
    $log.ForeColor = $txtCol
    $log.BorderStyle = "FixedSingle"
    $log.Location = New-Object System.Drawing.Point(24, 210)
    $log.Size = New-Object System.Drawing.Size(516, 200)
    $form.Controls.Add($log)

    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Style = "Continuous"
    $bar.Location = New-Object System.Drawing.Point(24, 418)
    $bar.Size = New-Object System.Drawing.Size(516, 6)
    $form.Controls.Add($bar)

    $btnInstall = New-Object System.Windows.Forms.Button
    $btnInstall.Text = "Install"
    $btnInstall.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnInstall.FlatStyle = "Flat"
    $btnInstall.BackColor = $green
    $btnInstall.ForeColor = [System.Drawing.Color]::White
    $btnInstall.FlatAppearance.BorderSize = 0
    $btnInstall.Location = New-Object System.Drawing.Point(430, 448)
    $btnInstall.Size = New-Object System.Drawing.Size(110, 36)
    $form.Controls.Add($btnInstall)

    $btnLaunch = New-Object System.Windows.Forms.Button
    $btnLaunch.Text = "Launch"
    $btnLaunch.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnLaunch.FlatStyle = "Flat"
    $btnLaunch.BackColor = $green
    $btnLaunch.ForeColor = [System.Drawing.Color]::White
    $btnLaunch.FlatAppearance.BorderSize = 0
    $btnLaunch.Location = New-Object System.Drawing.Point(430, 448)
    $btnLaunch.Size = New-Object System.Drawing.Size(110, 36)
    $btnLaunch.Visible = $false
    $form.Controls.Add($btnLaunch)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnClose.FlatStyle = "Flat"
    $btnClose.BackColor = $panel
    $btnClose.ForeColor = $txtCol
    $btnClose.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(54, 59, 68)
    $btnClose.Location = New-Object System.Drawing.Point(330, 448)
    $btnClose.Size = New-Object System.Drawing.Size(90, 36)
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)

    $result = @{ Python = $null }
    $script:Installing = $false
    $form.Add_FormClosing({
        param($sender, $e)
        if ($script:Installing) {
            [System.Windows.Forms.MessageBox]::Show(
                "Setup is still running - let it finish first.",
                "$AppName setup",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            $e.Cancel = $true
        }
    })
    $btnInstall.Add_Click({
        $btnInstall.Enabled = $false
        $btnClose.Enabled = $false
        $browse.Enabled = $false
        $dirBox.Enabled = $false
        $script:Installing = $true
        $script:InstallDir = $dirBox.Text.Trim()
        $script:NoStartMenuShortcut = -not $cbStart.Checked
        $script:NoDesktopShortcut = -not $cbDesk.Checked
        $script:GuiLogBox = $log
        $bar.Style = "Marquee"
        try {
            $r = Invoke-Install
            $result.Python = $r.Python
            $bar.Style = "Continuous"
            $bar.Value = 100
            $btnInstall.Visible = $false
            $btnLaunch.Visible = $true
        } catch {
            $bar.Style = "Continuous"
            $bar.Value = 0
            Write-Log ""
            Write-Log "INSTALL FAILED: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show(
                $_.Exception.Message, "$AppName setup",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            $btnInstall.Enabled = $true
            $browse.Enabled = $true
            $dirBox.Enabled = $true
        } finally {
            $script:Installing = $false
            $btnClose.Enabled = $true
        }
    })
    $btnLaunch.Add_Click({
        Start-App -Python $result.Python
        $form.Close()
    })

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
    } catch {
        $useGui = $false
    }
}

if ($useGui) {
    Show-InstallerGui
} else {
    if (-not $Silent) {
        Write-Host "=== $AppName setup (console) ==="
        Write-Host "Install folder : $InstallDir"
        Write-Host "WSL distro     : $(if ($script:Distro) { $script:Distro } else { '(default)' })"
        Write-Host "Shortcuts      : StartMenu=$(-not $NoStartMenuShortcut)  Desktop=$(-not $NoDesktopShortcut)"
        $answer = Read-Host "Proceed? [Y/n]"
        if ($answer -and $answer.Trim().ToLower().StartsWith("n")) {
            Write-Host "Cancelled."
            exit 1
        }
    }
    $r = Invoke-Install
    if (-not $Silent) {
        $answer = Read-Host "Launch $AppName now? [Y/n]"
        if (-not ($answer -and $answer.Trim().ToLower().StartsWith("n"))) {
            Start-App -Python $r.Python
        }
    }
}
