#Requires -Version 5.0
<#
.SYNOPSIS
  Uninstall Security Vitals (per-user install; no admin rights required).

.DESCRIPTION
  Removes the shortcuts, the Settings > Apps registration, the app folder inside WSL,
  and this Windows launcher folder. The tmNIDS binary cache and any local runtime state
  inside WSL (~/.cache/secvitals) are kept unless -PurgeSettings is given.

.PARAMETER Silent
  No confirmation prompt.
.PARAMETER PurgeSettings
  Also delete the WSL cache (~/.cache/secvitals, including the tmNIDS binary).
#>
[CmdletBinding()]
param(
    [switch]$Silent,
    [switch]$PurgeSettings
)

$ErrorActionPreference = "SilentlyContinue"
$env:WSL_UTF8 = "1"

$AppName    = "Security Vitals"
$AppKey     = "SecVitals"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------------------------------------------------------------------------
# Safety: this script deletes ITS OWN folder, so a stray copy in Desktop /
# Downloads / a profile root must never turn into "delete that folder".
# ---------------------------------------------------------------------------
if (-not (Test-Path (Join-Path $InstallDir "launch.cmd"))) {
    Write-Host "ERROR: '$InstallDir' does not look like a $AppName install folder"
    Write-Host "(launch.cmd is not here). Nothing was removed. Uninstall from Settings > Apps."
    exit 1
}
$protected = @([Environment]::GetFolderPath("Desktop"),
               [Environment]::GetFolderPath("MyDocuments"),
               [Environment]::GetFolderPath("UserProfile"),
               $env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA,
               $env:TEMP, "$env:SystemDrive\")
foreach ($p in $protected) {
    if ($p -and ($InstallDir.TrimEnd('\') -eq $p.TrimEnd('\'))) {
        Write-Host "ERROR: refusing to remove '$InstallDir' - it is a system/user folder."
        exit 1
    }
}

# Read where the app was installed inside WSL.
$distro = ""; $wslDir = ""
$infoPath = Join-Path $InstallDir "install-info.txt"
if (Test-Path $infoPath) {
    foreach ($line in (Get-Content $infoPath)) {
        if ("$line" -match '^\s*Distro\s*=\s*(.+?)\s*$') { $distro = $Matches[1] }
        if ("$line" -match '^\s*WslDir\s*=\s*(.+?)\s*$') { $wslDir = $Matches[1] }
    }
}

if (-not $Silent) {
    Write-Host "This removes $AppName:"
    Write-Host "  Windows launcher : $InstallDir"
    if ($wslDir) { Write-Host "  WSL app folder   : $distro : $wslDir" }
    $answer = Read-Host "Continue? [y/N]"
    if (-not ($answer -and $answer.Trim().ToLower().StartsWith("y"))) {
        Write-Host "Cancelled."; exit 1
    }
}

# Shortcuts
$programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
Remove-Item (Join-Path $programs "$AppName.lnk") -Force
Remove-Item (Join-Path ([Environment]::GetFolderPath("Desktop")) "$AppName.lnk") -Force

# Settings > Apps registration
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppKey" -Recurse -Force

# WSL app folder - only if it clearly looks like a Security Vitals install (contains
# secvitals.py) and is not a home/root/system path.
if ($distro -and $wslDir -and (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    $safe = ($wslDir -match '/secvitals/?$') -and (($wslDir.TrimEnd('/').Length) -gt 12)
    if ($safe) {
        $sh = "d='$wslDir'; case `"`$d`" in /|`$HOME|`$HOME/) echo REFUSE; exit 0;; esac; " +
              "if [ -f `"`$d/secvitals.py`" ]; then rm -rf `"`$d`"; echo REMOVED; else echo NOAPP; fi"
        # base64 the script so its quotes survive the PowerShell -> wsl.exe -> bash boundary.
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($sh))
        $r = (& wsl.exe -d $distro -e bash -lc "echo $b64 | base64 -d | bash")
        if ($r | Where-Object { "$_".Trim() -eq "REMOVED" }) { Write-Host "Removed WSL app folder: $wslDir" }
        else { Write-Host "NOTE: left the WSL folder in place ('$wslDir' didn't contain secvitals.py)." }
        if ($PurgeSettings) {
            $pb64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('rm -rf "$HOME/.cache/secvitals"'))
            & wsl.exe -d $distro -e bash -lc "echo $pb64 | base64 -d | bash" | Out-Null
            Write-Host "Purged WSL cache (~/.cache/secvitals)."
        }
    } else {
        Write-Host "NOTE: '$wslDir' didn't look like an app folder - left it in place."
    }
}

Write-Host "$AppName has been removed."

# The launcher folder contains THIS running script, so its deletion is handed to a
# detached cmd that waits for this process to exit, then retries for a while.
Set-Location $env:TEMP
$cmd = "/c for /l %i in (1,1,10) do (ping -n 2 127.0.0.1 >nul & " +
       "rmdir /s /q `"$InstallDir`" 2>nul & if not exist `"$InstallDir`" exit)"
Start-Process -FilePath "$env:ComSpec" -ArgumentList $cmd -WindowStyle Hidden
