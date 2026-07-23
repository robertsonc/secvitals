#Requires -Version 5.0
<#
.SYNOPSIS
  Uninstall Security Vitals (per-user install; no admin rights required).

.DESCRIPTION
  Removes the shortcuts, the Settings > Apps registration, and this Windows install
  folder. Security Vitals installs NOTHING inside WSL (each trigger's worker is streamed
  in over stdin at run time), so the only WSL footprint is the tmNIDS binary cache under
  ~/.cache/secvitals, which is kept unless -PurgeSettings is given.

.PARAMETER Silent
  No confirmation prompt.
.PARAMETER PurgeSettings
  Also delete the WSL cache (~/.cache/secvitals, including the pinned tmNIDS binary).
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
if (-not (Test-Path (Join-Path $InstallDir "secvitals.py"))) {
    Write-Host "ERROR: '$InstallDir' does not look like a $AppName install folder"
    Write-Host "(secvitals.py is not here). Nothing was removed. Uninstall from Settings > Apps."
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

# Read the distro that ran the worker (only needed for -PurgeSettings).
$distro = ""
$infoPath = Join-Path $InstallDir "install-info.txt"
if (Test-Path $infoPath) {
    foreach ($line in (Get-Content $infoPath)) {
        if ("$line" -match '^\s*Distro\s*=\s*(.+?)\s*$') { $distro = $Matches[1] }
    }
}

if (-not $Silent) {
    Write-Host "This removes $AppName:"
    Write-Host "  Windows install folder : $InstallDir"
    if ($PurgeSettings -and $distro) { Write-Host "  WSL tmNIDS cache       : $distro : ~/.cache/secvitals" }
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

# Optional: purge the WSL-side tmNIDS cache. base64 the command so its quotes survive the
# PowerShell -> wsl.exe -> bash boundary intact.
if ($PurgeSettings -and $distro -and (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    $pb64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('rm -rf "$HOME/.cache/secvitals"'))
    & wsl.exe -d $distro -e bash -lc "echo $pb64 | base64 -d | bash" | Out-Null
    Write-Host "Purged WSL cache (~/.cache/secvitals)."
}

Write-Host "$AppName has been removed."

# The install folder contains THIS running script, so its deletion is handed to a
# detached cmd that waits for this process to exit, then retries for a while.
Set-Location $env:TEMP
$cmd = "/c for /l %i in (1,1,10) do (ping -n 2 127.0.0.1 >nul & " +
       "rmdir /s /q `"$InstallDir`" 2>nul & if not exist `"$InstallDir`" exit)"
Start-Process -FilePath "$env:ComSpec" -ArgumentList $cmd -WindowStyle Hidden
