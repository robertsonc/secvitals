@echo off
REM Security Vitals installer bootstrapper. Double-click me.
REM
REM Runs install.ps1 from this folder when present (a repo checkout or release
REM download); otherwise fetches the latest installer from GitHub. Arguments pass
REM through to install.ps1, e.g.:  install.bat -Silent -NoDesktopShortcut
setlocal
title Security Vitals setup

if exist "%~dp0install.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
) else (
    echo Downloading the latest installer from GitHub ...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12;" ^
        "Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/robertsonc/secvitals/main/install.ps1' -OutFile (Join-Path $env:TEMP 'secvitals-install.ps1')"
    REM Run via -File so arguments (quotes, spaces) pass through verbatim.
    if exist "%TEMP%\secvitals-install.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP%\secvitals-install.ps1" %*
    ) else (
        echo ERROR: could not download install.ps1 - check the network/proxy.
        pause
        exit /b 1
    )
)

if errorlevel 1 pause
