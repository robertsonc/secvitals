# Installing Security Vitals (Windows + WSL)

Security Vitals runs **inside WSL** — its triggers use bash, tmNIDS and curl — and serves
a local web UI you open in the **Windows browser**. The installer is a per-user Windows
setup (no admin rights) with the same GUI experience as NetVitals, adapted for the WSL
web app.

## Quick start

1. Download this repo (or a release) and unzip it, **or** just grab `install.bat` +
   `install.ps1`.
2. Double-click **`install.bat`**.
3. In the setup window: confirm the WSL distro / Python status, pick the install folder
   and port, and click **Install**. Then **Launch**.

That's it — the console starts in WSL and your browser opens at `http://127.0.0.1:8787/`.
A Start Menu / Desktop shortcut (**Security Vitals**) does the same later, and it shows up
in **Settings → Apps** so you can uninstall it like any Windows app.

## What the installer does

- Finds your **WSL** default distro and a **Python 3.8+** inside it. Security Vitals needs
  no Tkinter (it's a web app), so any modern python3 works. If python3 is missing it is
  installed into the distro as root — no password prompt — via `apt`/`dnf`/`apk`/`pacman`.
- Copies the app into the distro's native filesystem (default
  `~/.local/share/secvitals`) — fast, no `/mnt` line-ending quirks.
- Writes a Windows **launcher** (`launch.cmd`) that starts the server in WSL and opens the
  browser; closing the launcher window stops the console.
- Creates **Start Menu / Desktop shortcuts** and registers an uninstaller in
  **Settings → Apps**.

It does **not** install WSL itself (that needs admin + a reboot). If WSL is missing, the
setup window tells you: run `wsl --install` in an elevated PowerShell, reboot, then re-run.

## Command line

```
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 [options]
```

| Option | Meaning |
|---|---|
| `-Silent` | no window, no prompts (implies `-NoGui`) |
| `-NoGui` | console output instead of the setup window |
| `-InstallDir <path>` | Windows folder for the launcher + shortcuts (default `%LOCALAPPDATA%\Programs\SecVitals`) |
| `-WslDir <path>` | folder inside WSL for the app (default `~/.local/share/secvitals`) |
| `-Distro <name>` | target WSL distro (default: the WSL default distro) |
| `-Port <n>` | loopback port (default 8787) |
| `-NoDesktopShortcut` / `-NoStartMenuShortcut` | skip that shortcut |
| `-SkipPythonInstall` | never install python3 into WSL; fail if none is found |
| `-Branch <name>` | branch to fetch when downloading from GitHub (default `main`) |

Silent example: `install.bat -Silent -Port 9000 -NoDesktopShortcut`

## Updating

The launcher folder includes **`update.cmd`**, which runs the app's hardened, signed
self-update inside WSL (`python3 secvitals.py --update` — pinned source, RSA-verified,
fail closed; see [UPDATE_SECURITY.md](UPDATE_SECURITY.md)).

## Uninstalling

Uninstall from **Settings → Apps**, or run `uninstall.ps1` from the launcher folder. It
removes the shortcuts, the registration, the WSL app folder (only if it actually contains
`secvitals.py`), and the launcher folder. The tmNIDS cache inside WSL
(`~/.cache/secvitals`) is kept unless you pass `-PurgeSettings`.

## Files

| File | Role |
|---|---|
| `install.bat` | double-click bootstrapper (runs `install.ps1`, or fetches it from GitHub) |
| `install.ps1` | the WinForms GUI installer (console/`-Silent` fallback) |
| `uninstall.ps1` | per-user uninstaller (also removes the WSL app folder, safely) |
| `launch.cmd` / `open-browser.cmd` | generated at install time — start the server + open the browser |
| `update.cmd` | generated at install time — runs the signed self-update in WSL |

Reused from NetVitals: the installer's **UI/experience** (WinForms GUI, HPE theme, Python
discovery, shortcuts, Add/Remove Programs registration, console fallback). Adapted: it
targets **WSL + python3** instead of Windows Python + Tkinter, and launches a **server +
browser** instead of a native Tkinter window.
