# Installing Security Vitals (Windows)

Security Vitals is a **Tkinter window** that runs on **Windows Python**, and everything
runs **natively — no WSL**. HTTP triggers use `curl.exe` (which ships with Windows 10
1803+); the rest use small built-in Python probes. The installer is a per-user Windows
setup (no admin rights) with the same GUI experience as NetVitals.

## Quick start

1. Download this repo (or a release) and unzip it, **or** just grab `install.bat` +
   `install.ps1`.
2. Double-click **`install.bat`**.
3. In the setup window: confirm the Python status, pick the install folder, and click
   **Install**. Then **Launch**.

That's it — the **Security Vitals** window opens (with its own taskbar icon). A Start
Menu / Desktop shortcut does the same later, and it shows up in **Settings → Apps** so you
can uninstall it like any Windows app.

## What the installer does

- Finds a **Windows Python 3.8+ with Tkinter** (the console is a Tk window). If none is
  found — or the one it finds lacks Tkinter — it installs Python from **python.org**
  per-user (silently, no admin), with tcl/tk included.
- Confirms **`curl.exe`** is present (Windows 10 1803+). If it isn't, setup still finishes
  and warns you — the HTTP triggers need it, but the `dns` / `tcp` triggers work without it.
- Copies the app to the Windows install folder (default `%LOCALAPPDATA%\Programs\SecVitals`).
- Creates **Start Menu / Desktop shortcuts** (a `pythonw` shortcut, so no console window)
  and registers an uninstaller in **Settings → Apps**.

No WSL, no distro, and nothing is downloaded-and-executed at run time — each trigger is an
explicit `curl` / socket probe from the fixed catalog.

## Command line

```
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 [options]
```

| Option | Meaning |
|---|---|
| `-Silent` | no window, no prompts (implies `-NoGui`) |
| `-NoGui` | console output instead of the setup window |
| `-InstallDir <path>` | Windows install folder (default `%LOCALAPPDATA%\Programs\SecVitals`) |
| `-NoDesktopShortcut` / `-NoStartMenuShortcut` | skip that shortcut |
| `-SkipPythonInstall` | never install Python; fail if a usable one isn't found |
| `-Branch <name>` | branch to fetch when downloading from GitHub (default `main`) |

Silent example: `install.bat -Silent -NoDesktopShortcut`

## Updating

Use **Check for updates** in the window, or run `py secvitals.py --update` from the install
folder. Either way it runs the app's hardened, signed self-update (pinned source,
RSA-verified, fail closed; on Windows the download retries through the system certificate
store so a TLS-inspecting proxy doesn't break it — see
[UPDATE_SECURITY.md](UPDATE_SECURITY.md)).

## Uninstalling

Uninstall from **Settings → Apps**, or run `uninstall.ps1` from the install folder. It
removes the shortcuts, the registration, and the install folder (only if it actually
contains `secvitals.py`). Security Vitals keeps no other on-disk state, so there is nothing
else to clean up.

## Files

| File | Role |
|---|---|
| `install.bat` | double-click bootstrapper (runs `install.ps1`, or fetches it from GitHub) |
| `install.ps1` | the WinForms GUI installer (console/`-Silent` fallback) |
| `uninstall.ps1` | per-user uninstaller (safe: refuses anything that isn't an install folder) |
| `install-info.txt` | generated at install time — records the installed version |

Reused from NetVitals: the installer's **UI/experience** — the WinForms GUI, HPE theme,
Windows Python discovery + python.org install, the `pythonw` shortcut, and Add/Remove
Programs registration. Both apps install the same way and each opens in its own window.
