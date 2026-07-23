# Installing Security Vitals (Windows + WSL)

Security Vitals is a **Tkinter window** that runs on **Windows Python**. When you fire a
trigger it runs a short-lived **worker inside WSL** (native `bash` / `curl` / tmNIDS, on
the SD-WAN egress path) and classifies the result. The installer is a per-user Windows
setup (no admin rights) with the same GUI experience as NetVitals.

## Quick start

1. Download this repo (or a release) and unzip it, **or** just grab `install.bat` +
   `install.ps1`.
2. Double-click **`install.bat`**.
3. In the setup window: confirm the Python / WSL status, pick the install folder, and
   click **Install**. Then **Launch**.

That's it — the **Security Vitals** window opens. A Start Menu / Desktop shortcut does the
same later, and it shows up in **Settings → Apps** so you can uninstall it like any Windows
app.

## What the installer does

- Finds a **Windows Python 3.8+ with Tkinter** (the console is a Tk window). If none is
  found — or the one it finds lacks Tkinter — it installs Python from **python.org**
  per-user (silently, no admin), with tcl/tk included.
- Verifies **WSL** and its default distro, and makes sure **`python3`** exists inside it
  (the worker needs it — no Tkinter required in WSL). If it's missing it's installed into
  the distro as root via `apt`/`dnf`/`apk`/`pacman`. Nothing else is copied into WSL; the
  console streams its own source to `python3 -` at run time.
- Copies the app to the Windows install folder (default
  `%LOCALAPPDATA%\Programs\SecVitals`) and **pins the verified distro** into
  `config\settings.yaml`.
- Creates **Start Menu / Desktop shortcuts** (a `pythonw` shortcut, so no console window)
  and registers an uninstaller in **Settings → Apps**.

It does **not** install WSL itself (that needs admin + a reboot). If WSL is missing, setup
**still installs** and the window still opens — it just warns you; run `wsl --install` in
an elevated PowerShell, reboot, and triggers will fire. (WSL problems surface as an
`error` at fire time, never as a false `blocked`.)

## Command line

```
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 [options]
```

| Option | Meaning |
|---|---|
| `-Silent` | no window, no prompts (implies `-NoGui`) |
| `-NoGui` | console output instead of the setup window |
| `-InstallDir <path>` | Windows install folder (default `%LOCALAPPDATA%\Programs\SecVitals`) |
| `-Distro <name>` | WSL distro the worker runs in (default: the WSL default distro) |
| `-NoDesktopShortcut` / `-NoStartMenuShortcut` | skip that shortcut |
| `-SkipPythonInstall` | never install Python (Windows or WSL); fail / warn instead |
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
contains `secvitals.py`). Security Vitals installs nothing inside WSL, so the only WSL
footprint is the tmNIDS cache (`~/.cache/secvitals`), which is kept unless you pass
`-PurgeSettings`.

## Files

| File | Role |
|---|---|
| `install.bat` | double-click bootstrapper (runs `install.ps1`, or fetches it from GitHub) |
| `install.ps1` | the WinForms GUI installer (console/`-Silent` fallback) |
| `uninstall.ps1` | per-user uninstaller (safe: refuses anything that isn't an install folder) |
| `install-info.txt` | generated at install time — records the version + pinned distro |

Reused from NetVitals: the installer's **UI/experience** (WinForms GUI, HPE theme, Windows
Python discovery + python.org install, `pythonw` shortcut, Add/Remove Programs
registration, console fallback). Added for Security Vitals: the **WSL worker check**
(verify WSL + provision `python3` in the distro), preserving the base64 command transport
that keeps PowerShell from mangling the bash it sends to WSL.
