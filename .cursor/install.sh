#!/usr/bin/env bash
# Cloud Agent install for Security Vitals (secvitals).
#
# secvitals is a standard-library-only Python app (Python 3.8+). The base image already
# ships Python 3 and curl, so the only durable prerequisites to add are:
#   * python3-tk  — Tkinter, required by the console window and the GUI smoke test;
#   * xvfb + x11-utils — a headless X server so the GUI can be launched/tested with no
#     physical display;
#   * iproute2    — the `ip` command used by the per-boot start script.
# There are deliberately no third-party Python dependencies (see requirements.txt).
set -euo pipefail

cd "$(dirname "$0")/.."

export DEBIAN_FRONTEND=noninteractive
SUDO=""
if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

# System packages. apt-get install is idempotent (a no-op when already present).
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq \
  python3-tk \
  xvfb \
  x11-utils \
  iproute2 \
  curl

# Fail fast if Tkinter is missing (the window and the GUI smoke test both need it).
python3 -c "import tkinter; print('tkinter', tkinter.TkVersion, 'OK')"

# Byte-compile the console — the same guard CI runs before the test suite.
python3 -m py_compile secvitals.py

echo "secvitals install complete: $(python3 --version), $(curl --version | head -1 | cut -d' ' -f1-2)"
