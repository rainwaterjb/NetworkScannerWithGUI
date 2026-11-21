# NetworkScannerWithGUI
A Python program that scans your local network and returns the IP address and MAC address. It also tries to get the computer name and OS version.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/python NetworkScannerWithGUI.py   # raw-socket scanning needs root
```

## Building the macOS app

```bash
pip install -r requirements-build.txt
pyinstaller NetworkScannerWithGUI.spec
```

The app is written to `dist/`. Build output is not committed to git: it freezes copies of every
library inside it, which then never receive security fixes. Publish the built app as a GitHub Release
asset instead, and rebuild whenever `requirements.txt` changes.
