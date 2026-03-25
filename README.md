# NetTrack

Local network inventory and topology mapping. The web UI listens on **127.0.0.1** only (not exposed on the LAN). SNMP community strings and similar secrets stay on disk next to the app and are never returned by the API.

**Repository:** see `GITHUB_REPO` in [`version.py`](version.py) (e.g. releases and issues on GitHub).

## Features

- **Scan**: ARP table, ping sweep on `/24`, MAC vendor lookup, reverse DNS where available
- **Topology**: Optional multi-phase discovery — traceroute (L3), SNMP (LLDP/CDP/ARP/FDB), passive LLDP/DHCP hints, mDNS, SSDP/UPnP, NetBIOS, light port/banner fingerprinting
- **Map**: Star / tree / force layout with edge types (LLDP, CDP, L3 hops, inferred)
- **SNMP v2c**: Per-IP or wildcard (`*`) community + **port** (stored in `snmp_config.json`)
- **Updates**: Optional in-app check against GitHub Releases (Windows `.exe` asset)

## Requirements

- **Python 3.10+** (recommended)
- **Core:** `flask`, `mac-vendor-lookup` — see [`requirements.txt`](requirements.txt)
- **Full discovery:** install optional packages commented in `requirements.txt` (`pysnmp`, `zeroconf`, `scapy`). Raw capture and LLDP on Windows typically need **Administrator** and often **Scapy**.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
# Optional:
pip install pysnmp zeroconf scapy
```

## Run

**Browser + auto-open:**

```bash
python launcher.py
```

**Flask only** (open http://127.0.0.1:5000 yourself):

```bash
python app.py
```

Data files are written next to the script or next to the frozen executable: `devices.json`, `topology.json`, `snmp_config.json`.

## Packaging

`build.py` wraps PyInstaller for a one-file, no-console Windows executable:

```bash
pip install pyinstaller
python build.py
# Output: dist/NetTrack.exe
```

Optional dependencies (`pysnmp`, `zeroconf`, `scapy`) are included as hidden imports if installed in the active environment.

## Windows Installer

Two installer scripts are provided. Run `build.py` first so `dist\NetTrack.exe` exists.

**Inno Setup 6 (recommended):**

```bat
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" NetTrack.iss
:: Output: dist-installer\NetTrack-Setup-1.3.0.exe
```

**NSIS (alternative):**

```bat
makensis installer.nsi
:: Output: dist-installer\NetTrack-Setup-1.3.0-nsis.exe
```

Both installers:
- Embed `dist\NetTrack.exe` at compile time (no internet required during install)
- Create Start Menu shortcuts and an optional Desktop shortcut
- Register in Windows Add/Remove Programs (Settings → Apps)
- Include an uninstaller

For a public release, sign the installer with an Authenticode certificate to avoid SmartScreen warnings.

## Development

For day-to-day development (e.g. working from a Desktop folder):

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install pysnmp zeroconf scapy   # optional, for full topology
python launcher.py
```

Data files (`devices.json`, `topology.json`, `snmp_config.json`) are written next to the script.

## Security notes

- Server binds to loopback only (127.0.0.1)
- Subprocess calls use argv lists and timeouts (see `topology.py` / `app.py` headers)
- SNMP communities are never echoed to the frontend
- Update downloads are validated against a hardcoded host/path allowlist

## License

Source-available — free for personal and non-commercial use. Commercial use requires a separate license. See [`LICENSE`](LICENSE) for full terms.
