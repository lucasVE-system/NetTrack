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

PyInstaller example spec: [`NetTrack.spec`](NetTrack.spec). Some optional dependencies need `hiddenimports` if the analyzer misses them — adjust after a test build.

## Security notes

- Server binds to loopback only
- Subprocess calls use argv lists and timeouts (see `topology.py` / `app.py` headers)
- SNMP communities are never echoed to the frontend

## License

MIT (see repository if a `LICENSE` file is present).
