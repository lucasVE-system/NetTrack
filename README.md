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



## Quick Start (Recommended)

1. Go to the GitHub Releases page
2. Download `NetTrack-Setup-x.x.x.exe`
3. Run the installer
4. Launch NetTrack from the Start Menu


## Security notes

- Server binds to loopback only (127.0.0.1)
- Subprocess calls use argv lists and timeouts (see `topology.py` / `app.py` headers)
- SNMP communities are never echoed to the frontend
- Update downloads are validated against a hardcoded host/path allowlist

## License

Source-available — free for personal and non-commercial use. Commercial use requires a separate license. See [`LICENSE`](LICENSE) for full terms.
