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
- SNMP credentials (v2c communities and v3 keys) are never echoed to the frontend
- Update downloads are validated against a hardcoded host/path allowlist
- Update downloads are verified against an RSA signature (`.sig` release asset)
  using the public key embedded in `signing.py`; without a `.sig`, a `.sha256`
  checksum asset is checked instead (corruption protection only)

## Signing a release (maintainer)

The private key (`release_key.json`, gitignored) must stay on your machine —
back it up offline. One-time setup: `python scripts/sign_release.py keygen`
(already done; the matching public key is embedded in `signing.py`).

For every release:

1. Build the exe: `python build.py`
2. Sign it: `python scripts/sign_release.py sign dist/NetTrack.exe`
3. Upload **both** `NetTrack.exe` and `NetTrack.exe.sig` to the GitHub release

Once all supported releases are signed, set `REQUIRE_SIGNATURE = True` in
`signing.py` so the updater refuses unsigned releases (closes the downgrade
loophole where an attacker simply omits the `.sig`).

## Safe Push Guardrails

- Run a local secret scan before pushing:
  - `python scripts/secret_scan.py`
- Optional Git hook setup (runs scanner automatically on push):
  - `git config core.hooksPath .githooks`
- Local runtime files are ignored by git (`devices.json`, `topology.json`, `snmp_config.json`, debug logs).

## License

Source-available — free for personal and non-commercial use. Commercial use requires a separate license. See [`LICENSE`](LICENSE) for full terms.
