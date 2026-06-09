# Changelog

## Unreleased

- **Refactor**: `app.py` now imports scanning helpers from `scanner.py` instead of duplicating them (~115 lines of duplicate code removed).
- **SNMPv3**: SNMP config accepts `version: "v3"` with `user`, optional `auth_key`/`auth_proto` (sha/md5) and `priv_key`/`priv_proto` (aes/des). v2c entries keep working unchanged. The SNMP modal in the UI has a version selector with v3 credential fields, and the entry list shows each entry's version.
- **UI**: update dialog shows a "Verifying checksum..." step when a SHA256 sidecar is being checked.
- **Validation**: `snmp_config.json` entries are schema-checked on startup; malformed entries are dropped instead of silently used.
- **Rate limiting**: `/scan` and `/scan-multi` reject repeat calls within 5 seconds (HTTP 429) to guard against runaway clients.
- **Update integrity**: auto-updater verifies a `<exe>.sha256` checksum sidecar from the GitHub release when present; mismatches abort the update.
- **Release signing**: new `signing.py` + `scripts/sign_release.py` — releases can be signed with an offline RSA-2048 private key; the updater verifies the `<exe>.sig` asset against the public key embedded in the app. Unlike the SHA256 sidecar, this protects against a compromised GitHub account. Set `REQUIRE_SIGNATURE = True` once all releases are signed.
- **Fix**: pinned `pysnmp>=4.4,<6` + `pyasn1<0.6` in requirements — unpinned installs pulled pysnmp 7.x whose changed API made the import fail, silently disabling all SNMP discovery on fresh installs.
- **Tests**: suite expanded from 6 to 73 tests, now covering `scanner.py`, `topology.py` (LLDP parser, device-type inference, graph builder), `dns_sniffer.py` (DNS parser, categorisation, persistence) and the new SNMP config validation.

## 1.3.0

- **License**: Replaced MIT with source-available license — free for personal/non-commercial use, commercial use requires a separate paid license.
- **Installer (Inno Setup)**: New `NetTrack.iss` — professional MUI wizard with welcome text, license page, directory selection, optional desktop/startup shortcuts, Add/Remove Programs registration, and finish page with launch option.
- **Installer (NSIS)**: Rewrote `installer.nsi` — removed broken `NSClientDL` download plugin; exe is now embedded at compile time using standard MUI2 pages, components, and full Add/Remove Programs registration.
- **Cleanup**: Removed `requirments.txt` (typo duplicate of `requirements.txt`) and `webapp` (scratch file).
- **README**: Added Windows installer build instructions (Inno Setup + NSIS).

## 1.2.0

- SNMP discovery respects **per-device agent port** from SNMP config.
- **README** and **requirements.txt** aligned with the Python/Flask app; removed typo filename `requirments.txt`.
- **Validation:** API routes use the same IPv4 checks as `topology` (`ipaddress`-based).
- **Topology job:** fatal errors reported via `/topology-status` (`error`); non-fatal phase issues collected in `warnings`.
- **UI:** topology discovery option checkboxes; header/legend show SSDP and DHCP fingerprint when present in topology meta.
- **PyInstaller:** common `hiddenimports` for optional discovery libraries.
