# Changelog

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
