# Changelog

## 1.2.0

- SNMP discovery respects **per-device agent port** from SNMP config.
- **README** and **requirements.txt** aligned with the Python/Flask app; removed typo filename `requirments.txt`.
- **Validation:** API routes use the same IPv4 checks as `topology` (`ipaddress`-based).
- **Topology job:** fatal errors reported via `/topology-status` (`error`); non-fatal phase issues collected in `warnings`.
- **UI:** topology discovery option checkboxes; header/legend show SSDP and DHCP fingerprint when present in topology meta.
- **PyInstaller:** common `hiddenimports` for optional discovery libraries.
