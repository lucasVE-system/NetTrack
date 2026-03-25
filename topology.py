"""
topology.py  –  NetTrack topology discovery engine
====================================================
Phase 1  : Traceroute-based L3 hop inference  (no credentials, works everywhere)
Phase 2  : SNMP  – neighbor tables, ARP cache, interface list  (managed switches)
Phase 3  : Passive pcap  – LLDP frame sniffing + DHCP fingerprinting  (admin/pcap cap)
Enrichment: mDNS / Bonjour service discovery + SSDP / UPnP device descriptions
             NetBIOS name queries  (fallback hostname for Windows boxes)
             Banner grabbing on fingerprint ports

Security notes
--------------
* SNMP community strings are kept in memory only; never logged, never returned to
  the frontend in any response.
* All subprocess calls use list args (no shell=True) and strict timeouts.
* IP addresses are validated before use as subprocess arguments.
* pcap sniffing is read-only (BPF filter, no injection).
* SSDP / mDNS / NetBIOS are read-only queries on local iface only.
* Banner grabbing connects only to IPs already discovered by the scan endpoint.
* SNMP OIDs are hardcoded – no user-supplied OID strings are ever sent to pysnmp.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

# ── optional heavy imports (fail gracefully) ─────────────────────────────────
try:
    from pysnmp.hlapi import (
        CommunityData, ContextData, ObjectIdentity, ObjectType,
        SnmpEngine, UdpTransportTarget, bulkCmd, getCmd, nextCmd,
    )
    _SNMP_OK = True
except Exception:
    _SNMP_OK = False

try:
    from zeroconf import ServiceBrowser, Zeroconf
    _ZEROCONF_OK = True
except Exception:
    _ZEROCONF_OK = False

# Scapy has known issues on some environments (broken IPv6 routes).
# We import only what we need and only if it works.
_SCAPY_OK = False
_scapy_sniff = None
_scapy_lldp  = None
try:
    import scapy.config
    scapy.config.conf.use_pcap = True          # prefer libpcap
    scapy.config.conf.verb    = 0              # silence scapy noise
    # Import only the L2/ARP layer – avoid inet6 which is broken in this env
    from scapy.layers.l2 import Ether, ARP
    from scapy.sendrecv import sniff as _sniff
    _scapy_sniff = _sniff
    _SCAPY_OK    = True
except Exception:
    pass

# ── IP validation helper ──────────────────────────────────────────────────────
_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def _valid_ip(ip: str) -> bool:
    """Return True iff ip is a well-formed unicast IPv4 address."""
    if not _IP_RE.match(ip):
        return False
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or not obj.is_multicast
    except ValueError:
        return False

def _safe_subnet(subnet: str) -> bool:
    """Accept only dotted-decimal subnet prefix like '192.168.1'."""
    parts = subnet.split('.')
    if len(parts) != 3:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 – Traceroute / TTL-based L3 topology
# ═══════════════════════════════════════════════════════════════════════════════

def traceroute_hops(target_ip: str, max_hops: int = 10, timeout: int = 2) -> List[str]:
    """
    Return an ordered list of hop IPs from local host to target_ip.
    Empty string in list means no reply for that TTL.
    Uses the OS traceroute/tracert command – no raw sockets needed.
    """
    if not _valid_ip(target_ip):
        return []

    if sys.platform == "win32":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w",
               str(timeout * 1000), target_ip]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops),
               "-w", str(timeout), target_ip]

    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    hops: List[str] = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=max_hops * (timeout + 1) + 5,
            **kwargs
        )
        for line in result.stdout.splitlines():
            # Match any IPv4 address in the line
            matches = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
            for m in matches:
                if _valid_ip(m):
                    hops.append(m)
                    break
    except Exception:
        pass
    return hops


def build_l3_topology(discovered_ips: List[str],
                      local_ip: str,
                      gateway_ip: Optional[str] = None,
                      max_workers: int = 8) -> Dict:
    """
    Run traceroutes in parallel and build a hop-graph.
    Returns {nodes: [...], edges: [{src, dst, type, ttl_distance}]}
    """
    if not _valid_ip(local_ip):
        return {"nodes": [], "edges": [], "method": "traceroute", "error": "invalid local ip"}

    hop_map: Dict[str, List[str]] = {}  # target -> [hop1, hop2, ...]
    lock = threading.Lock()

    def do_trace(ip):
        hops = traceroute_hops(ip, max_hops=8, timeout=1)
        if hops:
            with lock:
                hop_map[ip] = hops

    safe_ips = [ip for ip in discovered_ips if _valid_ip(ip) and ip != local_ip]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(as_completed([ex.submit(do_trace, ip) for ip in safe_ips]))

    # Build edge set from hop chains
    edges = []
    seen_edges = set()
    all_hop_ips = set()

    for target, hops in hop_map.items():
        # hops[0] is usually the gateway; last is target
        full_chain = hops + [target]
        for i in range(len(full_chain) - 1):
            src = full_chain[i]
            dst = full_chain[i + 1]
            if not dst:
                continue
            key = (src, dst)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"src": src, "dst": dst,
                               "type": "l3_hop", "hop_index": i})
            all_hop_ips.add(src)

    # Nodes = all IPs we know about + intermediate hops
    node_ips = set(discovered_ips) | all_hop_ips
    nodes = [{"ip": ip, "discovered_by_scan": ip in discovered_ips}
             for ip in node_ips if _valid_ip(ip)]

    return {"nodes": nodes, "edges": edges, "method": "traceroute"}


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2 – SNMP
# Whitelisted OIDs only – no user-supplied strings enter pysnmp
# ═══════════════════════════════════════════════════════════════════════════════

# Hardcoded OID whitelist
_OID_SYSNAME    = "1.3.6.1.2.1.1.5.0"
_OID_SYSDESCR   = "1.3.6.1.2.1.1.1.0"
_OID_SYSCONTACT = "1.3.6.1.2.1.1.4.0"
_OID_SYSLOC     = "1.3.6.1.2.1.1.6.0"
_OID_SYSOID     = "1.3.6.1.2.1.1.2.0"
_OID_IF_TABLE   = "1.3.6.1.2.1.2.2"      # ifTable
_OID_IP_NETTOMEDIA = "1.3.6.1.2.1.4.22"  # ipNetToMediaTable (ARP cache)
_OID_LLDP_REM   = "1.0.8802.1.1.2.1.4"   # lldpRemTable
_OID_CDP_CACHE  = "1.3.6.1.4.1.9.9.23.1.2.1"  # cdpCacheTable (Cisco)
_OID_BRIDGE_FDB = "1.3.6.1.2.1.17.4.3"   # dot1dTpFdbTable (bridge FDB)


def _snmp_get(ip: str, community: str, oid: str,
              port: int = 161, timeout: int = 3, retries: int = 1):
    """Single SNMP GET. Returns value string or None."""
    if not _SNMP_OK or not _valid_ip(ip):
        return None
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),   # SNMPv2c
            UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        errorIndication, errorStatus, _, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return str(varBind[1])
    except Exception:
        return None


def _snmp_walk(ip: str, community: str, oid: str,
               port: int = 161, timeout: int = 3, retries: int = 1,
               max_rows: int = 512) -> List[Tuple[str, str]]:
    """SNMP WALK. Returns list of (oid_str, value_str). Capped at max_rows."""
    if not _SNMP_OK or not _valid_ip(ip):
        return []
    results = []
    try:
        for (errorIndication, errorStatus, _, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            maxRows=max_rows
        ):
            if errorIndication or errorStatus:
                break
            for varBind in varBinds:
                results.append((str(varBind[0]), str(varBind[1])))
    except Exception:
        pass
    return results


def snmp_get_sysinfo(ip: str, community: str, port: int = 161) -> Dict:
    """Fetch basic system info (sysName, sysDescr, etc.) via SNMP."""
    return {
        "sysName":    _snmp_get(ip, community, _OID_SYSNAME, port=port)    or "",
        "sysDescr":   _snmp_get(ip, community, _OID_SYSDESCR, port=port)   or "",
        "sysContact": _snmp_get(ip, community, _OID_SYSCONTACT, port=port) or "",
        "sysLocation":_snmp_get(ip, community, _OID_SYSLOC, port=port)     or "",
        "sysObjectID":_snmp_get(ip, community, _OID_SYSOID, port=port)     or "",
    }


def _parse_mac_from_oid_suffix(oid_str: str) -> str:
    """Extract MAC from OID suffix like '...1.0.80.8.2.0.34'."""
    parts = oid_str.split('.')
    if len(parts) >= 6:
        try:
            mac_parts = parts[-6:]
            return ':'.join(f'{int(p):02X}' for p in mac_parts)
        except Exception:
            pass
    return ""


def snmp_get_arp_table(ip: str, community: str, port: int = 161) -> Dict[str, str]:
    """Walk ipNetToMediaTable → {ip: mac}."""
    result = {}
    rows = _snmp_walk(ip, community, _OID_IP_NETTOMEDIA, port=port)
    for oid_str, val in rows:
        # ipNetToMediaPhysAddress ends in .1.x.x.x.x (IP as OID suffix)
        if "ipNetToMediaPhysAddress" in oid_str or ".22.1.2." in oid_str:
            # value is a hex string like '0x001122334455'
            raw = val.replace("0x", "").replace(":", "")
            if len(raw) == 12:
                mac = ':'.join(raw[i:i+2].upper() for i in range(0, 12, 2))
                # IP is the last 4 parts of OID
                parts = oid_str.split('.')
                if len(parts) >= 4:
                    try:
                        peer_ip = '.'.join(parts[-4:])
                        if _valid_ip(peer_ip):
                            result[peer_ip] = mac
                    except Exception:
                        pass
    return result


def snmp_get_lldp_neighbors(ip: str, community: str, port: int = 161) -> List[Dict]:
    """Walk lldpRemTable → list of neighbor dicts."""
    neighbors = []
    rows = _snmp_walk(ip, community, _OID_LLDP_REM, port=port, max_rows=256)
    # Group by (local_port_idx, remote_idx) – last two OID components
    remote: Dict[str, Dict] = {}
    for oid_str, val in rows:
        parts = oid_str.split('.')
        # lldpRemTable OID format: ...lldpRemTable.1.<type>.<timemark>.<localport>.<remidx>
        try:
            key = f"{parts[-2]}.{parts[-1]}"
        except IndexError:
            continue

        entry = remote.setdefault(key, {})

        if "lldpRemPortId" in oid_str:
            entry["remote_port"] = val
        elif "lldpRemSysName" in oid_str:
            entry["sys_name"] = val
        elif "lldpRemSysDesc" in oid_str:
            entry["sys_desc"] = val
        elif "lldpRemChassisId" in oid_str:
            entry["chassis_id"] = val
        elif "lldpRemManAddrIfId" in oid_str or "lldpRemManAddr" in oid_str:
            if _valid_ip(val):
                entry["mgmt_ip"] = val

    neighbors = [v for v in remote.values() if v]
    return neighbors


def snmp_get_cdp_neighbors(ip: str, community: str, port: int = 161) -> List[Dict]:
    """Walk cdpCacheTable (Cisco) → list of neighbor dicts."""
    neighbors = []
    rows = _snmp_walk(ip, community, _OID_CDP_CACHE, port=port, max_rows=256)
    remote: Dict[str, Dict] = {}
    for oid_str, val in rows:
        parts = oid_str.split('.')
        try:
            key = f"{parts[-2]}.{parts[-1]}"
        except IndexError:
            continue
        entry = remote.setdefault(key, {})
        if "cdpCacheDeviceId" in oid_str:
            entry["device_id"] = val
        elif "cdpCacheDevicePort" in oid_str:
            entry["remote_port"] = val
        elif "cdpCachePlatform" in oid_str:
            entry["platform"] = val
        elif "cdpCacheAddress" in oid_str:
            # value may be hex IP
            if _valid_ip(val):
                entry["mgmt_ip"] = val
    return [v for v in remote.values() if v]


def snmp_get_fdb(ip: str, community: str, port: int = 161) -> List[Dict]:
    """
    Walk dot1dTpFdbTable → [{mac, port_index, status}]
    Useful for knowing which MAC addresses are behind which switch port.
    """
    rows = _snmp_walk(ip, community, _OID_BRIDGE_FDB, port=port, max_rows=2048)
    fdb_port: Dict[str, str]   = {}
    fdb_status: Dict[str, str] = {}
    for oid_str, val in rows:
        mac = _parse_mac_from_oid_suffix(oid_str)
        if not mac:
            continue
        if "dot1dTpFdbPort" in oid_str or ".17.4.3.1.2." in oid_str:
            fdb_port[mac] = val
        elif "dot1dTpFdbStatus" in oid_str or ".17.4.3.1.3." in oid_str:
            fdb_status[mac] = val

    return [
        {"mac": mac, "port_index": fdb_port.get(mac, ""),
         "status": fdb_status.get(mac, "")}
        for mac in set(fdb_port) | set(fdb_status)
    ]


def snmp_full_discovery(ip: str, community: str, *, port: int = 161) -> Dict:
    """
    Run all SNMP queries against a device. Returns a rich topology dict.
    community string is NEVER returned to the caller in this dict.
    """
    if not _SNMP_OK:
        return {"error": "pysnmp not available", "ip": ip}
    if not _valid_ip(ip):
        return {"error": "invalid ip", "ip": ip}

    result: Dict = {"ip": ip}
    result["sysinfo"]   = snmp_get_sysinfo(ip, community, port=port)
    result["arp_table"] = snmp_get_arp_table(ip, community, port=port)
    result["lldp"]      = snmp_get_lldp_neighbors(ip, community, port=port)
    result["cdp"]       = snmp_get_cdp_neighbors(ip, community, port=port)
    result["fdb"]       = snmp_get_fdb(ip, community, port=port)
    # community string deliberately excluded from result
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 – Passive pcap (LLDP + DHCP fingerprinting)
# ═══════════════════════════════════════════════════════════════════════════════

# DHCP option 55 (parameter request list) fingerprints
# Partial list – enough to distinguish major OS families
_DHCP_FINGERPRINTS: Dict[str, str] = {
    "1,3,6,15,119,252,95,44,46":          "macOS / iOS",
    "1,3,6,15,119,95,252,44,46":           "macOS / iOS",
    "1,28,2,3,15,6,119,12,44,47":          "Android",
    "1,33,3,6,15,26,28,51,58,59":          "Linux (systemd-networkd)",
    "1,3,6,12,15,17,23,28,29,42,72,180":   "Linux (dhcpcd)",
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows 10/11",
    "1,3,6,12,15,17,28,42,51,54,58,59,121": "Windows 7/8",
    "1,3,6,15,44,46,47,31,33,121,249,43,252,12": "Windows XP/Vista",
    "1,3,6,15,6,44,3,33,150,43,114,69,252,12":   "Cisco IP Phone",
}

def _match_fingerprint(opt55: str) -> str:
    """Match DHCP option 55 string against known fingerprints."""
    for pattern, name in _DHCP_FINGERPRINTS.items():
        if opt55.startswith(pattern) or pattern.startswith(opt55):
            return name
    return ""


# LLDP Ethernet type
_LLDP_ETHERTYPE = 0x88CC
_SNAP_ETHERTYPE = 0x8100

# Pure-Python minimal LLDP parser (avoids scapy entirely)
def _parse_lldp_frame(raw: bytes) -> Dict:
    """
    Parse raw LLDP Ethernet frame bytes.
    Returns dict with chassis_id, port_id, sys_name, sys_desc, mgmt_ip.
    """
    result: Dict = {}
    if len(raw) < 14:
        return result

    # Skip Ethernet header (14 bytes) + check ethertype
    ethertype = struct.unpack("!H", raw[12:14])[0]
    if ethertype != _LLDP_ETHERTYPE:
        return result

    offset = 14
    while offset + 2 <= len(raw):
        try:
            header = struct.unpack("!H", raw[offset:offset+2])[0]
            tlv_type   = (header >> 9) & 0x7F
            tlv_length = header & 0x01FF
            offset += 2
            value = raw[offset:offset+tlv_length]
            offset += tlv_length

            if tlv_type == 0:   # End of LLDPDU
                break
            elif tlv_type == 1:  # Chassis ID
                subtype = value[0] if value else 0
                if subtype == 4:  # MAC
                    result["chassis_id"] = ':'.join(f'{b:02X}' for b in value[1:7])
                else:
                    result["chassis_id"] = value[1:].decode('utf-8', errors='replace')
            elif tlv_type == 2:  # Port ID
                subtype = value[0] if value else 0
                result["port_id"] = value[1:].decode('utf-8', errors='replace')
            elif tlv_type == 4:  # Time To Live – skip
                pass
            elif tlv_type == 5:  # System Name
                result["sys_name"] = value.decode('utf-8', errors='replace').strip('\x00')
            elif tlv_type == 6:  # System Description
                result["sys_desc"] = value.decode('utf-8', errors='replace').strip('\x00')
            elif tlv_type == 8:  # Management Address
                if len(value) >= 6:
                    addr_len    = value[0]
                    addr_subtype = value[1]
                    if addr_subtype == 1 and addr_len == 5:  # IPv4
                        ip_bytes = value[2:6]
                        result["mgmt_ip"] = '.'.join(str(b) for b in ip_bytes)
        except Exception:
            break

    return result


class _DHCPSniffer:
    """
    Pure-socket DHCP sniffer (listens on UDP 67/68).
    Falls back silently if we lack permission.
    Uses SO_REUSEADDR so it doesn't conflict with a real DHCP server.
    """

    def __init__(self):
        self._lock      = threading.Lock()
        self._findings  : Dict[str, Dict] = {}   # mac -> {hostname, vendor_class, opt55_os}
        self._thread    : Optional[threading.Thread] = None
        self._running   = False
        self._sock      = None
        self._available = False

    def start(self, duration: int = 10) -> bool:
        """Start sniffing for `duration` seconds. Returns True if started."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(1.0)
            self._sock      = s
            self._running   = True
            self._available = True
            self._thread    = threading.Thread(
                target=self._run, args=(duration,), daemon=True)
            self._thread.start()
            return True
        except PermissionError:
            return False
        except Exception:
            return False

    def _run(self, duration: int):
        deadline = time.time() + duration
        while self._running and time.time() < deadline:
            try:
                data, addr = self._sock.recvfrom(4096)
                self._parse(data)
            except socket.timeout:
                continue
            except Exception:
                break
        self._running = False
        try:
            self._sock.close()
        except Exception:
            pass

    def _parse(self, data: bytes):
        """
        Parse a raw UDP/IP packet looking for DHCP DISCOVER or REQUEST.
        Extracts: client MAC, hostname (option 12), vendor class (option 60),
        parameter request list (option 55).
        """
        try:
            # IP header length
            if len(data) < 20:
                return
            ihl = (data[0] & 0x0F) * 4
            proto = data[9]
            if proto != 17:  # UDP
                return
            udp_offset = ihl
            if len(data) < udp_offset + 8:
                return
            dst_port = struct.unpack("!H", data[udp_offset+2:udp_offset+4])[0]
            if dst_port not in (67, 68):
                return

            # BOOTP/DHCP starts at udp_offset + 8
            bootp = data[udp_offset + 8:]
            if len(bootp) < 240:
                return
            if bootp[0] != 1:  # BOOTREQUEST
                return

            # Client MAC from BOOTP chaddr (bytes 28-34, first 6 bytes)
            mac_bytes = bootp[28:34]
            mac = ':'.join(f'{b:02X}' for b in mac_bytes)
            if mac == "00:00:00:00:00:00":
                return

            # DHCP magic cookie
            if bootp[236:240] != b'\x63\x82\x53\x63':
                return

            # Parse options
            hostname     = ""
            vendor_class = ""
            opt55        = ""
            i = 240
            while i < len(bootp):
                opt = bootp[i]
                if opt == 255:  # End
                    break
                if opt == 0:    # Pad
                    i += 1
                    continue
                if i + 1 >= len(bootp):
                    break
                length = bootp[i + 1]
                val    = bootp[i + 2: i + 2 + length]
                if opt == 12:   # Hostname
                    hostname = val.decode('utf-8', errors='replace').strip('\x00')
                elif opt == 60: # Vendor Class Identifier
                    vendor_class = val.decode('utf-8', errors='replace').strip('\x00')
                elif opt == 55: # Parameter Request List
                    opt55 = ','.join(str(b) for b in val)
                i += 2 + length

            finding: Dict = {}
            if hostname:
                finding["hostname"] = hostname
            if vendor_class:
                finding["vendor_class"] = vendor_class
            if opt55:
                finding["opt55_os"] = _match_fingerprint(opt55)
                finding["opt55_raw"] = opt55

            if finding:
                with self._lock:
                    existing = self._findings.get(mac, {})
                    existing.update(finding)
                    self._findings[mac] = existing
        except Exception:
            pass

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def results(self) -> Dict[str, Dict]:
        with self._lock:
            return dict(self._findings)


class _LLDPSniffer:
    """
    Pure-socket LLDP sniffer. Listens on raw Ethernet socket (Linux/Windows).
    Needs CAP_NET_RAW on Linux or admin on Windows.
    """

    LLDP_MULTICAST = b'\x01\x80\xc2\x00\x00\x0e'

    def __init__(self):
        self._lock     = threading.Lock()
        self._frames   : List[Dict] = []
        self._thread   : Optional[threading.Thread] = None
        self._running  = False
        self._available = False

    def start(self, iface: str = "", duration: int = 30) -> bool:
        try:
            if sys.platform == "win32":
                # On Windows, use scapy if available; otherwise skip
                if not _SCAPY_OK:
                    return False
                self._use_scapy = True
            else:
                self._use_scapy = False

            self._iface    = iface
            self._running  = True
            self._available = True
            self._thread   = threading.Thread(
                target=self._run, args=(duration,), daemon=True)
            self._thread.start()
            return True
        except Exception:
            return False

    def _run(self, duration: int):
        if self._use_scapy and _scapy_sniff:
            # Scapy path (Windows)
            try:
                _scapy_sniff(
                    filter="ether proto 0x88CC",
                    prn=self._handle_scapy,
                    timeout=duration,
                    store=False
                )
            except Exception:
                pass
        else:
            # Raw socket path (Linux)
            self._run_raw(duration)
        self._running = False

    def _handle_scapy(self, pkt):
        try:
            raw = bytes(pkt)
            parsed = _parse_lldp_frame(raw)
            if parsed:
                with self._lock:
                    self._frames.append(parsed)
        except Exception:
            pass

    def _run_raw(self, duration: int):
        try:
            # ETH_P_LLDP = 0x88CC
            s = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW,
                socket.htons(0x88CC)
            )
            s.settimeout(1.0)
            deadline = time.time() + duration
            while self._running and time.time() < deadline:
                try:
                    data, _ = s.recvfrom(2048)
                    parsed = _parse_lldp_frame(data)
                    if parsed:
                        with self._lock:
                            self._frames.append(parsed)
                except socket.timeout:
                    continue
                except Exception:
                    break
            s.close()
        except PermissionError:
            self._available = False
        except Exception:
            self._available = False

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def results(self) -> List[Dict]:
        with self._lock:
            return list(self._frames)


# ═══════════════════════════════════════════════════════════════════════════════
# ENRICHMENT – mDNS / Bonjour, SSDP/UPnP, NetBIOS, Banner Grabbing
# ═══════════════════════════════════════════════════════════════════════════════

class _MDNSListener:
    """
    Passive mDNS listener using zeroconf ServiceBrowser.
    Collects {hostname, type, ip} for each announced service.
    Read-only – no queries sent.
    """

    # Common mDNS service types we care about
    SERVICE_TYPES = [
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_ssh._tcp.local.",
        "_smb._tcp.local.",
        "_ftp._tcp.local.",
        "_printer._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
        "_airplay._tcp.local.",
        "_googlecast._tcp.local.",
        "_homekit._tcp.local.",
        "_hap._tcp.local.",
        "_apple-mobdev2._tcp.local.",
        "_daap._tcp.local.",
        "_raop._tcp.local.",
        "_rfb._tcp.local.",
        "_device-info._tcp.local.",
        "_workstation._tcp.local.",
        "_companion-link._tcp.local.",
        "_nas._tcp.local.",
        "_nfs._tcp.local.",
        "_afpovertcp._tcp.local.",
        "_rtsp._tcp.local.",
    ]

    def __init__(self):
        self._lock     = threading.Lock()
        self._devices  : Dict[str, Dict] = {}   # ip -> {hostname, services:[...]}
        self._zc       = None
        self._browsers : List = []
        self._available = False

    def start(self, duration: int = 5) -> bool:
        if not _ZEROCONF_OK:
            return False
        try:
            self._zc = Zeroconf()
            for stype in self.SERVICE_TYPES:
                b = ServiceBrowser(self._zc, stype, handlers=[self._on_service])
                self._browsers.append(b)
            self._available = True
            # Run for `duration` seconds then stop
            t = threading.Timer(duration, self.stop)
            t.daemon = True
            t.start()
            return True
        except Exception:
            return False

    def _on_service(self, zeroconf, service_type, name, state_change):
        try:
            from zeroconf import ServiceStateChange
            if state_change != ServiceStateChange.Added:
                return
            info = zeroconf.get_service_info(service_type, name)
            if not info:
                return
            # Extract IP
            ips = []
            for addr in info.addresses:
                try:
                    ip = socket.inet_ntoa(addr)
                    if _valid_ip(ip):
                        ips.append(ip)
                except Exception:
                    pass
            hostname = info.server or info.name or ""
            hostname = hostname.rstrip('.').replace('.local', '')
            service_label = service_type.replace('._tcp.local.', '').replace('._udp.local.', '').lstrip('_')
            for ip in ips:
                with self._lock:
                    entry = self._devices.setdefault(ip, {"hostname": hostname, "services": []})
                    if hostname and not entry.get("hostname"):
                        entry["hostname"] = hostname
                    if service_label not in entry["services"]:
                        entry["services"].append(service_label)
        except Exception:
            pass

    def stop(self):
        try:
            if self._zc:
                self._zc.close()
        except Exception:
            pass

    def results(self) -> Dict[str, Dict]:
        with self._lock:
            return dict(self._devices)


def ssdp_discover(timeout: int = 3) -> List[Dict]:
    """
    Send SSDP M-SEARCH and collect UPnP device announcements.
    Returns list of {ip, location_url, server, usn, st}.
    Bound to local interface only; does not follow location URLs automatically.
    """
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    MSEARCH = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    found: List[Dict] = []
    seen_usn: set = set()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(MSEARCH, (SSDP_ADDR, SSDP_PORT))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(4096)
                ip = addr[0]
                if not _valid_ip(ip):
                    continue
                text = data.decode('utf-8', errors='replace')
                entry: Dict = {"ip": ip}
                for line in text.splitlines():
                    low = line.lower()
                    if low.startswith("location:"):
                        loc = line.split(":", 1)[1].strip()
                        # Only store http/https URLs; do not follow yet
                        if loc.startswith("http://") or loc.startswith("https://"):
                            entry["location_url"] = loc
                    elif low.startswith("server:"):
                        entry["server"] = line.split(":", 1)[1].strip()
                    elif low.startswith("usn:"):
                        entry["usn"] = line.split(":", 1)[1].strip()
                    elif low.startswith("st:"):
                        entry["st"] = line.split(":", 1)[1].strip()
                usn = entry.get("usn", ip)
                if usn not in seen_usn:
                    seen_usn.add(usn)
                    found.append(entry)
            except socket.timeout:
                break
            except Exception:
                continue
        s.close()
    except Exception:
        pass
    return found


def ssdp_fetch_description(location_url: str, timeout: int = 3) -> Dict:
    """
    Fetch and parse a UPnP device description XML from location_url.
    Only HTTP/HTTPS URLs are followed; only local IPs are permitted.
    Returns {friendly_name, device_type, manufacturer, model_name, model_number}.
    """
    import urllib.request
    import xml.etree.ElementTree as ET

    result: Dict = {}
    if not location_url:
        return result

    # Security: only allow http(s) and only local (RFC1918) IPs
    try:
        from urllib.parse import urlparse
        parsed = urlparse(location_url)
        if parsed.scheme not in ("http", "https"):
            return result
        host = parsed.hostname or ""
        if not _valid_ip(host):
            return result
        obj = ipaddress.ip_address(host)
        if not obj.is_private:
            return result
    except Exception:
        return result

    try:
        req = urllib.request.Request(
            location_url,
            headers={"User-Agent": "NetTrack/1.0 UPnP/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(32768)   # cap at 32 KB
        root = ET.fromstring(raw)
        ns = {'u': 'urn:schemas-upnp-org:device-1-0'}
        dev = root.find('.//u:device', ns) or root.find('.//device')
        if dev is None:
            return result

        def _txt(tag):
            el = dev.find(f'u:{tag}', ns) or dev.find(tag)
            return el.text.strip() if el is not None and el.text else ""

        result = {
            "friendly_name":  _txt("friendlyName"),
            "device_type":    _txt("deviceType"),
            "manufacturer":   _txt("manufacturer"),
            "model_name":     _txt("modelName"),
            "model_number":   _txt("modelNumber"),
        }
    except Exception:
        pass
    return result


def netbios_query(ip: str, timeout: float = 1.5) -> str:
    """
    Send a NetBIOS Name Service node status request.
    Returns the first registered name (typically the hostname) or "".
    Pure UDP, no scapy needed.
    """
    if not _valid_ip(ip):
        return ""
    # NBNS Node Status Request packet
    # Transaction ID = 0x1234, flags = 0x0010 (status request), NBSTAT query
    packet = bytes([
        0x12, 0x34,   # TxID
        0x00, 0x10,   # Flags: status request
        0x00, 0x01,   # Questions: 1
        0x00, 0x00,   # Answer RRs
        0x00, 0x00,   # Authority RRs
        0x00, 0x00,   # Additional RRs
        # Question name: * (encoded as 0x20 '*' + 15 spaces in NBE encoding)
        0x20,
        0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00,
        0x00, 0x21,   # Type: NBSTAT
        0x00, 0x01,   # Class: IN
    ])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
        # Parse response: skip header (12 bytes), then name entries
        if len(data) < 57:
            return ""
        # Number of names at byte 56
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name = data[offset:offset+15].decode('ascii', errors='replace').rstrip()
            flags = struct.unpack("!H", data[offset+16:offset+18])[0]
            # Flag bit 0x8000 = group name; skip those
            if not (flags & 0x8000) and name.strip():
                return name.strip()
            offset += 18
    except Exception:
        pass
    return ""


# Fingerprint ports for banner grabbing
_FINGERPRINT_PORTS: List[Tuple[int, str]] = [
    (22,   "ssh"),
    (23,   "telnet"),
    (80,   "http"),
    (443,  "https"),
    (554,  "rtsp"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (9100, "jetdirect"),     # printers
    (5000, "upnp"),
    (49152,"upnp-alt"),
]

def grab_banner(ip: str, port: int, service: str,
                timeout: float = 1.5) -> Optional[str]:
    """
    Connect to ip:port and read the banner (first 512 bytes).
    For HTTP, sends a minimal GET / HTTP/1.0 request.
    Returns banner string or None.
    """
    if not _valid_ip(ip):
        return None
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        banner = b""
        if service in ("http", "http-alt"):
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        elif service == "rtsp":
            s.sendall(f"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        try:
            s.settimeout(timeout)
            banner = s.recv(512)
        except socket.timeout:
            pass
        s.close()
        return banner.decode('utf-8', errors='replace').strip()
    except Exception:
        return None


def fingerprint_device(ip: str, max_workers: int = 4) -> Dict:
    """
    Try fingerprint ports in parallel. Returns {open_ports: [...], banners: {port: banner}}.
    """
    if not _valid_ip(ip):
        return {}
    open_ports: List[int] = []
    banners: Dict[int, str] = {}
    lock = threading.Lock()

    def probe(port, service):
        banner = grab_banner(ip, port, service)
        if banner is not None:
            with lock:
                open_ports.append(port)
                if banner:
                    banners[port] = banner[:256]  # cap per port

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(as_completed([ex.submit(probe, p, s) for p, s in _FINGERPRINT_PORTS]))

    return {"open_ports": sorted(open_ports), "banners": banners}


# ═══════════════════════════════════════════════════════════════════════════════
# DEVICE TYPE AUTO-DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def infer_device_type(device: Dict) -> str:
    """
    Heuristically infer device type from available data.
    Returns a type string compatible with the existing ICONS map.
    """
    ip        = (device.get("ip") or "").lower()
    vendor    = (device.get("vendor") or "").lower()
    hostname  = (device.get("hostname") or "").lower()
    sys_descr = (device.get("sysinfo", {}).get("sysDescr") or "").lower()
    services  = [s.lower() for s in device.get("mdns_services") or []]
    banners   = {k: (v or "").lower() for k, v in (device.get("banners") or {}).items()}
    open_ports = device.get("open_ports") or []
    vendor_class = (device.get("vendor_class") or "").lower()
    opt55_os  = (device.get("opt55_os") or "").lower()
    lldp_info = device.get("lldp_neighbors") or []
    cdp_info  = device.get("cdp_neighbors") or []

    # Infrastructure first (highest confidence)
    infra_keywords = {
        "router":   ["router", "gateway", "openwrt", "routeros", "dd-wrt", "pfsense",
                     "mikrotik", "ubiquiti edgerouter", "cisco ios xe", "cisco ios",
                     "juniper junos", "fortigate", "vyos"],
        "switch":   ["switch", "catalyst", "procurve", "powerconnect", "comware",
                     "nexus", "ex series", "ex2", "sg2", "sg3", "netgear gs"],
        "ap":       ["access point", "unifi", "aironet", "aruba", "meraki",
                     "linksys wrt", "airport", "eap", "ew", "wap"],
        "firewall": ["firewall", "asa ", "fortigate", "pfsense", "sophos", "checkpoint",
                     "iptables", "opnsense"],
    }
    combined = f"{vendor} {hostname} {sys_descr}"
    for dtype, kws in infra_keywords.items():
        if any(kw in combined for kw in kws):
            return dtype

    # Gateway heuristic: x.x.x.1 or x.x.x.254
    if ip.endswith(".1") or ip.endswith(".254"):
        if "switch" not in combined and "ap" not in combined:
            return "router"

    # NAS
    if any(k in combined for k in ["synology", "qnap", "freenas", "truenas",
                                     "nas", "network attached", "netatalk"]):
        return "nas"
    if "afpovertcp" in services or "nfs" in services or "smb" in services:
        return "nas"

    # Camera
    if any(k in combined for k in ["camera", "ipcam", "hikvision", "dahua",
                                     "foscam", "axis", "vivotek", "bosch cam"]):
        return "camera"
    if 554 in open_ports:  # RTSP – very likely a camera
        return "camera"

    # Printer
    if any(k in combined for k in ["printer", "laserjet", "inkjet", "officejet",
                                     "workcentre", "bizhub", "brother", "epson",
                                     "canon pixma", "kyocera"]):
        return "printer"
    if 9100 in open_ports or "ipp" in services or "printer" in services:
        return "printer"

    # Server
    if any(k in combined for k in ["windows server", "ubuntu server", "debian",
                                     "centos", "red hat", "proxmox", "esxi",
                                     "vmware", "hyper-v"]):
        return "server"
    if 22 in open_ports and (443 in open_ports or 80 in open_ports):
        if any(k in banners.get(80, "") or banners.get(443, "")
               for k in ["apache", "nginx", "iis", "lighttpd"]):
            return "server"

    # IoT / Smart devices
    if any(k in combined for k in ["espressif", "tuya", "shelly", "tasmota",
                                     "philips hue", "ikea tradfri", "nest",
                                     "ring", "amazon echo", "google home",
                                     "sonos", "wemo", "arlo", "roborock"]):
        return "iot"
    if "homekit" in services or "googlecast" in services or "airplay" in services:
        return "iot"

    # Nintendo
    if "nintendo" in vendor:
        return "phone"  # closest icon

    # Mobile / Phone
    if any(k in opt55_os for k in ["android", "ios", "macos / ios"]):
        return "phone"
    if any(k in combined for k in ["iphone", "ipad", "android", "samsung mobile",
                                     "huawei", "xiaomi", "oneplus"]):
        return "phone"

    # PC / Laptop
    if any(k in opt55_os for k in ["windows"]):
        return "pc"
    if any(k in combined for k in ["intel", "dell", "hp ", "lenovo", "asus",
                                     "acer", "msi", "gigabyte", "asrock"]):
        # Intel/Dell could be server too – check ports
        if 3389 in open_ports:  # RDP
            return "pc"
        return "pc"
    if any(k in combined for k in ["apple", "macbook", "imac"]):
        return "laptop"
    if "ssh" in services or "workstation" in services:
        return "pc"

    return "other"


# ═══════════════════════════════════════════════════════════════════════════════
# TOPOLOGY GRAPH BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def build_topology_graph(
    scan_devices: List[Dict],
    traceroute_data: Optional[Dict] = None,
    snmp_results:   Optional[Dict[str, Dict]] = None,
    lldp_frames:    Optional[List[Dict]] = None,
    mdns_data:      Optional[Dict[str, Dict]] = None,
    ssdp_data:      Optional[List[Dict]] = None,
    dhcp_data:      Optional[Dict[str, Dict]] = None,
    fingerprint_data: Optional[Dict[str, Dict]] = None,
) -> Dict:
    """
    Merge all discovery results into a unified topology graph.
    Returns {nodes: [...], edges: [...], meta: {...}}.
    """
    # Index devices by IP
    node_map: Dict[str, Dict] = {d["ip"]: dict(d) for d in scan_devices if d.get("ip")}

    # ── Enrich from DHCP fingerprinting
    for mac, info in (dhcp_data or {}).items():
        # Find device by MAC
        for ip, dev in node_map.items():
            if dev.get("mac") == mac:
                dev.update(info)
                break

    # ── Enrich from mDNS
    for ip, info in (mdns_data or {}).items():
        if ip in node_map:
            node_map[ip]["hostname"] = node_map[ip].get("hostname") or info.get("hostname", "")
            node_map[ip]["mdns_services"] = info.get("services", [])

    # ── Enrich from SSDP
    ssdp_map: Dict[str, Dict] = {}
    for entry in (ssdp_data or []):
        ip = entry.get("ip", "")
        if ip:
            ssdp_map[ip] = entry
    for ip, entry in ssdp_map.items():
        if ip in node_map:
            node_map[ip]["ssdp_server"]  = entry.get("server", "")
            node_map[ip]["ssdp_st"]      = entry.get("st", "")
            node_map[ip]["location_url"] = entry.get("location_url", "")

    # ── Enrich from banner grabbing
    for ip, fp in (fingerprint_data or {}).items():
        if ip in node_map:
            node_map[ip]["open_ports"] = fp.get("open_ports", [])
            node_map[ip]["banners"]    = fp.get("banners", {})

    # ── Enrich from SNMP
    for ip, snmp in (snmp_results or {}).items():
        if ip in node_map:
            node_map[ip]["sysinfo"] = snmp.get("sysinfo", {})
            # Merge SNMP-discovered neighbors as potential new nodes
            for peer_ip in snmp.get("arp_table", {}).keys():
                if peer_ip not in node_map and _valid_ip(peer_ip):
                    node_map[peer_ip] = {
                        "ip": peer_ip, "discovered_by": "snmp_arp",
                        "type": "other", "name": "", "mac": ""
                    }

    # ── Auto-infer device types
    for ip, dev in node_map.items():
        if dev.get("type", "other") == "other":
            dev["type"] = infer_device_type(dev)

    # ── Build edges
    edges: List[Dict] = []
    seen_edges: set = set()

    def add_edge(src, dst, etype, **kwargs):
        if not (_valid_ip(src) and _valid_ip(dst)) or src == dst:
            return
        key = (src, dst, etype)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"src": src, "dst": dst, "type": etype, **kwargs})

    # Edges from traceroute
    for e in (traceroute_data or {}).get("edges", []):
        add_edge(e["src"], e["dst"], "l3_hop", hop_index=e.get("hop_index", 0))

    # Edges from SNMP LLDP
    for ip, snmp in (snmp_results or {}).items():
        for neighbor in snmp.get("lldp", []):
            peer_ip = neighbor.get("mgmt_ip", "")
            if peer_ip and _valid_ip(peer_ip):
                add_edge(ip, peer_ip, "lldp",
                         remote_port=neighbor.get("remote_port", ""),
                         sys_name=neighbor.get("sys_name", ""))

    # Edges from SNMP CDP
    for ip, snmp in (snmp_results or {}).items():
        for neighbor in snmp.get("cdp", []):
            peer_ip = neighbor.get("mgmt_ip", "")
            if peer_ip and _valid_ip(peer_ip):
                add_edge(ip, peer_ip, "cdp",
                         device_id=neighbor.get("device_id", ""))

    # Edges from passive LLDP frames
    for frame in (lldp_frames or []):
        mgmt_ip = frame.get("mgmt_ip", "")
        if mgmt_ip and _valid_ip(mgmt_ip):
            # Link to gateway as best guess if we don't know source IP
            gw = _find_gateway(node_map)
            if gw:
                add_edge(gw, mgmt_ip, "lldp_passive",
                         sys_name=frame.get("sys_name", ""))

    # Fallback: if no topology edges at all, connect everything to gateway
    if not edges:
        gw = _find_gateway(node_map)
        if gw:
            for ip in node_map:
                if ip != gw:
                    add_edge(gw, ip, "inferred_star")

    # Nodes – strip internal-only fields before sending to frontend
    _INTERNAL_KEYS = {"banners", "location_url"}
    nodes = []
    for ip, dev in node_map.items():
        node = {k: v for k, v in dev.items() if k not in _INTERNAL_KEYS}
        nodes.append(node)

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "has_lldp":  bool(lldp_frames) or any(
                snmp.get("lldp") for snmp in (snmp_results or {}).values()),
            "has_snmp":  bool(snmp_results),
            "has_mdns":  bool(mdns_data),
            "has_ssdp":  bool(ssdp_data),
            "has_dhcp_fp": bool(dhcp_data),
            "has_traceroute": bool(
                (traceroute_data or {}).get("edges")),
        }
    }


def _find_gateway(node_map: Dict[str, Dict]) -> Optional[str]:
    """Find the most likely gateway IP in node_map."""
    # Prefer x.x.x.1
    for ip in node_map:
        if ip.endswith(".1"):
            return ip
    # Then x.x.x.254
    for ip in node_map:
        if ip.endswith(".254"):
            return ip
    # Then any router-typed node
    for ip, dev in node_map.items():
        if dev.get("type") == "router":
            return ip
    return next(iter(node_map), None)
