"""
scanner.py  –  NetTrack network scanning utilities
===================================================
Extracted from app.py to separate concerns.
Handles ARP, ping sweeps, vendor lookups, hostname resolution.

All subprocess calls use list args + timeouts.
IP addresses are validated before use.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import topology as topo


def get_local_ip() -> str:
    """Detect local IP by connecting to a public DNS server (no actual data sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"


def get_subnet(local_ip: str) -> str:
    """Extract /24 subnet prefix from an IP (e.g., '192.168.1.100' -> '192.168.1')."""
    return ".".join(local_ip.split(".")[:3])


def ping_host(ip: str) -> bool:
    """
    Ping a single host. Returns True if reachable, False otherwise.
    Uses platform-specific ping command with 1-second timeout.
    """
    try:
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(
            ["ping", "-n" if sys.platform == "win32" else "-c", "1",
             "-w" if sys.platform == "win32" else "-W",
             "300" if sys.platform == "win32" else "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=1, **kwargs
        )
        return result.returncode == 0
    except Exception:
        return False


def get_arp_table() -> Dict[str, str]:
    """
    Query ARP table and return {ip: mac} mapping.
    Filters out broadcast, multicast, and reserved ranges.
    """
    discovered: Dict[str, str] = {}
    try:
        kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} \
            if sys.platform == "win32" else {}
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True,
            timeout=5, **kwargs
        )
        for line in result.stdout.splitlines():
            match = re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\w-]{17})', line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                if (not ip.endswith(".255")
                        and not ip.startswith("224.")
                        and not ip.startswith("239.")
                        and mac != "FF:FF:FF:FF:FF:FF"):
                    discovered[ip] = mac
    except Exception as e:
        print(f"ARP error: {e}")
    return discovered


# ── MAC VENDOR LOOKUP ────────────────────────────────────────────────────────
_mac_lookup = None
_mac_lookup_lock = threading.Lock()


def get_mac_lookup():
    """
    Lazily initialize MAC vendor lookup (thread-safe singleton).
    Returns MacLookup instance or None if not available.
    """
    global _mac_lookup
    with _mac_lookup_lock:
        if _mac_lookup is None:
            try:
                from mac_vendor_lookup import MacLookup
                _mac_lookup = MacLookup()
            except Exception:
                _mac_lookup = False
    return _mac_lookup if _mac_lookup else None


def lookup_vendor(mac: str) -> str:
    """Look up vendor name for a MAC address. Returns empty string if not found."""
    try:
        ml = get_mac_lookup()
        if ml:
            return ml.lookup(mac)
    except Exception:
        pass
    return ""


def get_hostname(ip: str) -> str:
    """Reverse DNS lookup. Returns hostname or empty string."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def ping_sweep(subnet: str) -> List[str]:
    """
    Ping sweep across a /24 subnet (e.g., '192.168.1').
    Returns list of responsive IPs.
    Uses thread pool with 50 concurrent workers.
    """
    if not topo._safe_subnet(subnet):
        return []
    alive: List[str] = []
    ips = [f"{subnet}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            try:
                if future.result():
                    alive.append(futures[future])
            except Exception:
                pass
    return alive


def scan_subnet_devices(subnet: str, local_ip: str = "") -> List[Dict]:
    """
    Run scan pipeline for a single /24-style subnet prefix (e.g., '192.168.1').
    Returns list of discovered devices with IP, MAC, vendor, and hostname.
    """
    arp_before = get_arp_table()
    alive_ips = ping_sweep(subnet)
    arp_after = get_arp_table()
    arp_results = {**arp_before, **arp_after}

    all_ips = set(list(arp_results.keys()) + alive_ips)
    if local_ip:
        all_ips.discard(local_ip)

    found: Dict[str, Dict] = {}
    for ip in all_ips:
        if not topo._valid_ip(ip):
            continue
        if not ip.startswith(subnet + "."):
            continue
        mac = arp_results.get(ip, "")
        vendor = lookup_vendor(mac) if mac else ""
        host = get_hostname(ip)
        found[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": host}

    return sorted(
        found.values(),
        key=lambda x: tuple(int(p) for p in x["ip"].split("."))
    )
