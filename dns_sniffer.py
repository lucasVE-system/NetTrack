"""
dns_sniffer.py – NetTrack passive DNS monitor.

Captures port-53 queries and logs which domains each LAN device queries.
Windows uses SOCK_RAW + SIO_RCVALL; Linux uses SOCK_RAW + IPPROTO_UDP.
Both require admin/CAP_NET_RAW; falls back silently if permission is denied.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time
from collections import deque
from typing import Dict, List, Optional, Tuple


# ── DNS category suffix map ───────────────────────────────────────────────────
# Suffix-match: a domain matches if it equals or ends with ".{suffix}".
# Deliberately small and curated; user can extend via user_categories.txt.
_DNS_CATEGORIES: Dict[str, str] = {
    # Streaming
    "youtube.com":          "Streaming",
    "googlevideo.com":      "Streaming",
    "ytimg.com":            "Streaming",
    "netflix.com":          "Streaming",
    "nflxvideo.net":        "Streaming",
    "spotify.com":          "Streaming",
    "scdn.co":              "Streaming",
    "twitch.tv":            "Streaming",
    "twitchsvc.net":        "Streaming",
    "primevideo.com":       "Streaming",
    "akamaihd.net":         "Streaming",
    "akamai.net":           "Streaming",
    "cloudfront.net":       "Streaming",
    # Ads / Tracking
    "doubleclick.net":      "Ads",
    "googlesyndication.com":"Ads",
    "googleadservices.com": "Ads",
    "adnxs.com":            "Ads",
    "adsrvr.org":           "Ads",
    "moatads.com":          "Ads",
    "taboola.com":          "Ads",
    "outbrain.com":         "Ads",
    "criteo.com":           "Ads",
    "scorecardresearch.com":"Tracking",
    "segment.io":           "Tracking",
    "mixpanel.com":         "Tracking",
    "amplitude.com":        "Tracking",
    "hotjar.com":           "Tracking",
    "graph.facebook.com":   "Tracking",
    "connect.facebook.net": "Tracking",
    "analytics.google.com": "Tracking",
    "googletagmanager.com": "Tracking",
    "googleanalytics.com":  "Tracking",
    # Social
    "facebook.com":         "Social",
    "instagram.com":        "Social",
    "twitter.com":          "Social",
    "x.com":                "Social",
    "tiktok.com":           "Social",
    "reddit.com":           "Social",
    "snapchat.com":         "Social",
    "linkedin.com":         "Social",
    "whatsapp.com":         "Social",
    "whatsapp.net":         "Social",
    # IoT / telemetry
    "tuya-us.com":          "IoT Telemetry",
    "tuya.com":             "IoT Telemetry",
    "tuyaeu.com":           "IoT Telemetry",
    "mqtt.tuya-us.com":     "IoT Telemetry",
    "home.nest.com":        "IoT Telemetry",
    "devices.nest.com":     "IoT Telemetry",
    "ring.com":             "IoT Telemetry",
    "philips.com":          "IoT Telemetry",
    "meethue.com":          "IoT Telemetry",
    "smartthings.com":      "IoT Telemetry",
    "amazonaws.com":        "Cloud",
    "azure.com":            "Cloud",
    "windows.net":          "Cloud",
    "microsoftonline.com":  "Cloud",
    # Dev / infra
    "github.com":           "Dev",
    "github.io":            "Dev",
    "githubusercontent.com":"Dev",
    "gitlab.com":           "Dev",
    "stackoverflow.com":    "Dev",
    "pypi.org":             "Dev",
    "npmjs.com":            "Dev",
    "docker.com":           "Dev",
    # Update / OS
    "windowsupdate.com":    "OS Update",
    "update.microsoft.com": "OS Update",
    "apple.com":            "OS Update",
    "icloud.com":           "OS Update",
    "gvt1.com":             "OS Update",    # Google update CDN
    # Search / Google
    "google.com":           "Search",
    "googleapis.com":       "Search",
    "gstatic.com":          "Search",
    "bing.com":             "Search",
    # CDN / infra (generic)
    "fastly.net":           "CDN",
    "cdn77.com":            "CDN",
    "edgecastcdn.net":      "CDN",
    "llnwd.net":            "CDN",
}

# Minimum number of labels a domain must have to be worth categorising.
_MIN_LABEL_COUNT = 2


def _categorise(domain: str) -> str:
    """
    Return a category string for *domain* using suffix matching.
    Tries longest suffix first so 'graph.facebook.com' beats 'facebook.com'.
    Returns '' when no match found.
    """
    domain = domain.lower().rstrip(".")
    if not domain or domain.count(".") < _MIN_LABEL_COUNT - 1:
        return ""
    parts = domain.split(".")
    # Try progressively shorter suffixes: full domain, then drop leading labels
    for i in range(len(parts) - 1):          # must keep at least "a.b"
        candidate = ".".join(parts[i:])
        if candidate in _DNS_CATEGORIES:
            return _DNS_CATEGORIES[candidate]
    return ""


def _load_user_categories(path: str) -> None:
    """
    Load user-defined domain→category overrides from a plain-text file.
    Format: one entry per line  →  domain<TAB>category
    Lines starting with # are comments.  Silently ignored on any error.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    _DNS_CATEGORIES[parts[0].strip().lower()] = parts[1].strip()
    except Exception:
        pass


# ── Minimal DNS wire-format parser ───────────────────────────────────────────

def _parse_dns_query(data: bytes) -> Optional[str]:
    """
    Parse a raw DNS query packet (UDP payload, no IP/UDP header).
    Returns the queried domain name on success, None otherwise.
    Only processes standard queries (QR=0, OPCODE=0).
    """
    try:
        if len(data) < 12:
            return None
        flags = struct.unpack("!H", data[2:4])[0]
        qr     = (flags >> 15) & 1       # 0 = query
        opcode = (flags >> 11) & 0xF     # 0 = standard query
        if qr != 0 or opcode != 0:
            return None
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return None

        # Decode the first QNAME from offset 12
        offset = 12
        labels: List[str] = []
        visited: set = set()
        while offset < len(data):
            if offset in visited:   # loop guard
                return None
            visited.add(offset)
            length = data[offset]
            if length == 0:         # root label → end
                offset += 1
                break
            if (length & 0xC0) == 0xC0:   # pointer (compression)
                if offset + 1 >= len(data):
                    return None
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                offset = ptr          # follow once; loop guard handles cycles
                continue
            offset += 1
            if offset + length > len(data):
                return None
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

        domain = ".".join(labels).lower()
        # Basic sanity: must look like a real domain
        if not domain or "." not in domain or len(domain) > 253:
            return None
        return domain
    except Exception:
        return None


# ── Entry dataclass (plain dict to keep it simple) ───────────────────────────
# Each entry: {"ts": float, "ip": str, "domain": str, "category": str}


class DNSSniffer:
    """
    Persistent background DNS sniffer.

    Usage
    -----
    sniffer = DNSSniffer(data_dir)
    sniffer.start()          # call once at app startup
    ...
    entries = sniffer.get_log()           # all recent entries
    entries = sniffer.get_log(ip="x.x.x.x")  # per-device
    sniffer.stop()           # call on shutdown; flushes to disk
    """

    RING_SIZE   = 1_000     # entries per device IP
    GLOBAL_RING = 2_000     # total entries in the global log (all devices)
    RETENTION_H = 24        # hours; older entries pruned on flush

    def __init__(self, data_dir: str):
        self._data_dir   = data_dir
        self._log_path   = os.path.join(data_dir, "dns_log.json")
        self._user_cat   = os.path.join(data_dir, "user_categories.txt")

        self._lock       = threading.Lock()
        # Per-IP deques; also a global deque for the live feed
        self._by_ip:   Dict[str, deque] = {}
        self._global:  deque            = deque(maxlen=self.GLOBAL_RING)

        self._thread:  Optional[threading.Thread] = None
        self._running  = False
        self._sock     = None
        self.available = False      # False if no raw socket permission

        _load_user_categories(self._user_cat)
        self._load_persisted()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """
        Open a raw socket and start the capture thread.
        Returns True if started successfully, False on permission error.
        Safe to call multiple times; no-op if already running.
        """
        if self._running:
            return self.available

        try:
            if sys.platform == "win32":
                self._sock = self._open_win_socket()
            else:
                self._sock = self._open_linux_socket()

            self._running  = True
            self.available = True
        except PermissionError:
            self.available = False
            return False
        except Exception:
            self.available = False
            return False

        self._thread = threading.Thread(target=self._run, daemon=True, name="dns-sniffer")
        self._thread.start()
        return True

    def _open_win_socket(self) -> socket.socket:
        """
        Windows: SOCK_RAW + IPPROTO_IP + SIO_RCVALL.
        SIO_RCVALL puts the NIC in promiscuous mode so we see both
        inbound AND outbound packets — required to capture locally
        generated DNS queries which IPPROTO_UDP misses on Windows.
        """
        # Bind to the primary local IP so Windows knows which interface.
        local_ip = self._get_local_ip()
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # SIO_RCVALL = 0x98000001
        SIO_RCVALL  = 0x98000001
        RCVALL_ON   = 1
        s.ioctl(SIO_RCVALL, RCVALL_ON)
        s.settimeout(1.0)
        return s

    def _open_linux_socket(self) -> socket.socket:
        """Linux: SOCK_RAW + IPPROTO_UDP sees all UDP traffic."""
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.settimeout(1.0)
        return s

    @staticmethod
    def _get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"

    def stop(self) -> None:
        """Stop capture thread and flush log to disk."""
        self._running = False
        if sys.platform == "win32" and self._sock:
            try:
                # Disable promiscuous mode before closing
                SIO_RCVALL  = 0x98000001
                RCVALL_OFF  = 0
                self._sock.ioctl(SIO_RCVALL, RCVALL_OFF)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        try:
            if self._sock:
                self._sock.close()
                self._sock = None
        except Exception:
            pass
        self._flush()

    # ── Capture loop ──────────────────────────────────────────────────────────

    def _run(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
                # On Windows with SIO_RCVALL, addr[0] is the src IP from
                # the IP header — but we parse the header ourselves anyway
                # so we get the correct src IP regardless of platform.
                self._parse_packet(data)
            except socket.timeout:
                continue
            except Exception:
                break
        self._running = False

    def _parse_packet(self, data: bytes) -> None:
        """
        Parse a raw IP packet (IP header + payload).
        Extracts src IP, then checks for UDP dst port 53.
        Works identically on Windows (SIO_RCVALL) and Linux (IPPROTO_UDP).
        """
        try:
            if len(data) < 20:
                return
            ihl   = (data[0] & 0x0F) * 4
            proto = data[9]
            if proto != 17:          # UDP only
                return
            # Extract source IP from IP header bytes 12-16
            src_ip = socket.inet_ntoa(data[12:16])
            udp_off = ihl
            if len(data) < udp_off + 8:
                return
            dst_port = struct.unpack("!H", data[udp_off + 2: udp_off + 4])[0]
            # Only care about DNS queries sent TO port 53
            if dst_port != 53:
                return
            payload = data[udp_off + 8:]
            domain  = _parse_dns_query(payload)
            if not domain:
                return
            self._record(src_ip, domain)
        except Exception:
            pass

    def _record(self, ip: str, domain: str) -> None:
        entry = {
            "ts":       time.time(),
            "ip":       ip,
            "domain":   domain,
            "category": _categorise(domain),
        }
        with self._lock:
            if ip not in self._by_ip:
                self._by_ip[ip] = deque(maxlen=self.RING_SIZE)
            self._by_ip[ip].append(entry)
            self._global.append(entry)

    # ── Query API ─────────────────────────────────────────────────────────────

    def get_log(self,
                ip:    Optional[str] = None,
                limit: int           = 200) -> List[Dict]:
        """
        Return recent DNS entries, newest-first.

        Parameters
        ----------
        ip    : If given, filter to only that source IP.
        limit : Max entries to return (capped at 1000).
        """
        limit = min(max(1, limit), 1_000)
        with self._lock:
            if ip:
                src = list(self._by_ip.get(ip, []))
            else:
                src = list(self._global)
        src.sort(key=lambda e: e["ts"], reverse=True)
        return src[:limit]

    def get_stats(self, ip: Optional[str] = None) -> Dict:
        """
        Return per-category query counts and top-10 domains.
        Optionally scoped to a single device IP.
        """
        entries = self.get_log(ip=ip, limit=self.RING_SIZE)
        cats:    Dict[str, int] = {}
        domains: Dict[str, int] = {}
        for e in entries:
            cat = e.get("category") or "Other"
            cats[cat]    = cats.get(cat, 0)    + 1
            d = e.get("domain", "")
            domains[d]   = domains.get(d, 0)   + 1

        top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "total":       len(entries),
            "by_category": cats,
            "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
        }

    def clear(self, ip: Optional[str] = None) -> None:
        """Clear log for one IP or all IPs."""
        with self._lock:
            if ip:
                self._by_ip.pop(ip, None)
                remaining = [e for e in self._global if e["ip"] != ip]
                self._global.clear()
                self._global.extend(remaining)
            else:
                self._by_ip.clear()
                self._global.clear()
        self._flush()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _flush(self) -> None:
        """
        Write all buffered entries to dns_log.json, pruning entries older
        than RETENTION_H hours.  Uses atomic write (tmp + os.replace).
        """
        cutoff = time.time() - self.RETENTION_H * 3600
        with self._lock:
            entries = [e for e in self._global if e["ts"] >= cutoff]

        tmp = self._log_path + ".tmp"
        try:
            os.makedirs(self._data_dir, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(entries, f)
            os.replace(tmp, self._log_path)
        except Exception:
            try:
                os.remove(tmp)
            except Exception:
                pass

    def _load_persisted(self) -> None:
        """
        Restore a previous session's log from disk on startup.
        Entries older than RETENTION_H are silently dropped.
        """
        if not os.path.exists(self._log_path):
            return
        cutoff = time.time() - self.RETENTION_H * 3600
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                entries: List[Dict] = json.load(f)
            if not isinstance(entries, list):
                return
            with self._lock:
                for e in entries:
                    if not isinstance(e, dict):
                        continue
                    if e.get("ts", 0) < cutoff:
                        continue
                    ip = e.get("ip", "")
                    if ip:
                        if ip not in self._by_ip:
                            self._by_ip[ip] = deque(maxlen=self.RING_SIZE)
                        self._by_ip[ip].append(e)
                    self._global.append(e)
        except Exception:
            pass
