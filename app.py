r"""
app.py  –  NetTrack Flask backend
==================================
Serves the web UI and all API endpoints.

Security notes
--------------
* Flask is bound to 127.0.0.1 only – not reachable from the network.
* SNMP community strings are stored server-side only; they are accepted from
  the frontend (user configured them) but NEVER echoed back in any response.
* All subprocess calls inside topology.py use list args + timeouts.
* Input validation happens at every endpoint before touching the filesystem
  or calling topology functions.
* devices.json and topology.json live in %APPDATA%\NetTrack when frozen
  (installed), or next to the script when running from source.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request
from version import VERSION, GITHUB_REPO

import topology as topo

app = Flask(__name__)

# ── BASE DIR ──────────────────────────────────────────────────────────────────
def get_base_dir() -> str:
    if getattr(sys, 'frozen', False):
       #r When installed (e.g. in Program Files), write data to %APPDATA%\NetTrack
        # so we never need write access to the install directory.
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
        data_dir = os.path.join(appdata, "NetTrack")
        os.makedirs(data_dir, exist_ok=True)
        return data_dir
    return os.path.dirname(os.path.abspath(__file__))

def get_data_file() -> str:
    return os.path.join(get_base_dir(), "devices.json")

def get_topology_file() -> str:
    return os.path.join(get_base_dir(), "topology.json")

def get_snmp_config_file() -> str:
    # Stored separately so it's easy to exclude from version control
    return os.path.join(get_base_dir(), "snmp_config.json")

# ── MAC VENDOR LOOKUP ─────────────────────────────────────────────────────────
_mac_lookup = None
def get_mac_lookup():
    global _mac_lookup
    if _mac_lookup is None:
        try:
            from mac_vendor_lookup import MacLookup
            _mac_lookup = MacLookup()
        except Exception:
            _mac_lookup = False
    return _mac_lookup if _mac_lookup else None

# ── DEVICE STORE ──────────────────────────────────────────────────────────────
def load_devices() -> List[Dict]:
    path = get_data_file()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_devices(devices: List[Dict]):
    with open(get_data_file(), "w") as f:
        json.dump(devices, f, indent=2)

def find_device_index(devices, mac=None, ip=None) -> int:
    if mac:
        for i, d in enumerate(devices):
            if d.get("mac") == mac:
                return i
    if ip:
        for i, d in enumerate(devices):
            if d.get("ip") == ip:
                return i
    return -1

# ── TOPOLOGY STORE ────────────────────────────────────────────────────────────
def load_topology() -> Dict:
    path = get_topology_file()
    if not os.path.exists(path):
        return {"nodes": [], "edges": [], "meta": {}}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {"nodes": [], "edges": [], "meta": {}}

def save_topology(data: Dict):
    with open(get_topology_file(), "w") as f:
        json.dump(data, f, indent=2)

# ── SNMP CONFIG STORE ─────────────────────────────────────────────────────────
# {ip: {community: str, port: int}}  –  never returned to frontend
_snmp_config: Dict[str, Dict] = {}
_snmp_config_lock = threading.Lock()

def load_snmp_config():
    global _snmp_config
    path = get_snmp_config_file()
    if not os.path.exists(path):
        return
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            with _snmp_config_lock:
                _snmp_config = data
    except Exception:
        pass

def save_snmp_config():
    with _snmp_config_lock:
        data = dict(_snmp_config)
    with open(get_snmp_config_file(), "w") as f:
        json.dump(data, f, indent=2)

def get_snmp_for_ip(ip: str) -> Optional[Dict]:
    with _snmp_config_lock:
        # Exact match first, then wildcard
        entry = _snmp_config.get(ip) or _snmp_config.get("*")
    return entry

# ── NETWORK HELPERS ───────────────────────────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"

def get_subnet(local_ip: str) -> str:
    return ".".join(local_ip.split(".")[:3])

def ping_host(ip: str) -> bool:
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
                ip  = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                if (not ip.endswith(".255")
                        and not ip.startswith("224.")
                        and not ip.startswith("239.")
                        and mac != "FF:FF:FF:FF:FF:FF"):
                    discovered[ip] = mac
    except Exception as e:
        print(f"ARP error: {e}")
    return discovered

def lookup_vendor(mac: str) -> str:
    try:
        ml = get_mac_lookup()
        if ml:
            return ml.lookup(mac)
    except Exception:
        pass
    return ""

def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def ping_sweep(subnet: str) -> List[str]:
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

# ── BACKGROUND TOPOLOGY JOB ───────────────────────────────────────────────────
_topo_state: Dict = {
    "status":   "idle",   # idle | running | done | error
    "progress": 0,
    "phase":    "",
    "error":    "",
    "warnings": [],
}
_topo_lock = threading.Lock()
_TOPO_WARNINGS_MAX = 32

def _update_topo_state(**kwargs):
    with _topo_lock:
        _topo_state.update(kwargs)

def _append_topo_warning(msg: str):
    """Append a short non-fatal warning for the UI (bounded list)."""
    text = (msg or "")[:400]
    if not text:
        return
    with _topo_lock:
        w = _topo_state.setdefault("warnings", [])
        if len(w) < _TOPO_WARNINGS_MAX:
            w.append(text)

def run_topology_discovery(scan_devices: List[Dict],
                            local_ip: str,
                            run_traceroute: bool = True,
                            run_snmp:       bool = True,
                            run_passive:    bool = True,
                            run_mdns:       bool = True,
                            run_ssdp:       bool = True,
                            run_netbios:    bool = True,
                            run_banners:    bool = True):
    """
    Full multi-phase topology discovery. Runs in a background thread.
    Results are saved to topology.json and merged into devices.json.
    """
    try:
        _run_topology_discovery_impl(
            scan_devices, local_ip,
            run_traceroute, run_snmp, run_passive,
            run_mdns, run_ssdp, run_netbios, run_banners,
        )
    except Exception as e:
        _update_topo_state(status="error", error=str(e), phase="")


def _run_topology_discovery_impl(scan_devices: List[Dict],
                                  local_ip: str,
                                  run_traceroute: bool,
                                  run_snmp: bool,
                                  run_passive: bool,
                                  run_mdns: bool,
                                  run_ssdp: bool,
                                  run_netbios: bool,
                                  run_banners: bool):
    _update_topo_state(status="running", progress=0, phase="init", error="", warnings=[])

    ips = [d["ip"] for d in scan_devices if d.get("ip") and topo._valid_ip(d["ip"])]

    # ── Phase 1: Traceroute ───────────────────────────────────────────────────
    traceroute_data = None
    if run_traceroute:
        _update_topo_state(progress=5, phase="traceroute")
        try:
            traceroute_data = topo.build_l3_topology(ips, local_ip)
        except Exception as e:
            _append_topo_warning(f"Traceroute: {e}")

    _update_topo_state(progress=20)

    # ── Phase 2: SNMP ─────────────────────────────────────────────────────────
    snmp_results: Dict[str, Dict] = {}
    if run_snmp:
        _update_topo_state(phase="snmp")
        snmp_err_count = 0
        for ip in ips:
            cfg = get_snmp_for_ip(ip)
            if not cfg:
                continue
            community = cfg.get("community", "public")
            port      = int(cfg.get("port", 161))
            try:
                result = topo.snmp_full_discovery(ip, community, port=port)
                snmp_results[ip] = result
            except Exception as e:
                if snmp_err_count < 8:
                    _append_topo_warning(f"SNMP {ip}: {e}")
                    snmp_err_count += 1
        _update_topo_state(progress=40)

    # ── Phase 3: Passive sniffing (LLDP + DHCP) ──────────────────────────────
    lldp_frames: List[Dict] = []
    dhcp_data:   Dict[str, Dict] = {}
    if run_passive:
        _update_topo_state(phase="passive_sniff")
        lldp_sniffer = topo._LLDPSniffer()
        dhcp_sniffer = topo._DHCPSniffer()
        lldp_sniffer.start(duration=15)
        dhcp_sniffer.start(duration=15)
        time.sleep(16)
        lldp_sniffer.stop()
        dhcp_sniffer.stop()
        lldp_frames = lldp_sniffer.results()
        dhcp_data   = dhcp_sniffer.results()
    _update_topo_state(progress=60)

    # ── Enrichment: mDNS ─────────────────────────────────────────────────────
    mdns_data: Dict[str, Dict] = {}
    if run_mdns:
        _update_topo_state(phase="mdns")
        listener = topo._MDNSListener()
        listener.start(duration=5)
        time.sleep(6)
        listener.stop()
        mdns_data = listener.results()
    _update_topo_state(progress=70)

    # ── Enrichment: SSDP ─────────────────────────────────────────────────────
    ssdp_data: List[Dict] = []
    if run_ssdp:
        _update_topo_state(phase="ssdp")
        try:
            raw_ssdp = topo.ssdp_discover(timeout=3)
            # Optionally fetch UPnP descriptions for local-only IPs
            for entry in raw_ssdp:
                loc = entry.get("location_url", "")
                if loc:
                    desc = topo.ssdp_fetch_description(loc, timeout=2)
                    entry.update(desc)
            ssdp_data = raw_ssdp
        except Exception as e:
            _append_topo_warning(f"SSDP: {e}")
    _update_topo_state(progress=80)

    # ── Enrichment: NetBIOS ───────────────────────────────────────────────────
    netbios_results: Dict[str, str] = {}
    if run_netbios:
        _update_topo_state(phase="netbios")
        def _nb(ip):
            name = topo.netbios_query(ip)
            if name:
                netbios_results[ip] = name
        with ThreadPoolExecutor(max_workers=20) as ex:
            list(as_completed([ex.submit(_nb, ip) for ip in ips]))
        # Merge hostnames
        for ip, name in netbios_results.items():
            for dev in scan_devices:
                if dev.get("ip") == ip and not dev.get("hostname"):
                    dev["hostname"] = name
    _update_topo_state(progress=88)

    # ── Enrichment: Banner grabbing ───────────────────────────────────────────
    fingerprint_data: Dict[str, Dict] = {}
    if run_banners:
        _update_topo_state(phase="fingerprint")
        def _fp(ip):
            fingerprint_data[ip] = topo.fingerprint_device(ip, max_workers=4)
        with ThreadPoolExecutor(max_workers=10) as ex:
            list(as_completed([ex.submit(_fp, ip) for ip in ips]))
    _update_topo_state(progress=95)

    # ── Build unified graph ───────────────────────────────────────────────────
    _update_topo_state(phase="build_graph")
    graph = topo.build_topology_graph(
        scan_devices      = scan_devices,
        traceroute_data   = traceroute_data,
        snmp_results      = snmp_results,
        lldp_frames       = lldp_frames,
        mdns_data         = mdns_data,
        ssdp_data         = ssdp_data,
        dhcp_data         = dhcp_data,
        fingerprint_data  = fingerprint_data,
    )

    # ── Persist ───────────────────────────────────────────────────────────────
    save_topology(graph)

    # Merge enriched data back into devices.json
    devices    = load_devices()
    node_by_ip = {n["ip"]: n for n in graph["nodes"] if n.get("ip")}
    for dev in devices:
        ip = dev.get("ip", "")
        if ip in node_by_ip:
            node = node_by_ip[ip]
            # Only update auto-inferred fields; don't overwrite user edits
            for field in ("hostname", "vendor", "mdns_services",
                           "ssdp_server", "opt55_os", "open_ports"):
                if node.get(field) and not dev.get(field):
                    dev[field] = node[field]
            if dev.get("type", "other") == "other" and node.get("type", "other") != "other":
                dev["type"] = node["type"]
    save_devices(devices)

    _update_topo_state(status="done", progress=100, phase="")

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/devices")
def get_devices():
    return jsonify(load_devices())

@app.route("/topology")
def get_topology():
    return jsonify(load_topology())

@app.route("/topology-status")
def topology_status():
    with _topo_lock:
        return jsonify(dict(_topo_state))

@app.route("/run-topology", methods=["POST"])
def trigger_topology():
    """
    Kick off background topology discovery.
    Body: { options: { traceroute, snmp, passive, mdns, ssdp, netbios, banners } }
    """
    with _topo_lock:
        if _topo_state["status"] == "running":
            return jsonify({"ok": False, "error": "Already running"}), 409

    data    = request.get_json() or {}
    options = data.get("options", {})

    devices = load_devices()
    local_ip = get_local_ip()

    t = threading.Thread(
        target=run_topology_discovery,
        kwargs={
            "scan_devices":   devices,
            "local_ip":       local_ip,
            "run_traceroute": bool(options.get("traceroute", True)),
            "run_snmp":       bool(options.get("snmp", True)),
            "run_passive":    bool(options.get("passive", True)),
            "run_mdns":       bool(options.get("mdns", True)),
            "run_ssdp":       bool(options.get("ssdp", True)),
            "run_netbios":    bool(options.get("netbios", True)),
            "run_banners":    bool(options.get("banners", True)),
        },
        daemon=True
    )
    t.start()
    return jsonify({"ok": True})

# ── SNMP CONFIG ───────────────────────────────────────────────────────────────
@app.route("/snmp-config", methods=["GET"])
def snmp_config_get():
    """
    Return SNMP config without community strings.
    Frontend only sees which IPs have SNMP configured.
    """
    with _snmp_config_lock:
        safe = {ip: {"port": cfg.get("port", 161), "has_community": True}
                for ip, cfg in _snmp_config.items()}
    return jsonify(safe)

@app.route("/snmp-config", methods=["POST"])
def snmp_config_set():
    """
    Add/update an SNMP entry. Accepts {ip, community, port}.
    ip can be "*" for a wildcard (all devices).
    Community string is stored server-side only, never returned.
    """
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()
    community = data.get("community", "").strip()
    port = int(data.get("port", 161))

    if ip != "*" and not topo._valid_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP"}), 400
    if not community:
        return jsonify({"ok": False, "error": "Community string required"}), 400
    if not (1 <= port <= 65535):
        return jsonify({"ok": False, "error": "Invalid port"}), 400

    with _snmp_config_lock:
        _snmp_config[ip] = {"community": community, "port": port}
    save_snmp_config()
    return jsonify({"ok": True})

@app.route("/snmp-config", methods=["DELETE"])
def snmp_config_delete():
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()
    if ip != "*" and not topo._valid_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP"}), 400
    with _snmp_config_lock:
        _snmp_config.pop(ip, None)
    save_snmp_config()
    return jsonify({"ok": True})

# ── SCAN ──────────────────────────────────────────────────────────────────────
@app.route("/scan")
def scan():
    local_ip   = get_local_ip()
    subnet     = get_subnet(local_ip)
    arp_before = get_arp_table()
    alive_ips  = ping_sweep(subnet)
    arp_after  = get_arp_table()
    arp_results = {**arp_before, **arp_after}

    all_ips = set(list(arp_results.keys()) + alive_ips)
    all_ips.discard(local_ip)

    found: Dict[str, Dict] = {}
    for ip in all_ips:
        if not topo._valid_ip(ip):
            continue
        mac    = arp_results.get(ip, "")
        vendor = lookup_vendor(mac) if mac else ""
        host   = get_hostname(ip)
        found[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": host}

    sorted_results = sorted(
        found.values(),
        key=lambda x: tuple(int(p) for p in x["ip"].split("."))
    )
    return jsonify({
        "subnet":   subnet,
        "local_ip": local_ip,
        "count":    len(sorted_results),
        "devices":  sorted_results
    })

# ── DEVICE CRUD ───────────────────────────────────────────────────────────────
@app.route("/save", methods=["POST"])
def save_one():
    data   = request.get_json()
    device = data.get("device")
    mac    = data.get("mac")
    if not device:
        return jsonify({"ok": False, "error": "No device provided"}), 400
    ip = device.get("ip", "")
    if ip and not topo._valid_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP"}), 400
    devices = load_devices()
    idx     = find_device_index(devices, mac=mac, ip=ip or None)
    if idx >= 0:
        devices[idx] = device
    else:
        devices.append(device)
    save_devices(devices)
    return jsonify({"ok": True})

@app.route("/save-all", methods=["POST"])
def save_all():
    devices = request.get_json()
    if not isinstance(devices, list):
        return jsonify({"ok": False, "error": "Expected a list"}), 400
    save_devices(devices)
    return jsonify({"ok": True})

@app.route("/delete-device", methods=["POST"])
def delete_device():
    data    = request.get_json()
    mac     = data.get("mac")
    ip      = data.get("ip")
    devices = load_devices()
    idx     = find_device_index(devices, mac=mac, ip=ip)
    if idx >= 0:
        devices.pop(idx)
        save_devices(devices)
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Device not found"}), 404

# ── VERSION + AUTO-UPDATE ─────────────────────────────────────────────────────
def parse_version(v: str):
    v = v.lstrip("v")
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0, 0, 0)

def fetch_latest_release():
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        req = urllib.request.Request(
            url, headers={"User-Agent": "NetTrack-updater"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None

_update_state: Dict = {"status": "idle", "progress": 0, "error": ""}
_latest_exe_url: Optional[str] = None
_update_token = secrets.token_urlsafe(24)

ALLOWED_UPDATE_HOSTS = {"github.com", "objects.githubusercontent.com"}
ALLOWED_GITHUB_PATH_PREFIX = f"/{GITHUB_REPO}/releases/download/"

def is_allowed_update_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        if parsed.hostname not in ALLOWED_UPDATE_HOSTS:
            return False
        if parsed.hostname == "github.com" and \
           not parsed.path.startswith(ALLOWED_GITHUB_PATH_PREFIX):
            return False
        return True
    except Exception:
        return False

@app.route("/version")
def get_version():
    return jsonify({"version": VERSION})

@app.route("/check-update")
def check_update():
    global _latest_exe_url
    release = fetch_latest_release()
    if not release:
        return jsonify({"update": False, "error": "Could not reach GitHub"})
    latest_tag  = release.get("tag_name", "")
    latest_ver  = parse_version(latest_tag)
    current_ver = parse_version(VERSION)
    if latest_ver <= current_ver:
        return jsonify({"update": False, "current": VERSION, "latest": latest_tag})
    exe_url = None
    for asset in release.get("assets", []):
        if asset["name"].lower().endswith(".exe"):
            exe_url = asset["browser_download_url"]
            break
    if exe_url and not is_allowed_update_url(exe_url):
        exe_url = None
    _latest_exe_url = exe_url
    return jsonify({
        "update":       True,
        "current":      VERSION,
        "latest":       latest_tag,
        "exe_url":      exe_url,
        "update_token": _update_token,
        "notes":        release.get("body", "")
    })

@app.route("/update-progress")
def update_progress():
    return jsonify(_update_state)

@app.route("/do-update", methods=["POST"])
def do_update():
    data    = request.get_json() or {}
    exe_url = data.get("exe_url")
    token   = data.get("update_token")
    if token != _update_token:
        return jsonify({"ok": False, "error": "Invalid update token"}), 403
    if not exe_url:
        return jsonify({"ok": False, "error": "No download URL"}), 400
    if exe_url != _latest_exe_url:
        return jsonify({"ok": False, "error": "Mismatched update URL"}), 400
    if not is_allowed_update_url(exe_url):
        return jsonify({"ok": False, "error": "Blocked update URL"}), 400

    def run_update():
        global _update_state
        _update_state = {"status": "downloading", "progress": 0, "error": ""}
        tmp = bak = ""
        try:
            base    = get_base_dir()
            current = sys.executable if getattr(sys, 'frozen', False) \
                      else os.path.join(base, "NetTrack.exe")
            tmp = current + ".new"
            bak = current + ".bak"
            req = urllib.request.Request(
                exe_url, headers={"User-Agent": "NetTrack-updater"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                total      = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                with open(tmp, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            _update_state["progress"] = int(downloaded / total * 100)
            _update_state["progress"] = 100
            _update_state["status"]   = "replacing"
            if os.path.exists(bak):
                os.remove(bak)
            if os.path.exists(current):
                os.rename(current, bak)
            os.rename(tmp, current)
            _update_state["status"] = "restarting"
            def restart():
                time.sleep(1.5)
                if sys.platform == "win32":
                    subprocess.Popen([current],
                                     creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen([current])
                os._exit(0)
            threading.Thread(target=restart, daemon=True).start()
        except Exception as e:
            _update_state["status"] = "error"
            _update_state["error"]  = str(e)
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass

    threading.Thread(target=run_update, daemon=True).start()
    return jsonify({"ok": True})

# ── STARTUP ───────────────────────────────────────────────────────────────────
load_snmp_config()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
