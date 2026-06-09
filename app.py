"""app.py – NetTrack Flask backend. Serves the UI and all API endpoints."""

from __future__ import annotations

import functools
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urlparse
from dns_sniffer import DNSSniffer

from flask import Flask, jsonify, render_template, request
from version import VERSION, GITHUB_REPO

import signing
import topology as topo
from scanner import (
    get_local_ip,
    get_subnet,
    scan_subnet_devices,
)

app = Flask(__name__)

def api_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status

# ── SIMPLE RATE LIMIT ─────────────────────────────────────────────────────────
# The app is localhost-only, so this is a guard against runaway clients
# hammering expensive scan endpoints, not against hostile traffic.
_rate_lock = threading.Lock()
_rate_last: Dict[str, float] = {}

def rate_limited(min_interval_s: float):
    """Reject calls to the wrapped endpoint within min_interval_s of the last one."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if app.config.get("TESTING"):
                return fn(*args, **kwargs)
            now = time.monotonic()
            with _rate_lock:
                last = _rate_last.get(fn.__name__, 0.0)
                if now - last < min_interval_s:
                    return api_error("Too many requests; try again shortly", 429)
                _rate_last[fn.__name__] = now
            return fn(*args, **kwargs)
        return wrapper
    return decorator

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
# {ip: {version, community, user, auth_key, priv_key, port}} – never returned
# to the frontend.
_snmp_config: Dict[str, Dict] = {}
_snmp_config_lock = threading.Lock()

_SNMP_VERSIONS = {"v2c", "v3"}
_SNMP_V3_PROTOS = {"auth_proto": {"sha", "md5"}, "priv_proto": {"aes", "des"}}

def _valid_snmp_entry(ip: str, entry) -> bool:
    """Schema check for one snmp_config.json entry; invalid entries are dropped."""
    if not isinstance(entry, dict):
        return False
    if ip != "*" and not topo._valid_ip(ip):
        return False
    port = entry.get("port", 161)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return False
    version = entry.get("version", "v2c")
    if version not in _SNMP_VERSIONS:
        return False
    for field, allowed in _SNMP_V3_PROTOS.items():
        if entry.get(field) and entry[field] not in allowed:
            return False
    if version == "v3":
        return bool(entry.get("user"))
    return bool(entry.get("community"))

def load_snmp_config():
    global _snmp_config
    path = get_snmp_config_file()
    if not os.path.exists(path):
        return
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            valid = {ip: cfg for ip, cfg in data.items()
                     if _valid_snmp_entry(ip, cfg)}
            with _snmp_config_lock:
                _snmp_config = valid
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

# ── BACKGROUND TOPOLOGY JOB ───────────────────────────────────────────────────
_topo_state: Dict = {
    "status":   "idle",   # idle | running | done | error
    "progress": 0,
    "phase":    "",
    "error":    "",
    "warnings": [],
    "started_at_ms": 0,
    "phase_started_at_ms": 0,
    "phase_timings_ms": {},
    "devices_scanned": 0,
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

def _mark_topo_phase(new_phase: str):
    now = int(time.time() * 1000)
    with _topo_lock:
        old_phase = _topo_state.get("phase")
        old_start = _topo_state.get("phase_started_at_ms", 0)
        timings = dict(_topo_state.get("phase_timings_ms", {}))
        if old_phase and old_start:
            timings[old_phase] = timings.get(old_phase, 0) + max(0, now - old_start)
        _topo_state["phase"] = new_phase
        _topo_state["phase_started_at_ms"] = now
        _topo_state["phase_timings_ms"] = timings

def run_topology_discovery(scan_devices: List[Dict],
                            local_ip: str,
                            run_traceroute: bool = True,
                            run_snmp:       bool = True,
                            run_passive:    bool = True,
                            run_mdns:       bool = True,
                            run_ssdp:       bool = True,
                            run_netbios:    bool = True,
                            run_banners:    bool = True):
    try:
        _run_discovery(
            scan_devices, local_ip,
            run_traceroute, run_snmp, run_passive,
            run_mdns, run_ssdp, run_netbios, run_banners,
        )
    except Exception as e:
        _update_topo_state(status="error", error=str(e), phase="")


def _run_discovery(scan_devices, local_ip,
                   run_traceroute, run_snmp, run_passive,
                   run_mdns, run_ssdp, run_netbios, run_banners):
    now_ms = int(time.time() * 1000)
    _update_topo_state(
        status="running",
        progress=0,
        phase="init",
        error="",
        warnings=[],
        started_at_ms=now_ms,
        phase_started_at_ms=now_ms,
        phase_timings_ms={},
        devices_scanned=len(scan_devices),
    )

    ips = [d["ip"] for d in scan_devices if d.get("ip") and topo._valid_ip(d["ip"])]

    # ── Phase 1: Traceroute ───────────────────────────────────────────────────
    traceroute_data = None
    if run_traceroute:
        _update_topo_state(progress=5)
        _mark_topo_phase("traceroute")
        try:
            traceroute_data = topo.build_l3_topology(ips, local_ip)
        except Exception as e:
            _append_topo_warning(f"Traceroute: {e}")

    _update_topo_state(progress=20)

    # ── Phase 2: SNMP ─────────────────────────────────────────────────────────
    snmp_results: Dict[str, Dict] = {}
    if run_snmp:
        _mark_topo_phase("snmp")
        snmp_err_count = 0
        for ip in ips:
            cfg = get_snmp_for_ip(ip)
            if not cfg:
                continue
            port = int(cfg.get("port", 161))
            try:
                # cfg is a credential dict (v2c or v3); see topo._snmp_auth_data
                result = topo.snmp_full_discovery(ip, cfg, port=port)
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
        _mark_topo_phase("passive_sniff")
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
        _mark_topo_phase("mdns")
        listener = topo._MDNSListener()
        listener.start(duration=5)
        time.sleep(6)
        listener.stop()
        mdns_data = listener.results()
    _update_topo_state(progress=70)

    # ── Enrichment: SSDP ─────────────────────────────────────────────────────
    ssdp_data: List[Dict] = []
    if run_ssdp:
        _mark_topo_phase("ssdp")
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
        _mark_topo_phase("netbios")
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
        _mark_topo_phase("fingerprint")
        def _fp(ip):
            fingerprint_data[ip] = topo.fingerprint_device(ip, max_workers=4)
        with ThreadPoolExecutor(max_workers=10) as ex:
            list(as_completed([ex.submit(_fp, ip) for ip in ips]))
    _update_topo_state(progress=95)

    # ── Build unified graph ───────────────────────────────────────────────────
    _mark_topo_phase("build_graph")
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

    _mark_topo_phase("")
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
        state = dict(_topo_state)
    now = int(time.time() * 1000)
    started = state.get("started_at_ms", 0)
    phase_started = state.get("phase_started_at_ms", 0)
    state["elapsed_ms"] = max(0, now - started) if started else 0
    state["current_phase_elapsed_ms"] = max(0, now - phase_started) if phase_started else 0
    return jsonify(state)

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
        safe = {ip: {"port": cfg.get("port", 161),
                     "version": cfg.get("version", "v2c"),
                     "has_community": True}
                for ip, cfg in _snmp_config.items()}
    return jsonify(safe)

@app.route("/snmp-config", methods=["POST"])
def snmp_config_set():
    """
    Add/update an SNMP entry.
    v2c: {ip, community, port}
    v3:  {ip, version: "v3", user, auth_key?, auth_proto? (sha|md5),
          priv_key?, priv_proto? (aes|des), port}
    ip can be "*" for a wildcard (all devices).
    Credentials are stored server-side only, never returned.
    """
    data = request.get_json(silent=True) or {}
    ip      = data.get("ip", "").strip()
    version = (data.get("version") or "v2c").strip().lower()
    try:
        port = int(data.get("port", 161))
    except (TypeError, ValueError):
        return api_error("Invalid port", 400)

    if ip != "*" and not topo._valid_ip(ip):
        return api_error("Invalid IP", 400)
    if not (1 <= port <= 65535):
        return api_error("Invalid port", 400)
    if version not in _SNMP_VERSIONS:
        return api_error("version must be v2c or v3", 400)

    if version == "v3":
        user = (data.get("user") or "").strip()
        if not user:
            return api_error("SNMPv3 requires a user", 400)
        entry = {"version": "v3", "user": user, "port": port}
        for key in ("auth_key", "priv_key"):
            val = (data.get(key) or "").strip()
            if val:
                entry[key] = val
        for key, allowed in _SNMP_V3_PROTOS.items():
            val = (data.get(key) or "").strip().lower()
            if val:
                if val not in allowed:
                    return api_error(f"{key} must be one of {sorted(allowed)}", 400)
                entry[key] = val
    else:
        community = (data.get("community") or "").strip()
        if not community:
            return api_error("Community string required", 400)
        entry = {"version": "v2c", "community": community, "port": port}

    with _snmp_config_lock:
        _snmp_config[ip] = entry
    save_snmp_config()
    return jsonify({"ok": True})

@app.route("/snmp-config", methods=["DELETE"])
def snmp_config_delete():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    if ip != "*" and not topo._valid_ip(ip):
        return api_error("Invalid IP", 400)
    with _snmp_config_lock:
        _snmp_config.pop(ip, None)
    save_snmp_config()
    return jsonify({"ok": True})

# ── DNS MONITOR ───────────────────────────────────────────────────────────────

@app.route("/dns-start", methods=["POST"])
def dns_start():
    if _dns_sniffer._running:
        return jsonify({"ok": True, "available": True, "already_running": True})
    ok = _dns_sniffer.start()
    return jsonify({"ok": ok, "available": ok, "already_running": False})

@app.route("/dns-stop", methods=["POST"])
def dns_stop():
    _dns_sniffer.stop()
    return jsonify({"ok": True})

@app.route("/dns-log")
def dns_log():
    ip_filter = request.args.get("ip", "").strip() or None
    if ip_filter and not topo._valid_ip(ip_filter):
        return api_error("Invalid IP", 400)
    try:
        limit = int(request.args.get("limit", 200))
    except (TypeError, ValueError):
        return api_error("limit must be an integer", 400)
    entries = _dns_sniffer.get_log(ip=ip_filter, limit=limit)
    return jsonify({
        "running":   _dns_sniffer._running,
        "available": _dns_sniffer.available,
        "entries":   entries,
    })

@app.route("/dns-stats")
def dns_stats():
    ip_filter = request.args.get("ip", "").strip() or None
    if ip_filter and not topo._valid_ip(ip_filter):
        return api_error("Invalid IP", 400)
    stats = _dns_sniffer.get_stats(ip=ip_filter)
    stats["running"]   = _dns_sniffer._running
    stats["available"] = _dns_sniffer.available
    return jsonify(stats)

@app.route("/dns-clear", methods=["POST"])
def dns_clear():
    data      = request.get_json(silent=True) or {}
    ip_filter = data.get("ip", "").strip() or None
    if ip_filter and not topo._valid_ip(ip_filter):
        return api_error("Invalid IP", 400)
    _dns_sniffer.clear(ip=ip_filter)
    return jsonify({"ok": True})

# ── SCAN ──────────────────────────────────────────────────────────────────────
@app.route("/scan")
@rate_limited(5.0)
def scan():
    local_ip   = get_local_ip()
    subnet     = get_subnet(local_ip)
    sorted_results = scan_subnet_devices(subnet, local_ip=local_ip)
    return jsonify({
        "subnet":   subnet,
        "local_ip": local_ip,
        "count":    len(sorted_results),
        "devices":  sorted_results
    })

@app.route("/scan-multi", methods=["POST"])
@rate_limited(5.0)
def scan_multi():
    data = request.get_json(silent=True) or {}
    raw_subnets = data.get("subnets")
    if not isinstance(raw_subnets, list) or not raw_subnets:
        return api_error("subnets must be a non-empty list", 400)

    seen = set()
    subnets: List[str] = []
    for raw in raw_subnets:
        if not isinstance(raw, str):
            return api_error("Each subnet must be a string", 400)
        subnet = raw.strip()
        if not subnet:
            return api_error("Subnet values cannot be empty", 400)
        if subnet in seen:
            continue
        seen.add(subnet)
        subnets.append(subnet)

    local_ip = get_local_ip()
    merged_by_ip: Dict[str, Dict] = {}
    merged_by_mac: Dict[str, Dict] = {}
    subnet_results: List[Dict] = []

    for subnet in subnets:
        result = {"subnet": subnet, "count": 0, "errors": []}
        if not topo._safe_subnet(subnet):
            result["errors"].append("Invalid subnet format; expected a.b.c")
            subnet_results.append(result)
            continue
        try:
            devices = scan_subnet_devices(subnet, local_ip=local_ip if subnet == get_subnet(local_ip) else "")
            result["count"] = len(devices)
            for dev in devices:
                mac = (dev.get("mac") or "").strip().upper()
                ip = (dev.get("ip") or "").strip()
                if mac:
                    if mac in merged_by_mac:
                        existing = merged_by_mac[mac]
                        if not existing.get("hostname") and dev.get("hostname"):
                            existing["hostname"] = dev["hostname"]
                        if not existing.get("vendor") and dev.get("vendor"):
                            existing["vendor"] = dev["vendor"]
                        if not existing.get("ip") and ip:
                            existing["ip"] = ip
                    else:
                        merged_by_mac[mac] = dict(dev)
                elif ip:
                    if ip in merged_by_ip:
                        existing = merged_by_ip[ip]
                        if not existing.get("hostname") and dev.get("hostname"):
                            existing["hostname"] = dev["hostname"]
                        if not existing.get("vendor") and dev.get("vendor"):
                            existing["vendor"] = dev["vendor"]
                    else:
                        merged_by_ip[ip] = dict(dev)
        except Exception as e:
            result["errors"].append(str(e))
        subnet_results.append(result)

    for dev in merged_by_mac.values():
        ip = (dev.get("ip") or "").strip()
        if ip and ip in merged_by_ip:
            merged_by_ip.pop(ip, None)

    merged_devices = list(merged_by_mac.values()) + list(merged_by_ip.values())
    merged_devices = sorted(
        merged_devices,
        key=lambda x: tuple(int(p) for p in x.get("ip", "999.999.999.999").split(".")) if topo._valid_ip(x.get("ip", "")) else (999, 999, 999, 999)
    )

    return jsonify({
        "subnets_requested": subnets,
        "subnet_results": subnet_results,
        "count": len(merged_devices),
        "devices": merged_devices,
        "local_ip": local_ip,
    })

# ── DEVICE CRUD ───────────────────────────────────────────────────────────────
@app.route("/save", methods=["POST"])
def save_one():
    data   = request.get_json(silent=True) or {}
    device = data.get("device")
    mac    = data.get("mac")
    if not isinstance(device, dict):
        return api_error("No device provided", 400)
    ip = device.get("ip", "")
    if ip and not topo._valid_ip(ip):
        return api_error("Invalid IP", 400)
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
    devices = request.get_json(silent=True)
    if not isinstance(devices, list):
        return api_error("Expected a list", 400)
    for item in devices:
        if not isinstance(item, dict):
            return api_error("Each device must be an object", 400)
        ip = item.get("ip", "")
        if ip and not topo._valid_ip(ip):
            return api_error("Invalid IP in device list", 400)
    save_devices(devices)
    return jsonify({"ok": True})

@app.route("/delete-device", methods=["POST"])
def delete_device():
    data    = request.get_json(silent=True) or {}
    mac     = data.get("mac")
    ip      = data.get("ip")
    if not mac and not ip:
        return api_error("Provide mac or ip", 400)
    devices = load_devices()
    idx     = find_device_index(devices, mac=mac, ip=ip)
    if idx >= 0:
        devices.pop(idx)
        save_devices(devices)
        return jsonify({"ok": True})
    return api_error("Device not found", 404)

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
_latest_sha_url: Optional[str] = None
_latest_sig_url: Optional[str] = None
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
    exe_url = sha_url = None
    exe_name = ""
    for asset in release.get("assets", []):
        if asset["name"].lower().endswith(".exe"):
            exe_url  = asset["browser_download_url"]
            exe_name = asset["name"]
            break
    # Optional integrity sidecars published with the release:
    #   "<exe_name>.sig"    – RSA signature, verified against the embedded
    #                         public key (protects against repo compromise)
    #   "<exe_name>.sha256" – plain checksum (protects against corruption)
    sig_url = None
    if exe_name:
        for asset in release.get("assets", []):
            name = asset["name"].lower()
            if name == exe_name.lower() + ".sha256":
                sha_url = asset["browser_download_url"]
            elif name == exe_name.lower() + ".sig":
                sig_url = asset["browser_download_url"]
    if exe_url and not is_allowed_update_url(exe_url):
        exe_url = None
    if sha_url and not is_allowed_update_url(sha_url):
        sha_url = None
    if sig_url and not is_allowed_update_url(sig_url):
        sig_url = None
    _latest_exe_url = exe_url
    global _latest_sha_url, _latest_sig_url
    _latest_sha_url = sha_url
    _latest_sig_url = sig_url
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
            _update_state["status"]   = "verifying"
            # Strongest check first: RSA signature against the embedded
            # public key. Falls back to the SHA256 sidecar (corruption-only
            # protection) for releases published before signing was adopted.
            if _latest_sig_url:
                sig_req = urllib.request.Request(
                    _latest_sig_url, headers={"User-Agent": "NetTrack-updater"})
                with urllib.request.urlopen(sig_req, timeout=30) as resp:
                    sig_hex = resp.read(4096).decode().strip()
                if not signing.verify_signature(tmp, sig_hex):
                    raise ValueError(
                        "Release signature invalid: download tampered or "
                        "signed with the wrong key")
            elif signing.REQUIRE_SIGNATURE:
                raise ValueError("Release is not signed; update refused")
            elif _latest_sha_url:
                sha_req = urllib.request.Request(
                    _latest_sha_url, headers={"User-Agent": "NetTrack-updater"})
                with urllib.request.urlopen(sha_req, timeout=30) as resp:
                    expected = resp.read(1024).decode().split()[0].strip().lower()
                h = hashlib.sha256()
                with open(tmp, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                if h.hexdigest() != expected:
                    raise ValueError("SHA256 mismatch: download corrupt or tampered")
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
_dns_sniffer = DNSSniffer(get_base_dir())

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
