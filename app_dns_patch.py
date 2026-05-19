"""
app.py  –  DNS Monitor additions
==================================
Paste these three changes into your existing app.py:

  1. Import block  (top of file, after existing imports)
  2. Sniffer init  (after load_snmp_config() at the bottom of the startup block)
  3. Four new routes  (anywhere in the ROUTES section, e.g. after /snmp-config)

Everything else in app.py stays unchanged.
"""

# ── CHANGE 1 ─────────────────────────────────────────────────────────────────
# Add this import near the top of app.py, after the existing imports:

from dns_sniffer import DNSSniffer

# ── CHANGE 2 ─────────────────────────────────────────────────────────────────
# Replace the STARTUP block at the bottom of app.py:
#
#   OLD:
#       load_snmp_config()
#
#   NEW:

load_snmp_config()

# Initialise the DNS sniffer singleton; it restores the previous session log.
# The sniffer does NOT start automatically – the user must call POST /dns-start.
_dns_sniffer = DNSSniffer(get_base_dir())


# ── CHANGE 3 ─────────────────────────────────────────────────────────────────
# Add these four routes to app.py.  Place them in the ROUTES section,
# e.g. directly after the /snmp-config DELETE route.

# ── DNS MONITOR ───────────────────────────────────────────────────────────────

@app.route("/dns-start", methods=["POST"])
def dns_start():
    """
    Start the background DNS sniffer.
    Requires a raw socket (admin/elevated on Windows, CAP_NET_RAW on Linux).
    Returns {ok, available, already_running}.
    """
    if _dns_sniffer._running:
        return jsonify({"ok": True, "available": True, "already_running": True})
    ok = _dns_sniffer.start()
    return jsonify({"ok": ok, "available": ok, "already_running": False})


@app.route("/dns-stop", methods=["POST"])
def dns_stop():
    """
    Stop the DNS sniffer and flush the log to disk.
    Safe to call even if the sniffer is not running.
    """
    _dns_sniffer.stop()
    return jsonify({"ok": True})


@app.route("/dns-log")
def dns_log():
    """
    Return recent DNS query log entries, newest-first.

    Query params
    ------------
    ip    : (optional) Filter to a single source IP address.
    limit : (optional) Max entries to return, 1–1000 (default 200).

    Response
    --------
    {
      "running":   bool,
      "available": bool,
      "entries": [
        {"ts": float, "ip": "x.x.x.x", "domain": "example.com", "category": "..."},
        ...
      ]
    }
    """
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
    """
    Return aggregated DNS statistics (category counts + top domains).

    Query params
    ------------
    ip : (optional) Scope stats to a single device IP.

    Response
    --------
    {
      "running":     bool,
      "total":       int,
      "by_category": {"Streaming": 42, "Ads": 7, ...},
      "top_domains": [{"domain": "youtube.com", "count": 42}, ...]
    }
    """
    ip_filter = request.args.get("ip", "").strip() or None
    if ip_filter and not topo._valid_ip(ip_filter):
        return api_error("Invalid IP", 400)

    stats = _dns_sniffer.get_stats(ip=ip_filter)
    stats["running"]   = _dns_sniffer._running
    stats["available"] = _dns_sniffer.available
    return jsonify(stats)


@app.route("/dns-clear", methods=["POST"])
def dns_clear():
    """
    Clear the DNS log.

    Body (optional)
    ---------------
    { "ip": "x.x.x.x" }  →  clear only that device's log
    (omit body)           →  clear everything
    """
    data      = request.get_json(silent=True) or {}
    ip_filter = data.get("ip", "").strip() or None
    if ip_filter and not topo._valid_ip(ip_filter):
        return api_error("Invalid IP", 400)
    _dns_sniffer.clear(ip=ip_filter)
    return jsonify({"ok": True})
