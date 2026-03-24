from flask import Flask, render_template, jsonify, request
import json, os, subprocess, re, socket, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# ── DATA FILE (works both as script and as .exe) ───────────
def get_data_file():
    if getattr(sys, 'frozen', False):
        # Running as compiled .exe — store next to the executable
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "devices.json")

# ── MAC VENDOR LOOKUP (singleton — instantiate once) ───────
_mac_lookup = None
def get_mac_lookup():
    global _mac_lookup
    if _mac_lookup is None:
        try:
            from mac_vendor_lookup import MacLookup
            _mac_lookup = MacLookup()
        except Exception:
            _mac_lookup = False   # mark as unavailable so we don't retry
    return _mac_lookup if _mac_lookup else None

# ── DATA ──────────────────────────────────────────────────
def load_devices():
    path = get_data_file()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_devices(devices):
    path = get_data_file()
    with open(path, "w") as f:
        json.dump(devices, f, indent=2)

def find_device_index(devices, mac=None, ip=None):
    """Find a device by MAC (primary key) with IP as fallback."""
    if mac:
        for i, d in enumerate(devices):
            if d.get("mac") == mac:
                return i
    if ip:
        for i, d in enumerate(devices):
            if d.get("ip") == ip:
                return i
    return -1

# ── NETWORK ───────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"

def get_subnet(local_ip):
    return ".".join(local_ip.split(".")[:3])

def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1
        )
        return result.returncode == 0
    except Exception:
        return False

def get_arp_table():
    discovered = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\w-]{17})', line)
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

def lookup_vendor(mac):
    try:
        ml = get_mac_lookup()
        if ml:
            return ml.lookup(mac)
    except Exception:
        pass
    return ""

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def ping_sweep(subnet):
    alive = []
    ips   = [f"{subnet}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            try:
                if future.result():
                    alive.append(futures[future])
            except Exception:
                pass
    return alive

# ── ROUTES ────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/devices")
def get_devices():
    return jsonify(load_devices())

@app.route("/scan")
def scan():
    local_ip    = get_local_ip()
    subnet      = get_subnet(local_ip)

    # Single ARP pass before ping, then one more after to catch new entries
    arp_before  = get_arp_table()
    alive_ips   = ping_sweep(subnet)
    arp_after   = get_arp_table()

    # Merge both ARP snapshots (after wins on conflict)
    arp_results = {**arp_before, **arp_after}

    all_ips = set(list(arp_results.keys()) + alive_ips)
    all_ips.discard(local_ip)

    found = {}
    for ip in all_ips:
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

@app.route("/save", methods=["POST"])
def save_one():
    """Save a single device. Uses MAC as primary key, IP as fallback."""
    data    = request.get_json()
    device  = data.get("device")
    mac     = data.get("mac")
    ip      = device.get("ip") if device else None

    if not device:
        return jsonify({"ok": False, "error": "No device provided"}), 400

    devices = load_devices()
    idx     = find_device_index(devices, mac=mac, ip=ip)

    if idx >= 0:
        devices[idx] = device
    else:
        devices.append(device)

    save_devices(devices)
    return jsonify({"ok": True})

@app.route("/save-all", methods=["POST"])
def save_all():
    """Replace the entire device list (called after every scan)."""
    devices = request.get_json()
    if not isinstance(devices, list):
        return jsonify({"ok": False, "error": "Expected a list"}), 400
    save_devices(devices)
    return jsonify({"ok": True})

@app.route("/delete-device", methods=["POST"])
def delete_device():
    """Delete a device by MAC (primary key) with IP as fallback."""
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

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
