from flask import Flask, render_template, jsonify, request
import json, os, subprocess, platform, re, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
DATA_FILE = "devices.json"

# ── DATA ──────────────────────────────────────────────────
def load_devices():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_devices(devices):
    with open(DATA_FILE, "w") as f:
        json.dump(devices, f, indent=2)

# ── NETWORK ───────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
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
    except:
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
                if not ip.endswith(".255") and not ip.startswith("224.") and mac != "FF:FF:FF:FF:FF:FF":
                    discovered[ip] = mac
    except Exception as e:
        print(f"ARP error: {e}")
    return discovered

def lookup_vendor(mac):
    try:
        from mac_vendor_lookup import MacLookup
        return MacLookup().lookup(mac)
    except:
        return ""

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
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
            except:
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
    arp_results = get_arp_table()
    alive_ips   = ping_sweep(subnet)
    arp_results.update(get_arp_table())

    all_ips = set(list(arp_results.keys()) + alive_ips)
    all_ips.discard(local_ip)

    found = {}
    for ip in all_ips:
        mac    = arp_results.get(ip, "")
        vendor = lookup_vendor(mac) if mac else ""
        host   = get_hostname(ip)
        found[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": host}

    sorted_results = sorted(found.values(), key=lambda x: int(x["ip"].split(".")[-1]))
    return jsonify({"subnet": subnet, "local_ip": local_ip, "count": len(sorted_results), "devices": sorted_results})

@app.route("/save", methods=["POST"])
def save_one():
    data    = request.get_json()
    index   = data.get("index")
    device  = data.get("device")
    devices = load_devices()
    if 0 <= index < len(devices):
        devices[index] = device
    else:
        devices.append(device)
    save_devices(devices)
    return jsonify({"ok": True})

@app.route("/save-all", methods=["POST"])
def save_all():
    devices = request.get_json()
    save_devices(devices)
    return jsonify({"ok": True})

@app.route("/delete-device", methods=["POST"])
def delete_device():
    data    = request.get_json()
    index   = data.get("index")
    devices = load_devices()
    if 0 <= index < len(devices):
        devices.pop(index)
        save_devices(devices)
    return jsonify({"ok": True})

if __name__ == "__main__":
    import webbrowser
    webbrowser.open('http://localhost:5000')
    app.run(debug=False)
