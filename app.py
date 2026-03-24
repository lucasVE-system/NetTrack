from flask import Flask, render_template, jsonify, request
import json, os, subprocess, re, socket, sys, threading, time, urllib.request, secrets
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from version import VERSION, GITHUB_REPO

app = Flask(__name__)

# ── BASE DIR (works both as script and as .exe) ────────────
def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_data_file():
    return os.path.join(get_base_dir(), "devices.json")

# ── MAC VENDOR LOOKUP (singleton) ─────────────────────────
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
    with open(get_data_file(), "w") as f:
        json.dump(devices, f, indent=2)

def find_device_index(devices, mac=None, ip=None):
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
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1,
            **kwargs
        )
        return result.returncode == 0
    except Exception:
        return False

def get_arp_table():
    discovered = {}
    try:
        kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5, **kwargs)
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

# ── AUTO UPDATE ───────────────────────────────────────────
def parse_version(v):
    v = v.lstrip("v")
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0, 0, 0)

def fetch_latest_release():
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "NetTrack-updater"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None

_update_state = {"status": "idle", "progress": 0, "error": ""}
_latest_exe_url = None
_update_token = secrets.token_urlsafe(24)

ALLOWED_UPDATE_HOSTS = {"github.com", "objects.githubusercontent.com"}
ALLOWED_GITHUB_PATH_PREFIX = f"/{GITHUB_REPO}/releases/download/"

def is_allowed_update_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        if parsed.hostname not in ALLOWED_UPDATE_HOSTS:
            return False
        if parsed.hostname == "github.com" and not parsed.path.startswith(ALLOWED_GITHUB_PATH_PREFIX):
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
        "update":  True,
        "current": VERSION,
        "latest":  latest_tag,
        "exe_url": exe_url,
        "update_token": _update_token,
        "notes":   release.get("body", "")
    })

@app.route("/update-progress")
def update_progress():
    return jsonify(_update_state)

@app.route("/do-update", methods=["POST"])
def do_update():
    data = request.get_json() or {}
    exe_url = data.get("exe_url")
    token = data.get("update_token")

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
        try:
            base    = get_base_dir()
            current = sys.executable if getattr(sys, 'frozen', False) \
                      else os.path.join(base, "NetTrack.exe")
            tmp     = current + ".new"
            bak     = current + ".bak"

            # Download with progress tracking
            req = urllib.request.Request(exe_url, headers={"User-Agent": "NetTrack-updater"})
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

            # Swap files
            if os.path.exists(bak):
                os.remove(bak)
            if os.path.exists(current):
                os.rename(current, bak)
            os.rename(tmp, current)

            _update_state["status"] = "restarting"

            def restart():
                time.sleep(1.5)
                if sys.platform == "win32":
                    subprocess.Popen([current], creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen([current])
                os._exit(0)

            threading.Thread(target=restart, daemon=True).start()

        except Exception as e:
            _update_state["status"] = "error"
            _update_state["error"]  = str(e)
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass

    threading.Thread(target=run_update, daemon=True).start()
    return jsonify({"ok": True})

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
    arp_before  = get_arp_table()
    alive_ips   = ping_sweep(subnet)
    arp_after   = get_arp_table()
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
    data   = request.get_json()
    device = data.get("device")
    mac    = data.get("mac")
    ip     = device.get("ip") if device else None
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

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
