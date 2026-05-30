import multiprocessing
multiprocessing.freeze_support()

import sys
import os

if getattr(sys, 'frozen', False):
    bundle_dir = sys._MEIPASS
    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)
else:
    bundle_dir = os.path.dirname(os.path.abspath(__file__))
    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)

import threading
import time
import urllib.request

import app


def start_flask():
    app.app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=True)


def wait_for_flask(timeout: float = 10.0) -> bool:
    """Poll until Flask responds or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://127.0.0.1:5000/", timeout=0.5)
            return True
        except Exception:
            time.sleep(0.1)
    return False


if __name__ == "__main__":
    threading.Thread(target=start_flask, daemon=True).start()
    wait_for_flask()

    import webview
    webview.create_window(
        "NetTrack",
        "http://127.0.0.1:5000",
        width=1400,
        height=900,
        min_size=(900, 600),
    )
    webview.start()

    # Clean up before exit
    app._dns_sniffer.stop()
