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

import app

def start_flask():
    app.app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=True)

if __name__ == "__main__":
    threading.Thread(target=start_flask, daemon=True).start()
    time.sleep(1.5)

    import webview
    webview.create_window(
        "NetTrack",
        "http://127.0.0.1:5000",
        width=1400,
        height=900,
        min_size=(900, 600),
    )
    webview.start()
