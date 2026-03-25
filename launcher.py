import multiprocessing
multiprocessing.freeze_support()

import sys
import os

# When frozen by PyInstaller, add the bundle directory to sys.path
# so that app.py, topology.py and version.py can be found as modules.
if getattr(sys, 'frozen', False):
    bundle_dir = sys._MEIPASS
    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)
else:
    # Running from source — add the script's own directory
    bundle_dir = os.path.dirname(os.path.abspath(__file__))
    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)

import threading
import webbrowser
import time
sys.path.append(r"C:\Users\vanee\Desktop\webapp")

import app

def open_browser():
    time.sleep(2)
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    threading.Thread(target=open_browser, daemon=True).start()
    app.app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=True)
