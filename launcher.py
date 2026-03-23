import threading
import webbrowser
import time
import app

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    threading.Thread(target=open_browser).start()
    app.app.run(host="0.0.0.0", port=5000, debug=False)