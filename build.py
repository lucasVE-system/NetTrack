"""
Build NetTrack.exe with PyInstaller (one-file, no console).
Requires: pip install pyinstaller
Output: dist/NetTrack.exe

For a branded icon, add NetTrack.ico in this folder and uncomment --icon below.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
ICON = os.path.join(ROOT, "NetTrack.ico")


def main() -> int:
    os.makedirs(DIST, exist_ok=True)
    templates = os.path.join(ROOT, "templates")
    if not os.path.isdir(templates):
        print("ERROR: templates/ folder missing.", file=sys.stderr)
        return 1

    hidden = [
        "pysnmp", "pysnmp.hlapi", "zeroconf", "zeroconf._protocol",
        "dns", "mac_vendor_lookup", "scapy", "scapy.layers.l2", "scapy.sendrecv",
    ]
    hi_args: list[str] = []
    for m in hidden:
        hi_args.extend(["--hidden-import", m])

    sep = ";" if sys.platform == "win32" else ":"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile", "--windowed",
        "--name", "NetTrack",
        f"--add-data={templates}{sep}templates",
        *hi_args,
        os.path.join(ROOT, "launcher.py"),
    ]
    if os.path.isfile(ICON):
        cmd.extend(["--icon", ICON])

    print("Running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
