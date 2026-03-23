import PyInstaller.__main__
import os

print("Building NetTrack executable...")

PyInstaller.__main__.run([
    'app.py',
    '--onefile',
    '--windowed',
    '--add-data=templates:templates',
    '--add-data=static:static',
    '--hidden-import=flask',
    '--hidden-import=mac_vendor_lookup',
    '--name=NetTrack',
    '--icon=icon.ico',  # Optional: add an icon
])

print("\n✓ Build complete!")
print("Your .exe is in: dist/NetTrack.exe")
