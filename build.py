import PyInstaller.__main__
import sys
import os

# Build the executable
PyInstaller.__main__.run([
    'app.py',
    '--onefile',
    '--windowed',
    '--add-data=templates:templates',
    '--add-data=static:static',
    '--add-data=devices.json:.',
    '--hidden-import=flask',
    '--name=NetTrack',
])

print("\n Build complete! Your .exe is in the 'dist' folder")
