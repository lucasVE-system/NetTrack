# -*- mode: python ; coding: utf-8 -*-
import os
ROOT = os.path.dirname(os.path.abspath(SPEC))

a = Analysis(
    [os.path.join(ROOT, 'launcher.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, 'templates'), 'templates'),
    ],
    hiddenimports=[
        'app',
        'topology',
        'version',
        'flask',
        'jinja2',
        'werkzeug',
        'mac_vendor_lookup',
        'pysnmp',
        'pysnmp.hlapi',
        'zeroconf',
        'zeroconf._protocol',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

# Manually inject app.py, topology.py, version.py as compiled modules
from PyInstaller.utils.hooks import collect_data_files
import py_compile, tempfile, shutil

for mod in ('app', 'topology', 'version'):
    src = os.path.join(ROOT, f'{mod}.py')
    if os.path.exists(src):
        a.pure.append((mod, src, 'PYMODULE'))

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetTrack',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    icon=os.path.join(ROOT, 'app-icon.ico'),
)
