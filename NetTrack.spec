# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\vanee\\Desktop\\webapp\\launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\vanee\\Desktop\\webapp\\templates', 'templates')],
    hiddenimports=['dns_sniffer', 'app', 'topology', 'version', 'pysnmp', 'pysnmp.hlapi', 'zeroconf', 'zeroconf._protocol', 'dns', 'mac_vendor_lookup', 'flask', 'jinja2', 'werkzeug', 'webview', 'webview.platforms', 'webview.platforms.winforms', 'pythonnet', 'clr'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
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
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:\\Users\\vanee\\Desktop\\webapp\\app-icon.ico'],
)
