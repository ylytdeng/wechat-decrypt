# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('main.py', '.'), ('config.py', '.'), ('decrypt_db.py', '.'), ('export_messages.py', '.'), ('voice_to_mp3.py', '.'), ('find_all_keys.py', '.'), ('find_all_keys_windows.py', '.'), ('find_all_keys_linux.py', '.'), ('key_scan_common.py', '.'), ('key_utils.py', '.'), ('decode_image.py', '.'), ('find_image_key.py', '.'), ('find_image_key_monitor.py', '.'), ('monitor.py', '.'), ('monitor_web.py', '.'), ('mcp_server.py', '.'), ('config.example.json', '.')]
binaries = []
hiddenimports = []
tmp_ret = collect_all('pilk')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['app_gui.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    name='WeChatDecrypt',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
