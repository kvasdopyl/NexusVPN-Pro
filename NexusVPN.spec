# -*- mode: python ; coding: utf-8 -*-
EXCLUDES = ["tkinter", "unittest", "pydoc", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
            "PySide6.QtQml", "PySide6.QtQuick", "PySide6.Qt3DCore", "PySide6.QtMultimedia", "PySide6.QtPdf",
            "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtBluetooth", "PySide6.QtSql",
            "PySide6.QtTest", "PySide6.QtDesigner", "PySide6.QtOpenGL", "PySide6.QtSvg"]

a = Analysis(["main.py"], pathex=["."], binaries=[], datas=[("assets", "assets")],
             hiddenimports=["nexusvpn.gui.pages", "nexusvpn.gui.pages2", "yaml", "psutil"],
             excludes=EXCLUDES, noarchive=False, optimize=1)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="NexusVPN Pro", icon="assets/icon.ico",
          version="version_info.txt", console=False, uac_admin=True, upx=False, disable_windowed_traceback=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="NexusVPN Pro")
