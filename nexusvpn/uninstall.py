"""Stopping and removing NexusVPN Pro from the system.

Used by the installer (--stop before an upgrade), the Windows uninstaller (--cleanup) and the
«Удаление» page. Everything here is best effort: a missing item is not an error.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time

import psutil

from . import paths, winutil

log = logging.getLogger("uninstall")
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0
APP_EXE = "NexusVPN Pro.exe"
CORE_NAMES = ("sing-box", "xray", "mihomo", "openvpn")
TASKS = ("NexusVPN Pro", "SmartVPN")
INSTANCE_KEY = "NexusVPN-Pro-single-instance"


def _run(args: list[str], timeout: int = 60) -> None:
    try:
        subprocess.run(args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        pass


def ask_running_instance_to_quit(timeout: float = 15) -> bool:
    """Graceful quit through the single-instance pipe: restores the proxy and stops the cores itself."""
    try:
        from PySide6.QtCore import QCoreApplication
        from PySide6.QtNetwork import QLocalSocket
    except ImportError:
        return False
    app = QCoreApplication.instance() or QCoreApplication([])  # sockets need an application object
    sock = QLocalSocket(app)
    sock.connectToServer(INSTANCE_KEY)
    if not sock.waitForConnected(500):
        return False
    sock.write(b"quit")
    sock.waitForBytesWritten(500)
    sock.disconnectFromServer()
    mine = _own_pids()
    end = time.time() + timeout
    while time.time() < end:
        if not [p for p in _app_processes() if p.pid not in mine]:
            return True
        time.sleep(0.3)
    return False


def _own_pids() -> set[int]:
    """This process plus its parents/children: a frozen exe may run as launcher + worker."""
    me = psutil.Process()
    pids = {me.pid}
    try:
        pids |= {p.pid for p in me.parents()} | {p.pid for p in me.children(recursive=True)}
    except psutil.Error:
        pass
    return pids


def _app_processes() -> list[psutil.Process]:
    out = []
    for p in psutil.process_iter(["name"]):
        if (p.info["name"] or "").lower() == APP_EXE.lower():
            out.append(p)
    return out


def kill_everything() -> None:
    """Our GUI (other than this process) and every core started from our data folder."""
    mine = _own_pids()
    data = str(paths.DATA_DIR).lower()
    for p in psutil.process_iter(["name", "exe", "cmdline"]):
        try:
            name = (p.info["name"] or "").lower()
            if p.pid in mine:
                continue
            if name == APP_EXE.lower():
                p.kill()
            elif name.startswith(CORE_NAMES):
                where = ((p.info["exe"] or "") + " " + " ".join(p.info["cmdline"] or [])).lower()
                if data in where or str(paths.BASE_DIR).lower() in where:
                    p.kill()
        except (psutil.Error, OSError):
            pass


def stop_all() -> None:
    if not ask_running_instance_to_quit():
        kill_everything()
    restore_proxy()


def restore_proxy() -> None:
    try:
        port = int(json.loads(paths.SETTINGS_FILE.read_text("utf-8")).get("mixed_port", 2080))
    except (OSError, ValueError):
        port = 2080
    winutil.clear_system_proxy(port)


def remove_system_entries() -> None:
    """Scheduled tasks, firewall rules, IKEv2 connections created by the program."""
    if not IS_WIN:
        return
    for t in TASKS:
        _run(["schtasks", "/Delete", "/TN", t, "/F"])
    for core in ("sing-box", "xray", "mihomo"):
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=NexusVPN Pro ({core}.exe)"])
    _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
          "Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'NexusVPN IKEv2*' } "
          "| Remove-VpnConnection -Force -ErrorAction SilentlyContinue"])


def purge_data() -> None:
    for d in (paths.DATA_DIR,):
        if d.exists() and d.resolve() != paths.BASE_DIR.resolve():
            shutil.rmtree(d, ignore_errors=True)


def full_cleanup(purge: bool) -> None:
    stop_all()
    remove_system_entries()
    if purge:
        purge_data()


def is_installed() -> bool:
    """Installed by setup.exe (has the Inno uninstaller next to it), not just unpacked."""
    return any(paths.BASE_DIR.glob("unins*.exe"))


def uninstaller() -> str | None:
    found = sorted(paths.BASE_DIR.glob("unins*.exe"))
    return str(found[-1]) if found else None


def delete_folder_after_exit(folder) -> None:
    """Portable copy: remove the program folder once this process has exited."""
    if not IS_WIN:
        shutil.rmtree(folder, ignore_errors=True)
        return
    cmd = f'ping 127.0.0.1 -n 4 > nul & rmdir /s /q "{folder}"'
    subprocess.Popen(["cmd", "/c", cmd], creationflags=NO_WINDOW | 0x00000008, cwd=os.environ.get("TEMP", "C:\\"))


def cli(argv: list[str]) -> int:
    """--stop: quit the running program (installer, before an upgrade)
    --cleanup [--purge]: also remove system entries and, with --purge, all user data (uninstaller)"""
    if "--cleanup" in argv:
        full_cleanup(purge="--purge" in argv)
    else:
        stop_all()
    return 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv))
