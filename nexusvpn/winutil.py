"""Windows integration: admin rights, system proxy (WinINet), autostart via Task Scheduler."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from . import paths

IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0
TASK_NAME = "NexusVPN Pro"
_INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_BYPASS = ("localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;"
           "172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;"
           "192.168.*;*.local;<local>")
_SAVED = paths.RUN_DIR / "sysproxy-backup.json"


def is_admin() -> bool:
    if not IS_WIN:
        return os.geteuid() == 0
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin(extra_args: list[str] | None = None) -> bool:
    if not IS_WIN:
        return False
    import ctypes
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, list(sys.argv[1:])
    else:
        exe, args = sys.executable, list(sys.argv)
    args += extra_args or []
    params = subprocess.list2cmdline(args)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return rc > 32


# ------------------------------------------------------------------ system proxy
def _refresh_wininet() -> None:
    import ctypes
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(0, 39, 0, 0)   # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(0, 37, 0, 0)   # INTERNET_OPTION_REFRESH


def _read_proxy() -> dict:
    import winreg
    out = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY) as k:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            try:
                out[name] = winreg.QueryValueEx(k, name)[0]
            except FileNotFoundError:
                out[name] = None
    return out


def _write_proxy(values: dict) -> None:
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY, 0, winreg.KEY_SET_VALUE) as k:
        for name, val in values.items():
            if val is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            elif name == "ProxyEnable":
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(val))
            else:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(val))
    _refresh_wininet()


def set_system_proxy(port: int) -> None:
    if not IS_WIN:
        return
    cur = _read_proxy()
    ours = f"127.0.0.1:{port}"
    if not _SAVED.exists() and cur.get("ProxyServer") != ours:
        _SAVED.write_text(json.dumps(cur), "utf-8")
    _write_proxy({"ProxyEnable": 1, "ProxyServer": ours, "ProxyOverride": _BYPASS, "AutoConfigURL": None})


def clear_system_proxy(port: int) -> None:
    """Restore whatever the user had before; only touch settings that are ours."""
    if not IS_WIN:
        return
    try:
        if _SAVED.exists():
            prev = json.loads(_SAVED.read_text("utf-8"))
            _write_proxy(prev)
            _SAVED.unlink()
            return
        if _read_proxy().get("ProxyServer") == f"127.0.0.1:{port}":
            _write_proxy({"ProxyEnable": 0})
    except OSError:
        pass


def system_proxy_is_ours(port: int) -> bool:
    if not IS_WIN:
        return False
    try:
        cur = _read_proxy()
        return bool(cur.get("ProxyEnable")) and cur.get("ProxyServer") == f"127.0.0.1:{port}"
    except OSError:
        return False


# ------------------------------------------------------------------ autostart
def set_autostart(enabled: bool) -> tuple[bool, str]:
    """Scheduled task with highest privileges: starts elevated at logon without a UAC prompt."""
    if not IS_WIN:
        return False, "только Windows"
    if enabled:
        if getattr(sys, "frozen", False):
            tr = f'"{sys.executable}" --autostart'
        else:
            tr = f'"{sys.executable}" "{paths.BASE_DIR / "main.py"}" --autostart'
        cmd = ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr, "/SC", "ONLOGON",
               "/RL", "HIGHEST", "/F", "/DELAY", "0000:15"]
    else:
        cmd = ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]
    r = subprocess.run(cmd, capture_output=True, text=True, creationflags=NO_WINDOW)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def autostart_enabled() -> bool:
    if not IS_WIN:
        return False
    r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True, creationflags=NO_WINDOW)
    return r.returncode == 0
