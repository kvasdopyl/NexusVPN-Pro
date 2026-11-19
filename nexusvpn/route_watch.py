"""Full bypass: keep addresses that belong to the VPN out of the physical interface.

In «full bypass» only the addresses in the TUN's route_address enter sing-box, so a program the user
sends through the VPN would leak when it dials a raw IP with no domain (games, custom ports). This
watcher adds such addresses to the TUN: it watches the TCP connections of VPN programs and adds every
new public destination as a host route, and it adds learned/user proxy IPs as they appear.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading

import psutil

from . import paths

log = logging.getLogger("bypass")
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0
POLL = 8.0


def _private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


class RouteWatcher:
    def __init__(self, on_change=None):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._added: set[str] = set()
        self._bad: set[str] = set()
        self.on_change = on_change or (lambda: None)

    # ---------- lifecycle ----------
    def start(self) -> None:
        self.refresh()
        self._thread = threading.Thread(target=self._loop, name="bypass", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(POLL):
            try:
                self.refresh()
            except Exception:  # noqa: BLE001 - a watcher must never kill the engine
                log.exception("route watcher")

    # ---------- routing ----------
    def _iface(self) -> str:
        try:
            cfg = json.loads(paths.SINGBOX_CONFIG.read_text("utf-8"))
        except (OSError, ValueError):
            return ""
        for inbound in cfg.get("inbounds", []):
            if inbound.get("type") == "tun":
                return inbound.get("interface_name") or "tun0"
        return ""

    def _regexes(self) -> list[re.Pattern]:
        try:
            cfg = json.loads(paths.SINGBOX_CONFIG.read_text("utf-8"))
        except (OSError, ValueError):
            return []
        out = []
        for rule in cfg.get("route", {}).get("rules", []):
            # Discord needs no scan: its domains resolve to FakeIP and its voice ranges are routed already
            if rule.get("outbound") == "proxy" and rule.get("process_path_regex"):
                out += [re.compile(r.replace("(?i)", ""), re.I) for r in rule["process_path_regex"]]
        return out

    def refresh(self) -> None:
        iface = self._iface()
        if not iface:
            return
        targets = set(self._proxy_ips())
        rx = self._regexes()
        if rx:
            targets |= self._program_destinations(rx)
        new = [ip for ip in targets if ip not in self._added and ip not in self._bad and not _private(ip)]
        for ip in new:
            if self._add(ip, iface):
                self._added.add(ip)
            else:
                self._bad.add(ip)
        if new:
            self.on_change()

    def _proxy_ips(self) -> list[str]:
        out: list[str] = []
        for path in (paths.USER_PROXY_IP_RS, paths.LEARNED_PROXY_IP_RS):
            try:
                data = json.loads(path.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            for rule in data.get("rules", []):
                out += rule.get("ip_cidr", [])
        return [c.split("/")[0] for c in out]

    def _program_destinations(self, rx: list[re.Pattern]) -> set[str]:
        out: set[str] = set()
        for conn in psutil.net_connections(kind="tcp"):
            if not conn.raddr or conn.status not in (psutil.CONN_SYN_SENT, psutil.CONN_ESTABLISHED):
                continue
            try:
                path = psutil.Process(conn.pid).exe() if conn.pid else ""
            except (psutil.Error, OSError):
                continue
            if path and any(r.search(path) for r in rx):
                out.add(conn.raddr.ip)
        return out

    def _add(self, ip: str, iface: str) -> bool:
        args = (["netsh", "interface", "ipv4", "add", "route", f"{ip}/32", iface, "store=active"] if IS_WIN
                else ["ip", "route", "add", f"{ip}/32", "dev", iface])
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW)
        except (OSError, subprocess.SubprocessError):
            return False
        ok = r.returncode == 0
        if ok:
            log.info("bypass: %s через %s", ip, iface)
        return ok


def flush_dns() -> None:
    """FakeIP answers are cached by Windows: after a mode change they must be thrown away."""
    if not IS_WIN:
        return
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=20, creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        pass

