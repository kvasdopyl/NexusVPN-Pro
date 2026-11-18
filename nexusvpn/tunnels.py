"""System-level tunnels driven by NexusVPN: OpenVPN (openvpn.exe) and IKEv2 (Windows RAS).

Neither protocol exists in sing-box, so the OS builds a real adapter and sing-box sends
selected traffic through it with `bind_interface`. Each tunnel is started WITHOUT taking
the default route (route-nopull / SplitTunneling), so only what our rules choose goes there.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

import psutil

from . import paths

log = logging.getLogger("tunnels")
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0
FALLBACK_METRIC = 9000


class TunnelError(RuntimeError):
    pass


def resolve_ips(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []


def iface_by_ip(ip: str) -> str | None:
    for name, addrs in psutil.net_if_addrs().items():
        if any(a.address == ip for a in addrs):
            return name
    return None


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def kill_orphans() -> None:
    """openvpn.exe processes started from our run dir by a crashed previous session."""
    marker = str(paths.OVPN_DIR).lower()
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            if (p.info["name"] or "").lower().startswith("openvpn") and \
                    marker in " ".join(p.info["cmdline"] or []).lower():
                p.kill()
        except (psutil.Error, OSError):
            pass


def add_fallback_route(iface: str) -> None:
    """A high-metric default route on the tunnel adapter: never used by normal traffic, but lets
    sockets bound to the adapter (IP_UNICAST_IF) find a route for any destination."""
    if IS_WIN:
        subprocess.run(["netsh", "interface", "ipv4", "add", "route", "0.0.0.0/0", iface,
                        f"metric={FALLBACK_METRIC}", "store=active"], capture_output=True, creationflags=NO_WINDOW)
    # Linux: SO_BINDTODEVICE already treats the destination as on-link, nothing to do


def _ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


class BaseTunnel:
    kind = ""

    def __init__(self, node, settings):
        self.node = node
        self.s = settings
        self.iface: str | None = None
        self.server_ips: list[str] = []
        self.last_lines: deque = deque(maxlen=60)
        self.error = ""

    def start(self, timeout: float = 45) -> str:
        raise NotImplementedError

    def alive(self) -> bool:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


# ====================================================================== OpenVPN
STRIP_DIRECTIVES = re.compile(
    r"^\s*(redirect-gateway|block-outside-dns|route\s|route-ipv6\s|management|log|log-append|daemon|"
    r"up\s|down\s|script-security|route-up|ipchange|dhcp-option|register-dns|auth-user-pass|"
    r"service|dev-node|status)\b.*$", re.I | re.M)


def openvpn_exe(settings=None) -> str | None:
    cand = []
    if settings and settings.get("openvpn_exe"):
        cand.append(settings.get("openvpn_exe"))
    if IS_WIN:
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramW6432", ""),
                     r"C:\Program Files"):
            if base:
                cand.append(os.path.join(base, "OpenVPN", "bin", "openvpn.exe"))
    cand.append(shutil.which("openvpn") or "")
    for c in cand:
        if c and os.path.isfile(c):
            return c
    return None


def openvpn_version(exe: str | None = None) -> str:
    exe = exe or openvpn_exe()
    if not exe:
        return ""
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10,
                             creationflags=NO_WINDOW).stdout
    except (OSError, subprocess.SubprocessError):
        return "?"
    m = re.search(r"OpenVPN (\d+\.\d+\.\d+)", out)
    return m.group(1) if m else "?"


def prepare_ovpn(text: str, mgmt_port: int, auth_file: Path | None) -> str:
    body = STRIP_DIRECTIVES.sub("", text)
    # inline blocks (<ca>…</ca>) are untouched by the regex: it only matches directive lines
    extra = ["", "# --- NexusVPN Pro ---", "route-nopull", 'pull-filter ignore "redirect-gateway"',
             'pull-filter ignore "block-outside-dns"', 'pull-filter ignore "dhcp-option"',
             'pull-filter ignore "route"', f"management 127.0.0.1 {mgmt_port}", "auth-nocache",
             "connect-retry 2 10", "resolv-retry infinite", "persist-tun", "verb 3", "script-security 1"]
    if auth_file:
        extra.append(f'auth-user-pass "{auth_file.as_posix()}"')
    return body.rstrip() + "\n" + "\n".join(extra) + "\n"


class OpenVPNTunnel(BaseTunnel):
    kind = "openvpn"

    def __init__(self, node, settings):
        super().__init__(node, settings)
        self.mgmt_port = free_port()
        self.proc: subprocess.Popen | None = None
        self.local_ip = ""

    def _mgmt(self, cmd: str, timeout: float = 3) -> str:
        with socket.create_connection(("127.0.0.1", self.mgmt_port), timeout=timeout) as s:
            s.settimeout(timeout)
            buf = b""
            try:
                buf += s.recv(4096)          # greeting
            except socket.timeout:
                pass
            s.sendall(cmd.encode() + b"\n")
            end = time.time() + timeout
            while time.time() < end and b"\nEND" not in buf and b"SUCCESS:" not in buf.split(b"\n", 1)[-1]:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
            return buf.decode(errors="replace")

    def start(self, timeout: float = 45) -> str:
        try:
            return self._start(timeout)
        except BaseException:
            self.stop()          # never leave a half-started openvpn holding the adapter
            raise

    def _start(self, timeout: float) -> str:
        exe = openvpn_exe(self.s)
        if not exe:
            raise TunnelError("OpenVPN не установлен. «Ядра и базы» → «Установить OpenVPN».")
        n = self.node
        self.server_ips = resolve_ips(n.server)
        d = paths.OVPN_DIR
        d.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w.-]", "_", n.tag)[:40] or "ovpn"
        auth = None
        if n.extra.get("needs_auth") or n.uuid:
            if not n.uuid:
                raise TunnelError("Для этого OpenVPN нужен логин и пароль (Серверы → Изменить)")
            auth = d / f"{safe}.auth"
            auth.write_text(f"{n.uuid}\n{n.password}\n", "utf-8")
            if not IS_WIN:
                auth.chmod(0o600)
        cfg = d / f"{safe}.ovpn"
        cfg.write_text(prepare_ovpn(n.extra.get("ovpn", ""), self.mgmt_port, auth), "utf-8")
        self.proc = subprocess.Popen([exe, "--config", str(cfg)], cwd=str(d), stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
        threading.Thread(target=self._pump, daemon=True, name=f"ovpn-{safe}").start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any("AUTH_FAILED" in line for line in self.last_lines):
                raise TunnelError("OpenVPN: неверный логин или пароль")
            if self.proc.poll() is not None:
                time.sleep(0.3)      # let the log pump catch the final lines
                if any("AUTH_FAILED" in line for line in self.last_lines):
                    raise TunnelError("OpenVPN: неверный логин или пароль")
                raise TunnelError("OpenVPN завершился: " + self._why())
            try:
                st = self._mgmt("state")
            except OSError:
                time.sleep(0.5)
                continue
            m = re.search(r"\d+,CONNECTED,SUCCESS,([\d.]+)", st)
            if m:
                self.local_ip = m.group(1)
                for _ in range(20):
                    self.iface = iface_by_ip(self.local_ip)
                    if self.iface:
                        break
                    time.sleep(0.25)
                if not self.iface:
                    raise TunnelError(f"OpenVPN подключился, но адаптер с IP {self.local_ip} не найден")
                add_fallback_route(self.iface)
                log.info("OpenVPN %s up: %s via %s", n.tag, self.local_ip, self.iface)
                return self.iface
            time.sleep(0.7)
        self.stop()
        raise TunnelError("OpenVPN не подключился за отведённое время: " + self._why())

    def _why(self) -> str:
        lines = [x for x in self.last_lines if re.search(r"error|fail|refused|cannot|unable|TLS", x, re.I)]
        return " | ".join((lines or list(self.last_lines))[-4:])[:400]

    def _pump(self) -> None:
        p = self.proc
        if not p or not p.stdout:
            return
        lg = logging.getLogger("openvpn")
        for raw in p.stdout:
            line = raw.decode("utf-8", "replace").rstrip()
            if line:
                self.last_lines.append(line)
                lg.debug(line)

    def alive(self) -> bool:
        if not (self.proc and self.proc.poll() is None):
            return False
        try:
            return "CONNECTED,SUCCESS" in self._mgmt("state", 2)
        except OSError:
            return True   # management busy: the process itself is fine

    def stop(self) -> None:
        p = self.proc
        if not p or p.poll() is not None:
            return
        try:
            self._mgmt("signal SIGTERM", 2)
            p.wait(6)
        except (OSError, subprocess.TimeoutExpired):
            p.kill()
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                pass


# ====================================================================== IKEv2 (Windows RAS)
class IKEv2Tunnel(BaseTunnel):
    kind = "ikev2"

    @property
    def conn_name(self) -> str:
        return "NexusVPN IKEv2 " + re.sub(r"[^\w.-]", "_", self.node.tag)[:30]

    def _ps(self, script: str, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                               "-Command", script], capture_output=True, text=True, timeout=timeout,
                              creationflags=NO_WINDOW)

    def ensure_profile(self) -> None:
        n = self.node
        auth = "MachineCertificate" if n.extra.get("auth") == "cert" else "Eap"
        name = _ps_quote(self.conn_name)
        script = (
            f"$n={name}; if (Get-VpnConnection -Name $n -ErrorAction SilentlyContinue) "
            f"{{ Remove-VpnConnection -Name $n -Force }}; "
            f"Add-VpnConnection -Name $n -ServerAddress {_ps_quote(n.server)} -TunnelType Ikev2 "
            f"-EncryptionLevel Required -AuthenticationMethod {auth} -SplitTunneling -RememberCredential "
            f"-Force -ErrorAction Stop; ")
        if n.extra.get("strong", True):
            script += ("Set-VpnConnectionIPsecConfiguration -ConnectionName $n "
                       "-AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 "
                       "-EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 "
                       "-PfsGroup PFS2048 -Force -ErrorAction Stop; ")
        r = self._ps(script)
        if r.returncode != 0:
            raise TunnelError("IKEv2: не удалось создать подключение Windows: " + (r.stderr or r.stdout)[-300:])

    def start(self, timeout: float = 45) -> str:
        if not IS_WIN:
            raise TunnelError("IKEv2 работает только в Windows")
        n = self.node
        self.server_ips = resolve_ips(n.server)
        self.ensure_profile()
        args = ["rasdial", self.conn_name]
        if n.uuid:
            args += [n.uuid, n.password]
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, creationflags=NO_WINDOW,
                           encoding="cp866", errors="replace")
        if r.returncode != 0:
            raise TunnelError(f"IKEv2: ошибка {r.returncode}. " + _ras_hint(r.returncode) +
                              " " + (r.stdout or "").strip()[-200:])
        for _ in range(40):
            if self.conn_name in psutil.net_if_addrs():
                self.iface = self.conn_name
                break
            time.sleep(0.25)
        if not self.iface:
            raise TunnelError("IKEv2 подключился, но адаптер не найден")
        add_fallback_route(self.iface)
        log.info("IKEv2 %s up via %s", n.tag, self.iface)
        return self.iface

    def alive(self) -> bool:
        r = subprocess.run(["rasdial"], capture_output=True, text=True, creationflags=NO_WINDOW,
                           encoding="cp866", errors="replace")
        return self.conn_name in r.stdout

    def stop(self) -> None:
        if IS_WIN:
            subprocess.run(["rasdial", self.conn_name, "/disconnect"], capture_output=True, creationflags=NO_WINDOW)

    def remove_profile(self) -> None:
        if IS_WIN:
            self.stop()
            self._ps(f"Remove-VpnConnection -Name {_ps_quote(self.conn_name)} -Force -ErrorAction SilentlyContinue")


RAS_HINTS = {
    691: "Неверный логин или пароль.",
    809: "Сервер не отвечает: порты UDP 500/4500 закрыты или заблокированы.",
    812: "Подключение запрещено политикой сервера.",
    13801: "Сертификат сервера не доверенный: импортируйте корневой сертификат (Серверы → Импорт сертификата CA).",
    13806: "Не найден сертификат компьютера для проверки подлинности.",
    13868: "Несовпадение политик IPsec: попробуйте отключить «усиленное шифрование» или включить его.",
    13843: "Неверный ответ сервера (ошибка IPsec).",
}


def _ras_hint(code: int) -> str:
    return RAS_HINTS.get(code, "")


def import_ca_certificate(path: str) -> tuple[bool, str]:
    if not IS_WIN:
        return False, "Только Windows"
    r = subprocess.run(["certutil", "-addstore", "Root", path], capture_output=True, text=True,
                       creationflags=NO_WINDOW, encoding="cp866", errors="replace")
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]


def make_tunnel(node, settings, index: int) -> BaseTunnel:
    if node.type == "openvpn":
        return OpenVPNTunnel(node, settings)
    if node.type == "ikev2":
        return IKEv2Tunnel(node, settings)
    raise ValueError(node.type)
