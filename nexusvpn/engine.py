"""Core supervisor + background service: start/stop, watchdog, failover, scheduled jobs."""
from __future__ import annotations

import json
import logging
import re
import secrets
import subprocess
import threading
import time
from collections import deque
from logging.handlers import RotatingFileHandler
from typing import Callable

import psutil

from . import config_builder, cores, paths, winutil
from .clash_api import ClashAPI
from .learner import Learner
from .tunnels import TunnelError, kill_orphans, make_tunnel
from .presets import enabled_presets
from .subscription import NodeStore, fetch, subs_from_settings, subs_to_settings

log = logging.getLogger("engine")
MEMORY_LIMIT_MB = 900


def setup_logging(level_mb: int) -> deque:
    paths.ensure_dirs()
    ring: deque = deque(maxlen=3000)

    class Ring(logging.Handler):
        def emit(self, record):
            ring.append(self.format(record))

    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fh = RotatingFileHandler(paths.LOGS_DIR / "nexusvpn.log", maxBytes=level_mb * 1024 * 1024, backupCount=3,
                             encoding="utf-8")
    rh = Ring()
    for h in (fh, rh):
        h.setFormatter(fmt)
        root.addHandler(h)
    return ring


class CoreProcess:
    """One child process with its output piped into a rotating log."""

    def __init__(self, name: str, args: list[str], log_mb: int):
        self.name = name
        self.args = args
        self.proc: subprocess.Popen | None = None
        self.logger = logging.getLogger(name)
        self.logger.propagate = True
        self._fh = RotatingFileHandler(paths.LOGS_DIR / f"{name}.log", maxBytes=log_mb * 1024 * 1024,
                                       backupCount=2, encoding="utf-8")
        self._fh.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
        self.last_lines: deque = deque(maxlen=40)

    def start(self) -> None:
        self.proc = subprocess.Popen(
            self.args, cwd=str(paths.RUN_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, creationflags=winutil.NO_WINDOW)
        threading.Thread(target=self._pump, name=f"{self.name}-log", daemon=True).start()

    def _pump(self) -> None:
        p = self.proc
        assert p and p.stdout
        for raw in p.stdout:
            line = raw.decode("utf-8", "replace").rstrip()
            line = _strip_ansi(line)
            if not line:
                continue
            self.last_lines.append(line)
            rec = logging.LogRecord(self.name, logging.INFO, "", 0, line, None, None)
            self._fh.emit(rec)
            lvl = logging.WARNING if (" ERROR" in line or "FATAL" in line) else logging.DEBUG
            self.logger.log(lvl, line)

    def alive(self) -> bool:
        return bool(self.proc and self.proc.poll() is None)

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    def stop(self, timeout: float = 6) -> None:
        p = self.proc
        if not p or p.poll() is not None:
            return
        try:
            # a windowed app has no console, so CTRL_BREAK cannot be delivered; Windows removes
            # the wintun adapter and its routes when the process handle closes
            p.terminate()
            p.wait(timeout)
        except (OSError, subprocess.TimeoutExpired):
            p.kill()
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                pass


def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def kill_stale() -> None:
    """Kill cores left over from a previous crash of the GUI (they would hold ports & TUN)."""
    try:
        pids = [int(x) for x in paths.PID_FILE.read_text().split()]
    except (OSError, ValueError):
        pids = []
    for pid in pids:
        try:
            p = psutil.Process(pid)
            if p.name().lower().startswith(("sing-box", "xray", "mihomo", "openvpn")):
                p.kill()
        except (psutil.Error, OSError):
            pass
    paths.PID_FILE.unlink(missing_ok=True)
    kill_orphans()


class Engine:
    """Owns sing-box (+ optional xray). All public methods are thread-safe."""

    STATES = ("stopped", "starting", "running", "stopping", "error")

    def __init__(self, settings, store: NodeStore, on_event: Callable[[str, dict], None]):
        self.s = settings
        self.store = store
        self.emit = on_event
        if not self.s["clash_secret"]:
            self.s["clash_secret"] = secrets.token_urlsafe(18)
            self.s.save()
        self.state = "stopped"
        self.error = ""
        self.started_at = 0.0
        self.singbox: CoreProcess | None = None
        self.xray: CoreProcess | None = None
        self.mihomo: CoreProcess | None = None
        self.tunnels: dict = {}            # tag -> BaseTunnel (OpenVPN / IKEv2)
        self.tunnel_errors: dict[str, str] = {}
        self._lock = threading.RLock()
        self._want_running = False
        self._restarts: deque = deque(maxlen=10)
        self._fails = 0
        self._last_hc = 0.0
        self._ifaces: frozenset = frozenset()
        self._stop_evt = threading.Event()
        self.learner = Learner(settings, self.api, self.emit)
        threading.Thread(target=self._watchdog, name="watchdog", daemon=True).start()

    # ------------------------------------------------------------------ helpers
    def api(self) -> ClashAPI:
        return ClashAPI(int(self.s["clash_api_port"]), self.s["clash_secret"])

    def proxy_ports(self) -> list[int | None]:
        """Download routes: direct first, then through the tunnel if it is up."""
        ports: list[int | None] = [None]
        if self.state == "running":
            ports.append(config_builder.probe_ports(self.s)[1])
        return ports

    def _set_state(self, st: str, err: str = "") -> None:
        self.state, self.error = st, err
        self.emit("state", {"state": st, "error": err})

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        with self._lock:
            if self.state in ("running", "starting"):
                return
            self._want_running = True
            self._set_state("starting")
            try:
                self._start_locked()
                self.started_at = time.time()
                self._fails = 0
                self._set_state("running")
                log.info("engine running")
            except Exception as e:  # noqa: BLE001 - surface any failure to the UI
                log.exception("start failed")
                self._kill_children()
                self._set_state("error", str(e))

    def _start_locked(self) -> None:
        sb_exe = paths.core_path("sing-box")
        if not sb_exe.exists():
            raise RuntimeError("Ядро sing-box не установлено. Откройте «Ядра» → «Обновить всё».")
        if self.s["capture_mode"] in ("tun", "both") and not winutil.is_admin():
            raise RuntimeError("Режим TUN требует прав администратора. Перезапустите программу от имени "
                               "администратора или выберите режим «Системный прокси».")
        kill_stale()
        if self.s["capture_mode"] in ("tun", "both"):
            winutil.allow_in_firewall([str(paths.core_path(n)) for n in ("sing-box", "xray", "mihomo")])
        ifaces, exclude = self._start_tunnels()
        _, xr, mh = config_builder.write_configs(self.s, self.store.nodes, ifaces=ifaces, exclude_ips=exclude)
        chk = subprocess.run([str(sb_exe), "check", "-c", str(paths.SINGBOX_CONFIG)], capture_output=True,
                             text=True, timeout=30, creationflags=winutil.NO_WINDOW, cwd=str(paths.RUN_DIR))
        if chk.returncode != 0:
            raise RuntimeError("Ошибка конфигурации: " + _strip_ansi(chk.stderr or chk.stdout)[-600:])
        mb = int(self.s["log_max_mb"])
        if xr:
            xr_exe = paths.core_path("xray")
            if not xr_exe.exists():
                raise RuntimeError("Для серверов XHTTP нужно ядро Xray. Откройте «Ядра» → «Обновить всё» "
                                   "или отключите XHTTP-серверы.")
            self.xray = CoreProcess("xray", [str(xr_exe), "run", "-c", str(paths.XRAY_CONFIG)], mb)
            self.xray.start()
            time.sleep(0.4)
            if not self.xray.alive():
                raise RuntimeError("Xray завершился: " + " | ".join(self.xray.last_lines))
        if mh:
            mh_exe = paths.core_path("mihomo")
            if not mh_exe.exists():
                raise RuntimeError("Для AmneziaWG нужно ядро mihomo. Откройте «Обновления» → «Обновить всё».")
            self.mihomo = CoreProcess("mihomo", [str(mh_exe), "-d", str(paths.RUN_DIR), "-f",
                                                 str(paths.MIHOMO_CONFIG)], mb)
            self.mihomo.start()
            time.sleep(0.6)
            if not self.mihomo.alive():
                raise RuntimeError("mihomo (AmneziaWG) завершился: " + " | ".join(list(self.mihomo.last_lines)[-5:]))
        self.singbox = CoreProcess("sing-box", [str(sb_exe), "run", "-c", str(paths.SINGBOX_CONFIG),
                                                "-D", str(paths.RUN_DIR), "--disable-color"], mb)
        self.singbox.start()
        pids = [p.pid for p in (self.singbox, self.xray, self.mihomo) if p and p.pid]
        pids += [t.proc.pid for t in self.tunnels.values() if getattr(t, "proc", None)]
        paths.PID_FILE.write_text(" ".join(map(str, pids)))
        api = self.api()
        deadline = time.time() + 15
        while time.time() < deadline:
            if not self.singbox.alive():
                raise RuntimeError("sing-box завершился: " + " | ".join(list(self.singbox.last_lines)[-6:]))
            if api.alive():
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("sing-box не отвечает (порт API занят?)")
        if self.s["capture_mode"] in ("system_proxy", "both"):
            winutil.set_system_proxy(int(self.s["mixed_port"]))
        self._ifaces = self._iface_snapshot()
        self.learner.start()

    def _start_tunnels(self) -> tuple[dict[str, str], list[str]]:
        """Bring up OpenVPN/IKEv2 adapters in parallel before sing-box. A failed tunnel only
        removes that one server; everything else keeps working."""
        self._stop_tunnels()
        self.tunnel_errors = {}
        todo = [n for n in self.store.enabled() if n.is_system_tunnel]
        if not todo:
            return {}, []
        tunnels = {n.tag: make_tunnel(n, self.s, i) for i, n in enumerate(todo)}
        self.tunnels = tunnels       # visible to stop() even if we are interrupted mid-start

        def run(tag, t):
            try:
                t.start()
            except (TunnelError, OSError, subprocess.SubprocessError) as e:
                self.tunnel_errors[tag] = str(e)
                log.warning("tunnel %s failed: %s", tag, e)

        threads = [threading.Thread(target=run, args=(tag, t), daemon=True) for tag, t in tunnels.items()]
        for th in threads:
            th.start()
        for th in threads:
            th.join(70)
        self.tunnels = tunnels
        for tag, err in self.tunnel_errors.items():
            self.emit("tunnel_error", {"node": tag, "error": err})
        ifaces = {tag: t.iface for tag, t in tunnels.items() if t.iface}
        exclude = sorted({ip for t in tunnels.values() for ip in t.server_ips})
        return ifaces, exclude

    def _stop_tunnels(self) -> None:
        for t in self.tunnels.values():
            try:
                t.stop()
            except (OSError, subprocess.SubprocessError):
                pass
        self.tunnels = {}

    def _kill_children(self) -> None:
        for p in (self.singbox, self.xray, self.mihomo):
            if p:
                p.stop()
        self.singbox = self.xray = self.mihomo = None
        self._stop_tunnels()
        paths.PID_FILE.unlink(missing_ok=True)

    def stop(self) -> None:
        with self._lock:
            self._want_running = False
            if self.state == "stopped":
                return
            self._set_state("stopping")
            self.learner.stop()
            winutil.clear_system_proxy(int(self.s["mixed_port"]))
            self._kill_children()
            self._set_state("stopped")
            log.info("engine stopped")

    def restart(self, reason: str = "") -> None:
        log.info("restart: %s", reason)
        with self._lock:
            self.stop()
            self.start()

    def reload(self) -> None:
        """Apply new settings/nodes. Only restarts if the core is running."""
        if self.state == "running":
            self.restart("настройки изменены")

    def shutdown(self) -> None:
        self._stop_evt.set()
        self.stop()

    # ------------------------------------------------------------------ runtime ops
    def select_node(self, tag: str) -> None:
        self.s["active_node"] = tag
        self.s.save()
        if self.state == "running":
            try:
                self.api().select("proxy", tag or "auto")
            except OSError:
                self.reload()

    def on_resume(self) -> None:
        """After sleep: all TCP sessions are dead; flush them and verify the tunnel."""
        if self.state != "running":
            return
        log.info("system resumed")
        time.sleep(3)
        try:
            self.api().close_all()
        except OSError:
            pass
        if not self._health_ok():
            self.restart("после сна туннель не работает")

    # ------------------------------------------------------------------ watchdog
    @staticmethod
    def _iface_snapshot() -> frozenset:
        try:
            out = set()
            for name, addrs in psutil.net_if_addrs().items():
                if paths.APP_SHORT in name or name.startswith(("tun", "NexusVPN IKEv2")):
                    continue
                for a in addrs:
                    # IPv4 only: Windows rotates temporary IPv6 addresses, which is not a network change
                    if a.family.name == "AF_INET" and not a.address.startswith(("127.", "169.254.")):
                        out.add((name, a.address))
            return frozenset(out)
        except (OSError, AttributeError):
            return frozenset()

    def _health_ok(self) -> bool:
        d = self.api().delay("proxy", self.s["health_check_url"], 6000)
        if d < 0:
            d = self.api().delay("proxy", "https://cp.cloudflare.com/generate_204", 6000)
        self.emit("health", {"delay": d})
        return d >= 0

    def _watchdog(self) -> None:
        while not self._stop_evt.wait(5):
            try:
                self._watch_once()
            except Exception:  # noqa: BLE001 - the watchdog must survive anything
                log.exception("watchdog")

    def _watch_once(self) -> None:
        if not self._want_running or self.state not in ("running", "error"):
            return
        sb_dead = not (self.singbox and self.singbox.alive())
        xr_dead = (self.xray is not None and not self.xray.alive()) or \
            (self.mihomo is not None and not self.mihomo.alive())
        tun_dead = [tag for tag, t in self.tunnels.items() if t.iface and not t.alive()]
        if tun_dead:
            log.warning("tunnel down: %s", tun_dead)
            self.emit("tunnel_error", {"node": ", ".join(tun_dead), "error": "соединение потеряно, переподключение"})
        if self.state == "error" or sb_dead or xr_dead or tun_dead:
            now = time.time()
            self._restarts.append(now)
            recent = [t for t in self._restarts if now - t < 300]
            delay = min(60, 2 ** min(len(recent), 6))
            log.warning("core down (sing-box dead=%s xray dead=%s), restart in %ss", sb_dead, xr_dead, delay)
            self.emit("core_crash", {"delay": delay})
            if self._stop_evt.wait(delay) or not self._want_running:
                return
            with self._lock:
                self.learner.stop()
                self._kill_children()
                self.state = "stopped"
            self.start()
            return

        # network changed (Wi-Fi switch, cable, VPN of a third party): drop stale sessions fast
        snap = self._iface_snapshot()
        if snap and snap != self._ifaces:
            self._ifaces = snap
            log.info("network changed, flushing connections")
            self.emit("network_changed", {})
            try:
                self.api().close_all()
            except OSError:
                pass

        # memory guard for weeks-long uptime
        try:
            rss = psutil.Process(self.singbox.pid).memory_info().rss / 2**20 if self.singbox else 0
            if rss > MEMORY_LIMIT_MB and not self.voice_active():
                self.restart(f"sing-box занимает {rss:.0f} МБ")
                return
        except psutil.Error:
            pass

        if time.time() - self._last_hc >= int(self.s["health_check_interval"]):
            self._last_hc = time.time()
            if self._health_ok():
                self._fails = 0
            else:
                self._fails += 1
                log.warning("health check failed (%d)", self._fails)
                if self._fails >= int(self.s["auto_switch_failures"]):
                    self._failover()

    def voice_active(self) -> bool:
        """True while a Discord (or any app routed via the discord group) UDP session is open."""
        if self.state != "running":
            return False
        try:
            for c in self.api().connections().get("connections") or []:
                md = c.get("metadata") or {}
                text = " ".join(c.get("chains") or []) + " " + str(md.get("processPath", ""))
                if md.get("network") == "udp" and "discord" in text.lower():
                    return True
        except (OSError, ValueError):
            pass
        return False

    def _failover(self) -> None:
        api = self.api()
        res = api.group_delay("auto", self.s["health_check_url"], 5000)
        alive = {k: v for k, v in res.items() if isinstance(v, int) and v > 0}
        if not alive:
            self.emit("all_down", {})
            self.restart("все серверы недоступны")
            self._fails = 0
            return
        best = min(alive, key=alive.get)
        log.warning("failover -> %s (%s ms)", best, alive[best])
        try:
            api.select("proxy", "auto" if self.s["auto_selector"] else best)
        except OSError:
            pass
        self.emit("failover", {"node": best, "delay": alive[best]})
        self._fails = 0


class Service:
    """Periodic jobs: subscriptions, core updates, rule updates. Runs one background thread."""

    def __init__(self, settings, store: NodeStore, engine: Engine, on_event):
        self.s, self.store, self.engine, self.emit = settings, store, engine, on_event
        self._stop = threading.Event()
        self._busy = threading.Lock()
        self._pending_reload = False
        threading.Thread(target=self._loop, name="service", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        self._stop.wait(20)
        last_core_check = last_app_check = 0.0
        while not self._stop.is_set():
            try:
                if self._pending_reload and not self.engine.voice_active():
                    self._pending_reload = False
                    self.engine.reload()
                self.update_subscriptions(only_due=True)
                if self.s["rules_auto_update"] and cores.rules_age_days() > 1:
                    self.update_rules()
                if time.time() - last_core_check > 86400:
                    last_core_check = time.time()
                    if self.s["core_auto_update"]:
                        self.update_cores(only_if_idle=True)
                    else:
                        avail = {n: i["latest"] for n, i in self.check_cores().items() if i["update"]}
                        if avail:
                            self.emit("cores_available", {"cores": avail})
                if self.s["app_update_check"] and time.time() - last_app_check > 6 * 3600:
                    last_app_check = time.time()
                    self.check_app_update(background=True)
            except Exception:  # noqa: BLE001
                log.exception("service loop")
            self._stop.wait(600)

    # ------------------------------------------------------------------ jobs
    def update_subscriptions(self, only_due: bool = False, names: list[str] | None = None) -> list[str]:
        msgs: list[str] = []
        with self._busy:
            subs = subs_from_settings(self.s)
            before = {n.key for n in self.store.enabled()}
            changed = False
            for sub in subs:
                if not sub.enabled or (names and sub.name not in names):
                    continue
                hours = sub.interval_hours or int(self.s["sub_auto_update_hours"])
                if only_due and time.time() - sub.updated_at < hours * 3600:
                    continue
                ports = self.engine.proxy_ports()
                if sub.via_proxy and len(ports) > 1:
                    ports = ports[::-1]
                err = ""
                for port in ports:
                    try:
                        nodes, warns = fetch(sub, port)
                        self.store.replace_group(sub.name, nodes)
                        msgs.append(f"{sub.name}: {len(nodes)} серверов" + (f" ({len(warns)} пропущено)" if warns else ""))
                        changed = True
                        err = ""
                        break
                    except Exception as e:  # noqa: BLE001
                        err = str(e)
                if err:
                    sub.last_error = err
                    msgs.append(f"{sub.name}: ошибка — {err}")
            subs_to_settings(self.s, subs)
        if changed:
            self.emit("nodes_changed", {"messages": msgs})
            if {n.key for n in self.store.enabled()} != before and self.engine.state == "running":
                # never cut an active call for a background refresh
                if self.engine.voice_active():
                    self._pending_reload = True
                else:
                    self.engine.reload()
        return msgs

    def update_rules(self) -> dict[str, str]:
        tags = [t for t, _, _ in enabled_presets(self.s)]
        res = cores.update_rules(self.engine.proxy_ports(), tags)
        self.emit("rules_updated", {"result": res})
        if self.engine.state == "running":
            # existing .srs files hot-reload; only a preset missing at start-up needs a restart
            try:
                running = {r["tag"] for r in json.loads(paths.SINGBOX_CONFIG.read_text("utf-8"))["route"]["rule_set"]}
            except (OSError, ValueError, KeyError):
                running = set()
            if set(tags) - running and not cores.missing_rules(tags):
                if self.engine.voice_active():
                    self._pending_reload = True
                else:
                    self.engine.reload()
        return res

    def check_app_update(self, background: bool = False) -> dict:
        """-> release info + 'newer'. Background checks notify once per build and may auto-install."""
        from . import updater
        try:
            info = updater.latest(self.s, self.engine.proxy_ports())
        except updater.UpdateError as e:
            if background:
                log.info("app update check: %s", e)
                return {}
            raise
        info["newer"] = updater.is_newer(info)
        if info["newer"] and background:
            if self.s["app_update_auto"] and not self.engine.voice_active():
                self.emit("app_update_auto", info)
            else:
                info["notify"] = info["build"] != int(self.s["update_notified_build"])
                if info["notify"]:
                    self.s["update_notified_build"] = info["build"]
                    self.s.save()
                self.emit("app_update", info)
        return info

    def check_cores(self) -> dict[str, dict]:
        out = {}
        for name in cores.SPECS:
            cur = cores.installed_version(name)
            try:
                latest, url = cores.latest_release(name, self.engine.proxy_ports())
            except OSError as e:
                latest, url = "", str(e)
            out[name] = {"installed": cur, "latest": latest, "url": url,
                         "update": bool(latest) and cores.is_newer(latest, cur)}
        return out

    def update_cores(self, names: list[str] | None = None, only_if_idle: bool = False,
                     force: bool = False) -> list[str]:
        msgs = []
        with self._busy:
            info = self.check_cores()
            todo = [n for n in (names or info) if info[n]["update"] or force]
            todo = [n for n in todo if info[n]["latest"]]
            if not todo:
                return ["Все ядра актуальны"]
            if only_if_idle and self.engine.voice_active():
                return ["Обновление отложено: идёт голосовой звонок"]
            was_running = self.engine.state == "running"
            ports = self.engine.proxy_ports()
            for name in todo:
                try:
                    ver = cores.install(name, ports, (info[name]["latest"], info[name]["url"]),
                                        before_replace=self.engine.stop if was_running else None)
                    msgs.append(f"{name} → {ver}")
                except OSError as e:
                    msgs.append(f"{name}: {e}")
            if was_running:
                self.engine.start()
                if self.engine.state != "running":
                    # new core rejected our config: roll back automatically
                    for name in todo:
                        cores.rollback(name)
                    self.engine.start()
                    msgs.append("новая версия не запустилась — выполнен откат")
        self.emit("cores_updated", {"messages": msgs})
        return msgs
