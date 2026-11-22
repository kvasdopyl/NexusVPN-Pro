"""Application object: main window, tray icon, lifecycle, OS power events."""
from __future__ import annotations

import atexit
import ctypes
import logging
import sys
import threading
import time

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QAction, QActionGroup
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QListWidget, QMainWindow, QMenu, QMessageBox,
                               QStackedWidget, QSystemTrayIcon, QWidget)

from .. import paths, winutil
from ..engine import Engine, Service, kill_stale, setup_logging
from ..settings import Settings
from ..subscription import NodeStore
from .common import COLORS, STATE_TEXT, THEME, Bridge, apply_dark_theme, run_bg, status_icon
from .pages import MODES, HomePage, ServersPage
from .pages3 import GamesPage, NoWheelUntilClicked
from .discord_page import DiscordPage
from .pages2 import (AboutPage, ConnectionsPage, CoresPage, LogsPage, SettingsPage, SmartPage, UninstallPage)
from .routing import CustomRoutingPage

log = logging.getLogger("app")
INSTANCE_KEY = "NexusVPN-Pro-single-instance"
WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND = 0x218, 0x12, 0x7


class MainWindow(QMainWindow):
    def __init__(self, app: "NexusApp"):
        super().__init__()
        self.app = app
        self.setWindowTitle(f"{paths.APP_NAME} {paths.APP_VERSION}")
        self.setWindowIcon(status_icon(COLORS["stopped"]))
        self.resize(1100, 720)
        self.setMinimumSize(880, 560)
        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(230)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav.setTextElideMode(Qt.ElideRight)
        self.stack = QStackedWidget()
        h.addWidget(self.nav)
        content = QWidget()
        cl = QHBoxLayout(content)
        cl.setContentsMargins(18, 14, 18, 10)
        cl.addWidget(self.stack)
        h.addWidget(content, 1)
        self.setCentralWidget(root)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self._hint_shown = False

    def add_page(self, title: str, w: QWidget) -> None:
        self.nav.addItem(title)
        self.stack.addWidget(w)

    def closeEvent(self, e):
        e.ignore()
        self.hide()
        if not self._hint_shown and self.app.tray.isVisible():
            self._hint_shown = True
            self.app.tray.showMessage(paths.APP_NAME, "Программа продолжает работать в трее.",
                                      QSystemTrayIcon.Information, 3000)

    def nativeEvent(self, event_type, message):
        if winutil.IS_WIN and event_type == b"windows_generic_MSG":
            from ctypes import wintypes
            msg = wintypes.MSG.from_address(int(message))
            if msg.message == WM_POWERBROADCAST and msg.wParam in (PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND):
                run_bg(self.app.engine.on_resume)
        return super().nativeEvent(event_type, message)


class NexusApp:
    def __init__(self, qapp: QApplication, autostart: bool):
        self.qapp = qapp
        paths.ensure_dirs()
        self.settings = Settings()
        self.ring = setup_logging(int(self.settings["log_max_mb"]))
        log.info("NexusVPN Pro start, data=%s admin=%s", paths.DATA_DIR, winutil.is_admin())
        self.autostarted = autostart
        winutil.clear_system_proxy(int(self.settings["mixed_port"]))

        self._quitting = False
        self.bridge = Bridge()
        self.bridge.event.connect(self.on_event, Qt.QueuedConnection)
        self.store = NodeStore()
        self.engine = Engine(self.settings, self.store, self.bridge.emit_event)
        self.service = Service(self.settings, self.store, self.engine, self.bridge.emit_event)
        atexit.register(self._emergency_cleanup)

        apply_dark_theme(qapp)
        self._no_wheel = NoWheelUntilClicked(qapp)
        qapp.installEventFilter(self._no_wheel)
        qapp.setStyleSheet(THEME)
        self.win = MainWindow(self)
        self.home = HomePage(self)
        self.servers = ServersPage(self)
        self.custom = CustomRoutingPage(self)
        self.smart = SmartPage(self)
        self.conns = ConnectionsPage(self)
        self.cores = CoresPage(self)
        self.settings_page = SettingsPage(self)
        self.logs = LogsPage(self, self.ring)
        self.about = AboutPage(self)
        self.uninstall_page = UninstallPage(self)
        self.games = GamesPage(self)
        self.discord = DiscordPage(self)
        self.page_index = {}
        for key, title, page in (("home", "  Главная", self.home), ("servers", "  Серверы", self.servers),
                                 ("custom", "  Своя маршрутизация", self.custom),
                                 ("games", "  Игры", self.games),
                                 ("discord", "  Discord", self.discord),
                                 ("smart", "  Умная маршрутизация", self.smart),
                                 ("conns", "  Соединения", self.conns), ("cores", "  Обновления", self.cores),
                                 ("settings", "  Настройки", self.settings_page), ("logs", "  Журнал", self.logs),
                                 ("about", "  О программе и удаление", self.about)):
            self.page_index[key] = self.win.nav.count()
            self.win.add_page(title, page)
        self.win.nav.setCurrentRow(0)
        self._build_tray()
        self._traffic_stop = threading.Event()
        threading.Thread(target=self._traffic_loop, daemon=True, name="traffic").start()
        threading.Thread(target=self._routes_loop, daemon=True, name="routes").start()

        if not (autostart and self.settings["start_minimized"]):
            self.win.show()
        self._tray_target = ""
        self.tray.messageClicked.connect(lambda: self._tray_target and self.open_page(self._tray_target))
        self.update_info: dict = {}
        self._after_update_notice()
        if winutil.IS_WIN and self.settings["autostart"]:
            # the program may have moved (zip folder -> Program Files): keep the logon task pointing here
            run_bg(winutil.set_autostart, True)
        # crash recovery (orphan cores holding the TUN) walks every process: slow on Windows, so off the window
        QTimer.singleShot(150, lambda: run_bg(kill_stale, done=lambda _r: self._first_run()))

    # ------------------------------------------------------------------ startup
    def _first_run(self) -> None:
        from .. import cores
        self._seed_bundled_cores()
        need = [n for n in cores.SPECS if not paths.core_path(n).exists()]
        if need:
            self.status("Первый запуск: загрузка ядер и баз правил…")

            def setup():
                msgs = self.service.update_cores(names=need, force=True)
                self.service.update_rules()
                return msgs
            run_bg(setup, done=lambda m: (self.status("; ".join(m)), self.cores.check(), self._autoconnect()),
                   failed=lambda e: self.status(f"Не удалось скачать ядра: {e}"))
        else:
            self._autoconnect()

    def _seed_bundled_cores(self) -> None:
        """The release zip ships cores/ and rules/ next to the exe: first start works even when
        GitHub is unreachable."""
        import shutil
        for sub, dest in (("cores", paths.CORES_DIR), ("rules", paths.RULES_DIR)):
            src = paths.BASE_DIR / sub
            if not src.is_dir() or src.resolve() == dest.resolve():
                continue
            for item in src.iterdir():
                target = dest / item.name
                if target.exists():
                    continue
                if item.is_dir():
                    shutil.copytree(item, target)
                else:
                    shutil.copy2(item, target)

    def notify(self, text: str, page: str = "", level=QSystemTrayIcon.Information, ms: int = 8000) -> None:
        self._tray_target = page
        self.tray.showMessage(paths.APP_NAME, text[:250], level, ms)
        self.status(text)

    def _after_update_notice(self) -> None:
        from .. import updater
        b = updater.current_build()
        last = int(self.settings["last_run_build"] or 0)
        if b and last and b > last:
            QTimer.singleShot(2500, lambda: self.notify(f"NexusVPN Pro обновлён: {updater.current_version_text()}",
                                                        "cores"))
        if b != last:
            self.settings["last_run_build"] = b
            self.settings.save()

    def install_app_update(self, info: dict, ask: bool = True) -> None:
        from .. import updater
        if ask and QMessageBox.question(
                self.win, "Обновление", f"Установить {info['name']}?\n\nСкачается {info['size'] // 1048576} МБ, "
                "программа закроется на несколько секунд и запустится снова. Настройки и подписки сохранятся.") \
                != QMessageBox.Yes:
            return
        if not updater.is_installed_copy():
            QMessageBox.information(self.win, "Обновление",
                                    "Эта копия запущена из распакованной папки, а не установлена. Скачайте "
                                    "установщик из раздела Releases на GitHub и запустите его — дальше "
                                    "обновления будут ставиться сами.")
            return
        self.status("Скачивание обновления…")

        def prog(got, total):
            self.bridge.emit_event("update_progress", {"got": got, "total": total})

        def done(setup):
            self.status("Установка обновления…")
            updater.run_installer(setup)
            self.quit()
        run_bg(updater.download, info, self.settings, self.engine.proxy_ports(), prog, done=done,
               failed=lambda e: self.notify(f"Обновление не скачалось: {e}", "cores", QSystemTrayIcon.Warning))

    def uninstall(self, purge: bool) -> None:
        from .. import uninstall
        self._quitting = True
        self._traffic_stop.set()
        self.service.stop()
        self.engine.shutdown()
        uninstall.restore_proxy()
        uninstall.remove_system_entries()
        unins = uninstall.uninstaller()
        if unins:
            import subprocess
            args = [unins, "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART"] + ([] if purge else ["/KEEPDATA"])
            subprocess.Popen(args, creationflags=0x00000008 if winutil.IS_WIN else 0)
        else:
            if purge:
                uninstall.purge_data()
            uninstall.delete_folder_after_exit(paths.BASE_DIR)
        self.tray.hide()
        self.qapp.quit()

    def _autoconnect(self, attempt: int = 0) -> None:
        """Started with Windows (autostart) -> always connect. Started by hand -> reconnect if the VPN
        was on last time. Right after logon the network may still be coming up: keep trying."""
        want = self.autostarted or self.settings["was_connected"]
        if not want or self.engine.state in ("running", "starting"):
            return
        if not self.store.enabled():
            if self.settings["subscriptions"] and attempt < 8:
                def retry(_m=None):
                    self.nodes_changed()
                    if self.store.enabled():
                        self._autoconnect(attempt + 1)
                    else:
                        QTimer.singleShot(15000, lambda: self._autoconnect(attempt + 1))
                run_bg(self.service.update_subscriptions, False, None, done=retry,
                       failed=lambda _e: QTimer.singleShot(15000, lambda: self._autoconnect(attempt + 1)))
            return
        if self.autostarted:
            log.info("запуск вместе с Windows — подключение")
        run_bg(self.engine.start)

    # ------------------------------------------------------------------ tray
    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(status_icon(COLORS["stopped"]))
        m = QMenu()
        self.act_toggle = QAction("Подключить")
        self.act_toggle.triggered.connect(self.home.toggle)
        m.addAction(self.act_toggle)
        modes = m.addMenu("Режим")
        grp = QActionGroup(m)
        self.mode_actions = {}
        for k, t, _h in MODES:
            a = QAction(t, checkable=True)
            a.setChecked(self.settings["routing_mode"] == k)
            a.triggered.connect(lambda _=False, key=k: self.set_mode(key))
            grp.addAction(a)
            modes.addAction(a)
            self.mode_actions[k] = a
        m.addSeparator()
        open_a = QAction("Открыть окно")
        open_a.triggered.connect(self.show_window)
        m.addAction(open_a)
        upd = QAction("Обновить подписки")
        upd.triggered.connect(lambda: self.servers.update_subs())
        m.addAction(upd)
        m.addSeparator()
        quit_a = QAction("Выход")
        quit_a.triggered.connect(self.quit)
        m.addAction(quit_a)
        self._tray_actions = [open_a, upd, quit_a]
        self.tray.setContextMenu(m)
        self.tray.activated.connect(
            lambda r: self.show_window() if r in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self.tray.setToolTip(f"{paths.APP_NAME} — отключено")
        self.tray.show()

    def set_mode(self, key: str) -> None:
        self.home.set_mode(key)

    def mode_changed(self) -> None:
        for k, a in self.mode_actions.items():
            a.setChecked(self.settings["routing_mode"] == k)

    def open_page(self, key: str) -> None:
        self.show_window()
        self.win.nav.setCurrentRow(self.page_index[key])

    def show_window(self) -> None:
        self.win.showNormal()
        self.win.raise_()
        self.win.activateWindow()

    # ------------------------------------------------------------------ events
    def on_event(self, name: str, data: dict) -> None:
        if name == "rules_changed":
            # lists changed: the core reloads rule files by itself; a restart happens only if the config
            # really changes (e.g. the first program sent through the VPN in «Мимо программы»)
            self.engine.reload_later()
            return
        if name == "voice_moved":
            self.notify(f"Сервер голоса не отвечал — звонок Discord перенесён на {data['node']} "
                        f"({data['delay']} мс)", "discord", ms=5000)
            return
        if name == "state":
            st = data["state"]
            icon = status_icon(COLORS.get(st, "#64748b"))
            self.tray.setIcon(icon)
            self.win.setWindowIcon(icon)
            self.tray.setToolTip(f"{paths.APP_NAME} — {STATE_TEXT.get(st, st)}")
            self.act_toggle.setText("Отключить" if st in ("running", "starting") else "Подключить")
            if st == "error":
                self.tray.showMessage(paths.APP_NAME, data.get("error", "")[:250], QSystemTrayIcon.Critical, 6000)
            if st in ("running", "stopped") and not self._quitting:
                self.settings["was_connected"] = st == "running"
                self.settings.save()
            for k, a in self.mode_actions.items():
                a.setChecked(self.settings["routing_mode"] == k)
            self.home.refresh()
        elif name == "health":
            self.home.ping = data["delay"]
        elif name == "traffic":
            self.home.set_traffic(data["up"], data["down"])
        elif name == "routes":
            self.home.set_routes(data)
        elif name == "app_update":
            self.update_info = data
            self.home.show_update(data)
            self.cores.show_app_info(data)
            if data.get("notify"):
                self.notify(f"Вышло обновление NexusVPN Pro: {data['name']}. Нажмите, чтобы открыть.", "cores")
        elif name == "app_update_auto":
            self.notify(f"Устанавливается обновление {data['name']}…", "cores")
            self.install_app_update(data, ask=False)
        elif name == "update_progress":
            t = data["total"] or 1
            self.status(f"Скачивание обновления: {data['got'] * 100 // t}% ({data['got'] // 1048576} МБ)")
        elif name == "cores_available":
            names = ", ".join(f"{k} {v}" for k, v in data["cores"].items())
            self.home.show_cores_update(data["cores"])
            self.notify(f"Доступны новые версии ядер: {names}. Откройте «Обновления».", "cores")
        elif name == "cores_updated":
            done = [m for m in data.get("messages", []) if "→" in m]
            if done:
                self.notify("Ядра обновлены: " + "; ".join(done), "cores")
            self.home.show_cores_update({})
        elif name == "learned":
            self.status(f"Обнаружена блокировка: {data['domain']} → теперь через VPN ({data['reason']})")
            if self.smart.isVisible():
                self.smart.reload()
        elif name == "learned_app":
            self.tray.showMessage(paths.APP_NAME, f"Программа {data['process']} теперь работает через VPN",
                                  QSystemTrayIcon.Information, 4000)
        elif name == "failover":
            self.tray.showMessage(paths.APP_NAME, f"Сервер не отвечал — переключено на {data['node']} "
                                              f"({data['delay']} мс)", QSystemTrayIcon.Warning, 5000)
        elif name == "core_crash":
            self.status(f"Ядро упало — перезапуск через {data['delay']} с")
        elif name == "all_down":
            self.tray.showMessage(paths.APP_NAME, "Ни один сервер не отвечает. Проверьте интернет или подписку.",
                                  QSystemTrayIcon.Critical, 6000)
        elif name == "nodes_changed":
            self.nodes_changed()
        elif name == "tunnel_error":
            self.tray.showMessage(paths.APP_NAME, f"{data['node']}: {data['error']}"[:250],
                                  QSystemTrayIcon.Warning, 6000)
            self.status(f"{data['node']}: {data['error']}")
        elif name == "status":
            self.status(data["text"])
            self.tray.showMessage(paths.APP_NAME, data["text"], QSystemTrayIcon.Information, 4000)
        elif name == "network_changed":
            self.status("Сеть изменилась — соединения обновлены")

    def nodes_changed(self, reload_engine: bool = False) -> None:
        self.servers.reload()
        self.home.reload_nodes()
        if reload_engine:
            run_bg(self.engine.reload)

    def status(self, text: str) -> None:
        self.win.statusBar().showMessage(str(text), 15000)
        if text:
            log.info(text)

    def relaunch_admin(self) -> None:
        if winutil.relaunch_as_admin(["--after-elevate"]):
            self.quit()

    def _routes_loop(self) -> None:
        from ..route_stats import RouteStats
        stats, started = RouteStats(), 0.0
        while not self._traffic_stop.wait(2):
            if self.engine.state != "running":
                continue
            if self.engine.started_at != started:
                started = self.engine.started_at
                stats.reset()
            try:
                snap = stats.update(self.engine.api().connections().get("connections") or [])
            except (OSError, ValueError):
                continue
            self.bridge.emit_event("routes", snap)

    def _traffic_loop(self) -> None:
        while not self._traffic_stop.is_set():
            if self.engine.state != "running":
                time.sleep(1)
                continue
            try:
                for t in self.engine.api().stream("/traffic", timeout=10):
                    self.bridge.emit_event("traffic", {"up": t.get("up", 0), "down": t.get("down", 0)})
                    if self._traffic_stop.is_set() or self.engine.state != "running":
                        break
            except (OSError, ValueError):
                time.sleep(2)
        self.bridge.emit_event("traffic", {"up": 0, "down": 0})

    # ------------------------------------------------------------------ exit
    def _emergency_cleanup(self) -> None:
        try:
            winutil.clear_system_proxy(int(self.settings["mixed_port"]))
            self.engine._kill_children()
        except Exception:  # noqa: BLE001 - best effort at interpreter exit
            pass

    def quit(self) -> None:
        self._quitting = True
        self._traffic_stop.set()
        self.service.stop()
        self.engine.shutdown()
        self.tray.hide()
        self.qapp.quit()


def _another_instance_running() -> bool:
    sock = QLocalSocket()
    sock.connectToServer(INSTANCE_KEY)
    if sock.waitForConnected(300):
        sock.write(b"show")
        sock.waitForBytesWritten(300)
        sock.disconnectFromServer()
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv
    if "--stop" in argv or "--cleanup" in argv:
        from .. import uninstall
        return uninstall.cli(argv)
    if winutil.IS_WIN:
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("NexusVPN.Pro")
        except (AttributeError, OSError):
            pass
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    qapp = QApplication(argv)
    qapp.setApplicationName(paths.APP_NAME)
    qapp.setQuitOnLastWindowClosed(False)
    if "--after-elevate" in argv:
        time.sleep(1.0)   # let the non-elevated instance release the single-instance pipe
    if _another_instance_running():
        return 0
    QLocalServer.removeServer(INSTANCE_KEY)
    server = QLocalServer()
    server.listen(INSTANCE_KEY)
    app = NexusApp(qapp, autostart="--autostart" in argv)

    def on_connection():
        conn = server.nextPendingConnection()
        conn.waitForReadyRead(500)
        if bytes(conn.readAll()) == b"quit":
            app.quit()
        else:
            app.show_window()
    server.newConnection.connect(on_connection)
    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.information(None, paths.APP_NAME, "Системный трей недоступен — окно будет всегда открыто.")
    return qapp.exec()
