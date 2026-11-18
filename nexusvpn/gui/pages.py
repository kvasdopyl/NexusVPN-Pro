"""Home page (power + three routing modes) and Servers page (subscriptions & single nodes)."""
from __future__ import annotations

import time
from datetime import datetime

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QStackedWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from .. import paths, tunnels, winutil
from ..links import from_text, to_text
from ..models import Node
from ..parsers import ParseError, parse_subscription
from ..subscription import Subscription, subs_from_settings, subs_to_settings
from .common import COLORS, STATE_TEXT, HelpButton, human_bytes, run_bg, with_help
from .widgets import btn, group_header, page_title, selected_data, set_row, table

MODES = [("global", "Всё через VPN", "mode_global"),
         ("custom", "Своя маршрутизация", "mode_custom"),
         ("smart", "Умная маршрутизация", "mode_smart")]
CAPTURE = [("tun", "TUN — весь трафик всех программ"), ("system_proxy", "Системный прокси (браузеры, Discord, Telegram)"),
           ("both", "TUN + системный прокси")]


# ======================================================================= Home
class HomePage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        s = app.settings
        v = QVBoxLayout(self)
        brand = QLabel(paths.APP_NAME)
        brand.setObjectName("brand")
        v.addWidget(brand)
        sub = QLabel("Профессиональный VPN-клиент с интеллектуальной самообучающейся маршрутизацией "
                     "(Smart Auto-Split Tunneling)")
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        v.addWidget(sub)
        self.banner = QWidget()
        self.banner.setObjectName("banner")
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(12, 8, 8, 8)
        self.banner_lbl = QLabel()
        self.banner_lbl.setWordWrap(True)
        bl.addWidget(self.banner_lbl, 1)
        self.banner_btn = QPushButton("Обновить")
        self.banner_btn.setObjectName("primary")
        self.banner_btn.clicked.connect(self._banner_clicked)
        bl.addWidget(self.banner_btn)
        self.banner.hide()
        v.addWidget(self.banner)
        self._app_update: dict = {}
        self._cores_update: dict = {}

        top = QHBoxLayout()
        self.connect_btn = QPushButton("ВКЛ")
        self.connect_btn.setObjectName("bigconnect")
        self.connect_btn.clicked.connect(self.toggle)
        top.addWidget(self.connect_btn, 0, Qt.AlignVCenter)
        top.addWidget(HelpButton("power"), 0, Qt.AlignTop)
        info = QVBoxLayout()
        self.state_lbl = QLabel()
        self.err_lbl = QLabel()
        self.err_lbl.setWordWrap(True)
        self.err_lbl.setStyleSheet("color:#fca5a5")
        self.detail_lbl = QLabel()
        self.detail_lbl.setObjectName("muted")
        self.detail_lbl.setWordWrap(True)
        for w in (self.state_lbl, self.detail_lbl, self.err_lbl):
            info.addWidget(w)
        info.addStretch()
        top.addSpacing(14)
        top.addLayout(info, 1)
        v.addLayout(top)

        g = QGroupBox("Режим маршрутизации")
        gl = QHBoxLayout(g)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        self.mode_buttons: dict[str, QPushButton] = {}
        for key, title, help_key in MODES:
            col = QVBoxLayout()
            b = QPushButton(title)
            b.setObjectName("mode")
            b.setCheckable(True)
            b.setMinimumHeight(54)
            b.clicked.connect(lambda _=False, k=key: self.set_mode(k))
            self.mode_group.addButton(b)
            self.mode_buttons[key] = b
            row = QHBoxLayout()
            row.addWidget(b, 1)
            row.addWidget(HelpButton(help_key), 0, Qt.AlignTop)
            col.addLayout(row)
            gl.addLayout(col, 1)
        v.addWidget(g)

        g2 = QGroupBox("Подключение")
        f = QFormLayout(g2)
        self.capture = QComboBox()
        for k, t in CAPTURE:
            self.capture.addItem(t, k)
        self.capture.setCurrentIndex(max(0, self.capture.findData(s["capture_mode"])))
        self.capture.currentIndexChanged.connect(self._capture_changed)
        self.node = QComboBox()
        self.node.currentIndexChanged.connect(self._node_changed)
        f.addRow("Перехват трафика:", with_help(self.capture, "capture", True))
        f.addRow("Сервер:", with_help(self.node, "server", True))
        v.addWidget(g2)

        cards = QGridLayout()
        self.c_speed, self.c_ping, self.c_learn, self.c_uptime = (QLabel() for _ in range(4))
        for i, c in enumerate((self.c_speed, self.c_ping, self.c_learn, self.c_uptime)):
            c.setObjectName("card")
            c.setMinimumHeight(66)
            cards.addWidget(c, i // 2, i % 2)
        self.c_routes = QLabel()
        self.c_routes.setObjectName("card")
        self.c_routes.setWordWrap(True)
        self.c_routes.setMinimumHeight(66)
        cards.addWidget(self.c_routes, 2, 0, 1, 2)
        v.addLayout(cards)
        self.routes: dict = {}
        v.addWidget(with_help(QLabel(""), "cards"))
        v.addStretch()
        self.up = self.down = 0
        self.ping = None
        self.sync_mode()
        self.reload_nodes()
        self.refresh()
        t = QTimer(self)
        t.timeout.connect(self.refresh)
        t.start(1000)

    def sync_mode(self) -> None:
        mode = self.app.settings["routing_mode"]
        if mode in self.mode_buttons:
            self.mode_buttons[mode].setChecked(True)

    def set_mode(self, key: str) -> None:
        if self.app.settings["routing_mode"] == key:
            self.sync_mode()
            return
        self.app.settings["routing_mode"] = key
        self.app.settings.save()
        self.sync_mode()
        self.app.mode_changed()
        if key == "custom" and not self.app.engine.learner.db.user_entries("proxy"):
            QMessageBox.information(self, "Своя маршрутизация",
                                    "Список «Через VPN» пока пуст — откроется страница, где можно вписать "
                                    "домены, IP и программы (можно сразу пачкой).")
            self.app.open_page("custom")
        run_bg(self.app.engine.reload)

    def reload_nodes(self) -> None:
        self.node.blockSignals(True)
        self.node.clear()
        self.node.addItem("⚡ Авто — самый быстрый", "")
        for n in self.app.store.enabled():
            self.node.addItem(n.display, n.tag)
        self.node.setCurrentIndex(max(0, self.node.findData(self.app.settings["active_node"])))
        self.node.blockSignals(False)

    def toggle(self) -> None:
        eng = self.app.engine
        if eng.state in ("running", "starting"):
            run_bg(eng.stop)
        else:
            if not self.app.store.enabled():
                QMessageBox.information(self, "Нет серверов", "Добавьте подписку или сервер на странице «Серверы».")
                self.app.open_page("servers")
                return
            run_bg(eng.start)

    def _capture_changed(self) -> None:
        val = self.capture.currentData()
        self.app.settings["capture_mode"] = val
        self.app.settings.save()
        if val in ("tun", "both") and not winutil.is_admin():
            if QMessageBox.question(self, "Нужны права администратора",
                                    "Режим TUN работает только с правами администратора. Перезапустить "
                                    "программу с запросом прав?") == QMessageBox.Yes:
                self.app.relaunch_admin()
            return
        run_bg(self.app.engine.reload)

    def _node_changed(self) -> None:
        run_bg(self.app.engine.select_node, self.node.currentData() or "")

    def show_update(self, info: dict) -> None:
        self._app_update = info if info.get("newer") else {}
        self._render_banner()

    def show_cores_update(self, cores: dict) -> None:
        self._cores_update = cores
        self._render_banner()

    def _render_banner(self) -> None:
        parts = []
        if self._app_update:
            parts.append(f"Вышла новая версия программы: <b>{self._app_update['name']}</b>")
        if self._cores_update:
            parts.append("Новые версии ядер: " + ", ".join(f"{k} {v}" for k, v in self._cores_update.items()))
        self.banner_lbl.setText("<br>".join(parts))
        self.banner_btn.setText("Обновить программу" if self._app_update else "Открыть «Обновления»")
        self.banner.setVisible(bool(parts))

    def _banner_clicked(self) -> None:
        if self._app_update:
            self.app.install_app_update(self._app_update)
        else:
            self.app.open_page("cores")

    def set_traffic(self, up: int, down: int) -> None:
        self.up, self.down = up, down

    def set_routes(self, snap: dict) -> None:
        self.routes = snap

    def refresh(self) -> None:
        eng = self.app.engine
        st = eng.state
        self.state_lbl.setText(STATE_TEXT.get(st, st))
        self.state_lbl.setStyleSheet(f"font-size:16pt;font-weight:700;color:{COLORS.get(st)}")
        self.connect_btn.setText("ВЫКЛ" if st in ("running", "starting") else "ВКЛ")
        self.connect_btn.setStyleSheet(
            f"background:{'#15803d' if st == 'running' else '#1e293b'};border:3px solid {COLORS.get(st)}")
        err = eng.error if st == "error" else ""
        if eng.tunnel_errors and st == "running":
            err = "Не подключились: " + "; ".join(f"{k}: {v}" for k, v in eng.tunnel_errors.items())
        self.err_lbl.setText(err)
        mode = {k: t for k, t, _ in MODES}.get(self.app.settings["routing_mode"], "")
        cap = dict(CAPTURE).get(self.app.settings["capture_mode"], "")
        self.detail_lbl.setText(f"{mode} · {cap}")
        ping = "—" if self.ping is None else ("нет связи" if self.ping < 0 else f"{self.ping} мс")
        self.c_ping.setText(f"<b>Задержка через VPN</b><br>{ping}")
        r = self.routes if st == "running" else {}
        self.c_speed.setText(
            f"<b>Скорость</b> &nbsp;↑ {human_bytes(self.up)}/с &nbsp; ↓ {human_bytes(self.down)}/с<br>"
            f"<span style='color:#38bdf8'>через VPN: {human_bytes(r.get('vpn_bytes', 0))}</span> &nbsp;·&nbsp; "
            f"<span style='color:#4ade80'>напрямую: {human_bytes(r.get('direct_bytes', 0))}</span>")
        db = eng.learner.db
        self.c_learn.setText(f"<b>Изучено умной маршрутизацией</b><br>в VPN: {len(db.values('domain', 'proxy', 'auto'))}"
                             f" · напрямую: {len(db.values('domain', 'direct', 'auto'))}"
                             f" · проверок за сеанс: {eng.learner.stats['probes']}")
        now = r.get("vpn_now") or []
        top = ", ".join(f"{name} ({human_bytes(b)})" for name, b in r.get("top_vpn", []))
        self.c_routes.setText(
            f"<b>Сейчас через VPN</b>: {r.get('vpn_conns', 0)} соединений · напрямую: {r.get('direct_conns', 0)}<br>"
            f"<span style='color:#38bdf8'>{', '.join(now[:12]) + (' …' if len(now) > 12 else '') or '—'}</span>"
            + (f"<br><span style='color:#94a3b8'>Больше всего трафика через VPN: {top}</span>" if top else ""))
        up = int(time.time() - eng.started_at) if st == "running" and eng.started_at else 0
        self.c_uptime.setText(f"<b>Время работы</b><br>{up // 86400}д {up % 86400 // 3600:02d}:"
                              f"{up % 3600 // 60:02d}:{up % 60:02d}")


# ======================================================================= dialogs
class SubDialog(QDialog):
    def __init__(self, parent, sub: Subscription | None = None):
        super().__init__(parent)
        self.setWindowTitle("Изменить подписку" if sub else "Новая подписка")
        self.setMinimumWidth(600)
        f = QFormLayout(self)
        self.name = QLineEdit(sub.name if sub else "Основная")
        self.url = QLineEdit(sub.url if sub else "")
        self.url.setPlaceholderText("https://…")
        self.ua = QComboBox()
        self.ua.setEditable(True)
        self.ua.addItems(["v2rayN/7.0", "sing-box/1.14.4", "clash-verge/2.0", "Happ/2.0", "NexusVPN/2.0"])
        self.ua.setCurrentText(sub.user_agent if sub else "v2rayN/7.0")
        self.enabled = QCheckBox("Подписка включена")
        self.enabled.setChecked(sub.enabled if sub else True)
        self.insecure = QCheckBox("Разрешить самоподписанный сертификат панели (3x-ui, Marzban)")
        self.insecure.setChecked(sub.insecure if sub else True)
        self.via_proxy = QCheckBox("Обновлять сначала через VPN")
        self.via_proxy.setChecked(sub.via_proxy if sub else False)
        self.interval = QSpinBox()
        self.interval.setRange(0, 720)
        self.interval.setSuffix(" ч (0 = как указал сервер)")
        self.interval.setValue(sub.interval_hours if sub else 0)
        f.addRow("Название:", self.name)
        f.addRow("Ссылка:", self.url)
        f.addRow("User-Agent:", with_help(self.ua, "Некоторые панели отдают разный формат в зависимости от "
                                                   "User-Agent. Если серверов 0 — попробуйте другой.", True))
        f.addRow("Интервал:", self.interval)
        f.addRow(self.enabled)
        f.addRow(self.insecure)
        f.addRow(self.via_proxy)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def apply_to(self, sub: Subscription) -> Subscription:
        sub.name = self.name.text().strip() or "Подписка"
        sub.url = self.url.text().strip()
        sub.user_agent = self.ua.currentText().strip()
        sub.enabled = self.enabled.isChecked()
        sub.insecure = self.insecure.isChecked()
        sub.via_proxy = self.via_proxy.isChecked()
        sub.interval_hours = self.interval.value()
        return sub


class NodeDialog(QDialog):
    """Add or edit one server: link/config text, or the IKEv2 form."""

    def __init__(self, parent, node: Node | None = None):
        super().__init__(parent)
        self.node = node
        self.result_nodes: list[Node] = []
        self.setWindowTitle("Изменить сервер" if node else "Добавить сервер")
        self.setMinimumSize(680, 520)
        v = QVBoxLayout(self)
        f = QFormLayout()
        self.kind = QComboBox()
        self.kind.addItem("Ссылка / WireGuard / AmneziaWG / OpenVPN", "text")
        self.kind.addItem("IKEv2 (встроенный в Windows)", "ikev2")
        self.name = QLineEdit(node.remark or node.tag if node else "")
        self.name.setPlaceholderText("Название (необязательно)")
        f.addRow("Тип:", with_help(self.kind, "nodes", True))
        f.addRow("Название:", self.name)
        v.addLayout(f)
        self.stack = QStackedWidget()
        # --- text page
        tp = QWidget()
        tv = QVBoxLayout(tp)
        tv.setContentsMargins(0, 0, 0, 0)
        tv.addWidget(group_header("Ссылка или конфигурация", "node_text"))
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText("vless://…   или   [Interface] …   или содержимое .ovpn")
        self.text.setStyleSheet("font-family: Consolas, monospace;")
        tv.addWidget(self.text, 1)
        row = QHBoxLayout()
        row.addWidget(btn("Открыть файл…", self.open_file))
        row.addWidget(btn("Вставить из буфера", lambda: self.text.setPlainText(QApplication.clipboard().text())))
        row.addStretch()
        tv.addLayout(row)
        af = QFormLayout()
        self.user = QLineEdit(node.uuid if node and node.type == "openvpn" else "")
        self.pw = QLineEdit(node.password if node and node.type == "openvpn" else "")
        self.pw.setEchoMode(QLineEdit.Password)
        af.addRow("Логин (OpenVPN):", with_help(self.user, "node_auth", True))
        af.addRow("Пароль (OpenVPN):", self.pw)
        tv.addLayout(af)
        self.stack.addWidget(tp)
        # --- ikev2 page
        ip = QWidget()
        iv = QFormLayout(ip)
        iv.addRow(group_header("IKEv2", "ikev2"))
        self.ike_server = QLineEdit()
        self.ike_user = QLineEdit()
        self.ike_pw = QLineEdit()
        self.ike_pw.setEchoMode(QLineEdit.Password)
        self.ike_auth = QComboBox()
        self.ike_auth.addItem("EAP-MSCHAPv2 (логин и пароль)", "eap")
        self.ike_auth.addItem("Сертификат компьютера", "cert")
        self.ike_strong = QCheckBox("Усиленное шифрование (AES-256-GCM / SHA-256 / DH14)")
        self.ike_strong.setChecked(True)
        iv.addRow("Сервер:", self.ike_server)
        iv.addRow("Проверка подлинности:", self.ike_auth)
        iv.addRow("Логин:", self.ike_user)
        iv.addRow("Пароль:", self.ike_pw)
        iv.addRow(self.ike_strong)
        iv.addRow(btn("Импорт сертификата CA…", self.import_ca))
        self.stack.addWidget(ip)
        v.addWidget(self.stack, 1)
        self.kind.currentIndexChanged.connect(lambda i: self.stack.setCurrentIndex(i))
        if node and node.group != "Ручные" and node.group:
            warn = QLabel(f"Сервер из подписки «{node.group}»: после сохранения он станет ручным, "
                          f"иначе обновление подписки отменит правку.")
            warn.setWordWrap(True)
            warn.setStyleSheet("color:#fbbf24")
            v.addWidget(warn)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.save)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)
        if node:
            if node.type == "ikev2":
                self.kind.setCurrentIndex(1)
                self.ike_server.setText(node.server)
                self.ike_user.setText(node.uuid)
                self.ike_pw.setText(node.password)
                self.ike_auth.setCurrentIndex(max(0, self.ike_auth.findData(node.extra.get("auth", "eap"))))
                self.ike_strong.setChecked(bool(node.extra.get("strong", True)))
            else:
                try:
                    self.text.setPlainText(to_text(node))
                except ValueError as e:
                    self.text.setPlainText(f"# {e}")

    def open_file(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "Файл конфигурации", "",
                                            "Конфиги (*.conf *.ovpn *.txt *.json *.yaml);;Все (*)")
        if fn:
            with open(fn, encoding="utf-8", errors="replace") as fh:
                self.text.setPlainText(fh.read())
            if not self.name.text():
                import os
                self.name.setText(os.path.splitext(os.path.basename(fn))[0])

    def import_ca(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "Корневой сертификат", "", "Сертификаты (*.crt *.cer *.pem *.der)")
        if not fn:
            return
        if QMessageBox.question(self, "Сертификат", "Добавить этот сертификат в доверенные корневые Windows? "
                                                    "Делайте это только для сертификата вашего VPN-провайдера.") \
                != QMessageBox.Yes:
            return
        ok, msg = tunnels.import_ca_certificate(fn)
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Сертификат", msg or "Готово")

    def save(self) -> None:
        name = self.name.text().strip()
        try:
            if self.kind.currentData() == "ikev2":
                server = self.ike_server.text().strip()
                if not server:
                    raise ParseError("Укажите сервер")
                n = Node(type="ikev2", server=server, port=500, uuid=self.ike_user.text().strip(),
                         password=self.ike_pw.text(), remark=name or f"IKEv2 {server}")
                n.extra = {"auth": self.ike_auth.currentData(), "strong": self.ike_strong.isChecked()}
                nodes = [n]
            else:
                text = self.text.toPlainText().strip()
                if not text:
                    raise ParseError("Вставьте ссылку или конфигурацию")
                lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
                if not self.node and len(lines) > 1 and all("://" in ln for ln in lines):
                    nodes, _w = parse_subscription(text)         # several links at once
                elif not self.node and text.startswith("vpn://"):
                    nodes, _w = parse_subscription(text)
                else:
                    nodes = [from_text(text, name, self.user.text().strip(), self.pw.text())]
                if not nodes:
                    raise ParseError("Ничего не найдено")
                for n in nodes:
                    if n.type == "openvpn" and self.user.text().strip():
                        n.uuid, n.password = self.user.text().strip(), self.pw.text()
        except (ParseError, ValueError, KeyError) as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return
        self.result_nodes = nodes
        self.accept()


# ======================================================================= Servers
class ServersPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.delays: dict[str, int] = {}
        v = QVBoxLayout(self)
        v.addWidget(page_title("Серверы и подписки"))

        g = QGroupBox()
        gv = QVBoxLayout(g)
        gv.addWidget(group_header("Подписки", "subs"))
        self.subs = table(["Название", "Вкл", "Серверов", "Трафик", "Истекает", "Обновлено", "Статус"], 0)
        self.subs.setMaximumHeight(150)
        self.subs.doubleClicked.connect(lambda *_: self.edit_sub())
        gv.addWidget(self.subs)
        row = QHBoxLayout()
        row.addWidget(btn("+ Добавить", self.add_sub, "primary"))
        row.addWidget(btn("Изменить", self.edit_sub))
        row.addWidget(btn("Удалить", self.del_sub))
        row.addStretch()
        row.addWidget(btn("Обновить выбранную", lambda: self.update_subs(selected_data(self.subs) or None)))
        row.addWidget(btn("Обновить все", lambda: self.update_subs()))
        gv.addLayout(row)
        v.addWidget(g)

        g2 = QGroupBox()
        g2v = QVBoxLayout(g2)
        hdr = QHBoxLayout()
        hdr.addWidget(group_header("Серверы", "nodes"))
        hdr.addWidget(QLabel("UDP:"))
        hdr.addWidget(HelpButton("udp"))
        hdr.addStretch()
        g2v.addLayout(hdr)
        self.nodes = table(["Вкл", "Название", "Протокол", "Транспорт", "Адрес", "UDP / голос", "Задержка", "Группа"], 1)
        self.nodes.itemChanged.connect(self._toggled)
        self.nodes.doubleClicked.connect(lambda *_: self.edit_node())
        g2v.addWidget(self.nodes)
        r2 = QHBoxLayout()
        r2.addWidget(btn("+ Добавить сервер", self.add_node, "primary"))
        r2.addWidget(btn("Изменить", self.edit_node))
        r2.addWidget(btn("Удалить", self.del_nodes))
        r2.addWidget(btn("Импорт файла…", self.import_file,
                         tip="WireGuard/AmneziaWG .conf, OpenVPN .ovpn, Clash .yaml, sing-box .json, .txt"))
        r2.addStretch()
        g2v.addLayout(r2)
        r3 = QHBoxLayout()
        r3.addWidget(btn("Проверить задержку", self.test_delays))
        r3.addWidget(btn("Использовать выбранный", self.use_selected))
        r3.addWidget(btn("Копировать ссылку", self.copy_link))
        r3.addStretch()
        g2v.addLayout(r3)
        v.addWidget(g2, 1)
        self.reload()

    # ---------- subscriptions ----------
    def _subs(self) -> list[Subscription]:
        return subs_from_settings(self.app.settings)

    def reload(self) -> None:
        subs = self._subs()
        self.subs.setSortingEnabled(False)
        self.subs.setRowCount(len(subs))
        for i, s in enumerate(subs):
            used = human_bytes(s.upload + s.download) + (f" / {human_bytes(s.total)}" if s.total else "")
            exp = datetime.fromtimestamp(s.expire).strftime("%d.%m.%Y") if s.expire else "∞"
            upd = datetime.fromtimestamp(s.updated_at).strftime("%d.%m %H:%M") if s.updated_at else "—"
            set_row(self.subs, i, [s.name, "да" if s.enabled else "нет", s.count, used, exp, upd,
                                   s.last_error or "OK"], s.name)
        self.subs.setSortingEnabled(True)

        self.nodes.blockSignals(True)
        self.nodes.setSortingEnabled(False)
        ns = self.app.store.nodes
        self.nodes.setRowCount(len(ns))
        for i, n in enumerate(ns):
            d = self.delays.get(n.tag)
            dtxt = "" if d is None else ("✖" if d < 0 else d)
            udp = "да" if n.supports_udp else "нет"
            if n.helper:
                udp += f" ({n.helper})"
            transport = n.transport or {"hysteria2": "quic", "tuic": "quic", "wireguard": "udp",
                                        "amneziawg": f"awg v{(n.extra.get('awg') or {}).get('version', 1)}",
                                        "ikev2": "ipsec"}.get(n.type, "tcp")
            set_row(self.nodes, i, ["", n.remark or n.tag, n.type, transport, f"{n.server}:{n.port}",
                                    udp, dtxt, n.group], n.tag)
            it = self.nodes.item(i, 0)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if n.enabled else Qt.Unchecked)
        self.nodes.setSortingEnabled(True)
        self.nodes.blockSignals(False)

    def add_sub(self) -> None:
        d = SubDialog(self)
        if d.exec() != QDialog.Accepted:
            return
        sub = d.apply_to(Subscription(name="", url=""))
        if not sub.url.startswith(("http://", "https://")):
            QMessageBox.warning(self, "Ошибка", "Ссылка должна начинаться с http:// или https://")
            return
        subs = self._subs()
        if any(s.name == sub.name for s in subs):
            sub.name += f" {len(subs) + 1}"
        subs_to_settings(self.app.settings, subs + [sub])
        self.update_subs([sub.name])

    def edit_sub(self) -> None:
        names = selected_data(self.subs)
        if not names:
            QMessageBox.information(self, "Подписки", "Выберите подписку в таблице.")
            return
        subs = self._subs()
        old = next(s for s in subs if s.name == names[0])
        old_name, old_url, old_en = old.name, old.url, old.enabled
        d = SubDialog(self, old)
        if d.exec() != QDialog.Accepted:
            return
        d.apply_to(old)
        if old.name != old_name and any(s.name == old.name for s in subs if s is not old):
            QMessageBox.warning(self, "Ошибка", "Подписка с таким названием уже есть")
            return
        if old.name != old_name:
            for n in self.app.store.nodes:
                if n.group == old_name:
                    n.group = old.name
            self.app.store.save()
        subs_to_settings(self.app.settings, subs)
        if not old.enabled and old_en:
            self.app.store.remove_group(old.name)
            self.app.nodes_changed(reload_engine=True)
        elif old.url != old_url or (old.enabled and not old_en):
            self.update_subs([old.name])
        else:
            self.reload()

    def del_sub(self) -> None:
        names = selected_data(self.subs)
        if not names or QMessageBox.question(self, "Удалить", f"Удалить подписку «{names[0]}» и её серверы?") \
                != QMessageBox.Yes:
            return
        subs_to_settings(self.app.settings, [s for s in self._subs() if s.name != names[0]])
        self.app.store.remove_group(names[0])
        self.app.nodes_changed(reload_engine=True)

    def update_subs(self, names=None) -> None:
        self.app.status("Обновление подписок…")
        run_bg(self.app.service.update_subscriptions, False, names or None,
               done=lambda msgs: (self.app.status("; ".join(msgs) or "Нет подписок"), self.app.nodes_changed()),
               failed=lambda e: self.app.status(f"Ошибка: {e}"))

    # ---------- nodes ----------
    def _toggled(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        n = self.app.store.by_tag(item.data(Qt.UserRole))
        if n:
            n.enabled = item.checkState() == Qt.Checked
            self.app.store.save()
            self.app.nodes_changed(reload_engine=True)

    def add_node(self) -> None:
        d = NodeDialog(self)
        if d.exec() == QDialog.Accepted and d.result_nodes:
            self.app.store.add_nodes(d.result_nodes)
            self.app.nodes_changed(reload_engine=True)
            self.app.status(f"Добавлено серверов: {len(d.result_nodes)}")

    def edit_node(self) -> None:
        tags = selected_data(self.nodes)
        if not tags:
            QMessageBox.information(self, "Серверы", "Выберите сервер в таблице.")
            return
        n = self.app.store.by_tag(tags[0])
        if not n:
            return
        d = NodeDialog(self, n)
        if d.exec() == QDialog.Accepted and d.result_nodes:
            new = self.app.store.update_node(n.tag, d.result_nodes[0])
            if self.app.settings["active_node"] == n.tag:
                self.app.settings["active_node"] = new.tag
                self.app.settings.save()
            self.app.nodes_changed(reload_engine=True)
            self.app.status(f"Сервер «{new.tag}» сохранён")

    def copy_link(self) -> None:
        out = []
        for tag in selected_data(self.nodes):
            n = self.app.store.by_tag(tag)
            if n:
                try:
                    out.append(to_text(n))
                except ValueError as e:
                    self.app.status(str(e))
        if out:
            QApplication.clipboard().setText("\n".join(out))
            self.app.status(f"Скопировано: {len(out)}")

    def import_file(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "Импорт", "",
                                            "Конфиги (*.conf *.ovpn *.yaml *.yml *.json *.txt);;Все (*)")
        if not fn:
            return
        import os
        name = os.path.splitext(os.path.basename(fn))[0]
        try:
            with open(fn, encoding="utf-8", errors="replace") as fh:
                nodes, warns = parse_subscription(fh.read(), group=name)
        except (OSError, ParseError) as e:
            QMessageBox.warning(self, "Импорт", f"Не удалось распознать: {e}")
            return
        for n in nodes:
            if n.type in ("openvpn", "wireguard", "amneziawg") and n.remark in ("", "OpenVPN", "WireGuard"):
                n.remark = name
        self.app.store.add_nodes(nodes)
        self.app.nodes_changed(reload_engine=bool(nodes))
        need = [n for n in nodes if n.type == "openvpn" and n.extra.get("needs_auth") and not n.uuid]
        msg = f"Добавлено серверов: {len(nodes)}"
        if need:
            msg += "\n\nДля OpenVPN нужен логин и пароль: выберите сервер → «Изменить»."
        if warns:
            msg += "\n\nПропущено:\n" + "\n".join(warns[:10])
        QMessageBox.information(self, "Импорт", msg)

    def del_nodes(self) -> None:
        tags = set(selected_data(self.nodes))
        if tags and QMessageBox.question(self, "Удалить", f"Удалить серверов: {len(tags)}?") == QMessageBox.Yes:
            for t in tags:
                n = self.app.store.by_tag(t)
                if n and n.type == "ikev2":
                    tunnels.IKEv2Tunnel(n, self.app.settings).remove_profile()
            self.app.store.remove(tags)
            self.app.nodes_changed(reload_engine=True)

    def test_delays(self) -> None:
        eng = self.app.engine
        if eng.state != "running":
            QMessageBox.information(self, "Проверка", "Проверка задержки выполняется через ядро — сначала "
                                                      "подключитесь.")
            return
        self.app.status("Проверка задержки…")
        url = self.app.settings["health_check_url"]

        def work():
            api = eng.api()
            res = api.group_delay("auto", url, 6000)
            for n in self.app.store.enabled():
                if n.tag not in res:
                    res[n.tag] = api.delay(n.tag, url, 6000)
            # WireGuard/AmneziaWG/OpenVPN spend the first probe on the handshake: retry failures once
            for tag, d in list(res.items()):
                if not (isinstance(d, int) and d > 0):
                    res[tag] = api.delay(tag, url, 8000)
            return res

        def done(res):
            self.delays = {k: (v if isinstance(v, int) and v > 0 else -1) for k, v in res.items()}
            self.reload()
            ok = sum(1 for v in self.delays.values() if v > 0)
            self.app.status(f"Работает {ok} из {len(self.delays)}")
        run_bg(work, done=done, failed=self.app.status)

    def use_selected(self) -> None:
        tags = selected_data(self.nodes)
        if tags:
            run_bg(self.app.engine.select_node, tags[0])
            self.app.home.reload_nodes()
            self.app.status(f"Выбран сервер: {tags[0]}")
