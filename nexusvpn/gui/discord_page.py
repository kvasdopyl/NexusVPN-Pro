"""«Discord»: one switch, the server that carries the voice, live call status, what to check in Discord."""
from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QComboBox, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .. import winutil
from .common import run_bg, with_help
from .widgets import btn, page_title

GRADE = {2: "голос по UDP — без заиканий", 1: "голос внутри TCP — может заикаться", 0: "голос не передаёт"}


class DiscordPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Discord", "Текст, голос, видео и стримы Discord через VPN. Звонок держится на "
                                          "отдельном сервере и не обрывается, когда вы меняете другие настройки.",
                               "discord"))
        top = QHBoxLayout()
        self.toggle = QPushButton()
        self.toggle.setObjectName("toggle")
        self.toggle.setCheckable(True)
        self.toggle.setMinimumHeight(44)
        self.toggle.clicked.connect(self.set_enabled)
        top.addWidget(self.toggle, 1)
        v.addLayout(top)

        g = QGroupBox("Сервер для голоса")
        gv = QVBoxLayout(g)
        row = QHBoxLayout()
        self.node = QComboBox()
        self.node.activated.connect(self._node_chosen)
        row.addWidget(with_help(self.node, "discord_node", True), 1)
        self.reconnect = btn("Переподключить голос", self._reconnect,
                             tip="Discord переподключит звонок за 1–2 секунды через выбранный сервер")
        self.reconnect.setEnabled(False)
        row.addWidget(self.reconnect)
        gv.addLayout(row)
        self.no_udp = QLabel()
        self.no_udp.setWordWrap(True)
        self.no_udp.setStyleSheet("color:#fbbf24")
        gv.addWidget(self.no_udp)
        v.addWidget(g)

        self.status = QLabel()
        self.status.setObjectName("card")
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(70)
        v.addWidget(self.status)

        tips = QGroupBox("Если голос заикается или пропадает")
        tv = QVBoxLayout(tips)
        t = QLabel(
            "<ol>"
            "<li>Выберите выше сервер с пометкой <b>«голос по UDP»</b> (Hysteria2, TUIC, WireGuard, AmneziaWG, "
            "Shadowsocks). Через VLESS и Trojan голос идёт внутри TCP: одна потерянная посылка останавливает звук.</li>"
            "<li>В Discord: <b>Настройки → Голос и видео → Голос</b> → <b>«Показать расширенные настройки голоса»</b> "
            "→ выключите <b>«Качество обслуживания»</b>. С VPN этот переключатель может вызывать обрывы.</li>"
            "<li>У голосового канала оставьте регион <b>«Автоматический выбор»</b>.</li>"
            "<li>Если пропадает весь интернет, а не только Discord, — смените основной сервер на главной.</li>"
            "</ol>Программа сама следит за звонком: если сервер голоса перестал отвечать, звонок переедет на "
            "работающий сервер за пару секунд.")
        t.setWordWrap(True)
        tv.addWidget(t)
        v.addWidget(tips)
        v.addStretch()
        self.load()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(3000)

    # ---------- state ----------
    def _enabled(self) -> bool:
        from .routing import SERVICE_ENTRIES
        listed = set(self.app.engine.learner.db.user_entries("proxy"))
        return bool(self.app.settings["preset_discord"]) or set(SERVICE_ENTRIES["Discord"]) <= listed

    def load(self) -> None:
        on = self._enabled()
        self.toggle.blockSignals(True)
        self.toggle.setChecked(on)
        self.toggle.blockSignals(False)
        self.toggle.setText("✓  Discord через VPN — включено" if on else "Discord через VPN — выключено (нажмите, "
                                                                        "чтобы включить)")
        nodes = [n for n in self.app.store.enabled()]
        self.node.clear()
        self.node.addItem("Авто — самый быстрый сервер, который передаёт голос по UDP", "")
        for n in sorted(nodes, key=lambda n: -n.voice_grade):
            if n.voice_grade:
                self.node.addItem(f"{n.display}  —  {GRADE[n.voice_grade]}", n.tag)
        self.node.setCurrentIndex(max(0, self.node.findData(self.app.settings["discord_node"])))
        native = any(n.voice_grade == 2 for n in nodes)
        self.no_udp.setText("" if native or not nodes else
                            "Среди ваших серверов нет ни одного, который передаёт голос по UDP напрямую. Голос "
                            "пойдёт через VLESS/Trojan внутри TCP и при потерях будет заикаться. Попросите у "
                            "поставщика VPN сервер Hysteria2, TUIC или WireGuard.")
        self.no_udp.setVisible(bool(self.no_udp.text()))
        if self.app.settings["capture_mode"] == "system_proxy" and not winutil.is_admin():
            self.no_udp.setText("Режим «Системный прокси» без прав администратора: голос Discord не попадёт в VPN. "
                                "Запустите программу от администратора или выберите TUN на главной.")
            self.no_udp.setVisible(True)
        self.refresh()

    def set_enabled(self) -> None:
        """Called after the click: the button already shows the new state."""
        on = self.toggle.isChecked()
        from .routing import SERVICE_ENTRIES
        s = self.app.settings
        s["preset_discord"] = bool(on)
        s.save()
        custom = getattr(self.app, "custom", None)
        if custom is not None:
            if on:
                custom.change("proxy", add=SERVICE_ENTRIES["Discord"])
            else:
                custom.change("proxy", remove=SERVICE_ENTRIES["Discord"])
        self.toggle.setText("✓  Discord через VPN — включено" if on else
                            "Discord через VPN — выключено (нажмите, чтобы включить)")
        self.app.engine.reload_later()

    def _node_chosen(self, _i: int) -> None:
        run_bg(self.app.engine.select_voice_node, self.node.currentData() or "", False)
        self.app.status("Сервер для голоса выбран — новые звонки пойдут через него. Текущий звонок можно "
                        "перенести кнопкой «Переподключить голос».")

    def _reconnect(self) -> None:
        run_bg(self.app.engine.select_voice_node, self.node.currentData() or "", True)
        self.app.status("Голос переподключается…")

    # ---------- live ----------
    def refresh(self) -> None:
        if not self.isVisible():
            return
        if self.app.engine.state != "running":
            self.status.setText("<b>VPN выключен.</b> Включите его на главной.")
            self.reconnect.setEnabled(False)
            return
        run_bg(self.app.engine.discord_connections, done=self._render)

    def _render(self, conns: list) -> None:
        udp = [c for c in conns if (c.get("metadata") or {}).get("network") == "udp"]
        nodes = {n.tag: n for n in self.app.store.nodes}
        self.reconnect.setEnabled(bool(udp))
        if not conns:
            self.status.setText("<b>Discord сейчас не подключён.</b> Откройте Discord — здесь появится, через какой "
                                "сервер он работает.")
            return
        def server(c):
            chains = c.get("chains") or []
            return chains[0] if chains else "?"
        if udp:
            tag = server(udp[0])
            if tag == "direct":
                text = ("<b style='color:#fca5a5'>Звонок идёт мимо VPN.</b> Включите «Discord через VPN» выше.")
            else:
                g = nodes[tag].voice_grade if tag in nodes else 1
                color = "#4ade80" if g == 2 else "#fbbf24"
                text = (f"<b style='color:{color}'>🎙 Идёт звонок</b> · сервер <b>{tag}</b> · {GRADE.get(g, '')}")
        else:
            tags = sorted({server(c) for c in conns})
            text = f"<b>Discord подключён</b> (без звонка) · {', '.join(tags)}"
        self.status.setText(text + f"<br><span style='color:#94a3b8'>соединений Discord: {len(conns)}, "
                                   f"из них голосовых: {len(udp)}</span>")
