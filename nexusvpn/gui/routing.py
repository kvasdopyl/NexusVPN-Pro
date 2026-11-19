"""«Своя маршрутизация»: service switches + two lists (через VPN / напрямую) that apply immediately."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QFileDialog, QGridLayout, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QTableWidget,
                               QVBoxLayout, QWidget)

from ..presets import DISCORD_DOMAINS, TELEGRAM_CIDRS
from ..rules_text import KINDS_HELP, parse_text, to_text
from .common import HelpButton, run_bg, with_help
from .widgets import btn, page_title, set_row, table

SERVICES: dict[str, list[str]] = {
    "Discord": DISCORD_DOMAINS + ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"],
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "ggpht.com", "youtube-nocookie.com",
                "youtubei.googleapis.com"],
    "Telegram": ["telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "Telegram.exe",
                 *TELEGRAM_CIDRS],
    "ChatGPT": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"],
    "Claude": ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"],
    "Gemini": ["gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com"],
    "Instagram / Facebook": ["instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "fb.com",
                             "messenger.com"],
    "X / Twitter": ["x.com", "twitter.com", "twimg.com", "t.co"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net", "wa.me"],
}
KIND_TEXT = {"domain": "Сайт", "full": "Адрес сайта", "keyword": "Слово в адресе", "ip": "IP / подсеть",
             "process": "Программа"}
TITLES = {"proxy": "Через VPN", "direct": "Напрямую"}


def _entries(text_items: list[str]) -> list[tuple[str, str]]:
    return parse_text("\n".join(text_items))[0]


SERVICE_ENTRIES = {name: _entries(items) for name, items in SERVICES.items()}


class ManualDialog(QDialog):
    def __init__(self, parent, verdict: str):
        super().__init__(parent)
        self.setWindowTitle(f"Добавить в «{TITLES[verdict]}»")
        self.resize(560, 460)
        v = QVBoxLayout(self)
        hint = QLabel("Вставьте или впишите адреса сайтов, IP или имена программ — по одному на строку.\n"
                      "Ссылки вида https://site.com/… сами превратятся в site.com.")
        hint.setWordWrap(True)
        v.addWidget(hint)
        self.ed = QPlainTextEdit()
        self.ed.setPlaceholderText("например:\nkinopoisk.ru\nsteam.exe\n91.108.4.0/22")
        v.addWidget(self.ed, 1)
        more = QLabel(KINDS_HELP.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;"))
        more.setObjectName("muted")
        more.setStyleSheet("font-family: Consolas, monospace; font-size: 8.5pt;")
        v.addWidget(more)
        r = QHBoxLayout()
        r.addStretch()
        r.addWidget(btn("Отмена", self.reject))
        r.addWidget(btn("Добавить", self.accept, "primary"))
        v.addLayout(r)

    def entries(self) -> tuple[list[tuple[str, str]], list[str]]:
        return parse_text(self.ed.toPlainText())


class ListPanel(QGroupBox):
    """One list. Every button acts at once; buttons that need a selection are greyed out without one."""

    def __init__(self, page: "CustomRoutingPage", verdict: str):
        super().__init__()
        self.page, self.verdict = page, verdict
        other = "direct" if verdict == "proxy" else "proxy"
        v = QVBoxLayout(self)
        head = QHBoxLayout()
        self.title = QLabel()
        self.title.setObjectName("h2")
        head.addWidget(self.title)
        head.addWidget(HelpButton("custom_vpn" if verdict == "proxy" else "custom_direct"))
        head.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск…")
        self.search.setClearButtonEnabled(True)
        self.search.setMaximumWidth(220)
        self.search.textChanged.connect(self._filter)
        head.addWidget(self.search)
        v.addLayout(head)
        add = QHBoxLayout()
        add.addWidget(btn("+ Программа…", lambda: page.add_programs(verdict),
                          tip="Выбрать из программ, которые сейчас запущены"))
        add.addWidget(btn("+ Сайт…", lambda: page.add_sites(verdict),
                          tip="Выбрать из сайтов, которые вы открывали, или вписать адрес"))
        add.addWidget(btn("+ Вручную…", lambda: page.add_manual(verdict),
                          tip="Вписать или вставить сразу много адресов, IP или программ"))
        add.addStretch()
        v.addLayout(add)
        self.tbl = table(["Что", "Тип"], 0)
        self.tbl.setSelectionMode(QTableWidget.ExtendedSelection)
        self.tbl.itemSelectionChanged.connect(self._sel_changed)
        self.empty = QLabel("Список пуст — добавьте программу или сайт кнопками выше.")
        self.empty.setObjectName("muted")
        self.empty.setAlignment(Qt.AlignCenter)
        v.addWidget(self.tbl, 1)
        v.addWidget(self.empty)
        act = QHBoxLayout()
        self.b_remove = btn("Убрать", self.remove, tip="Убрать выбранное из списка")
        self.b_move = btn(f"→ В «{TITLES[other]}»", self.move, tip=f"Перенести выбранное в «{TITLES[other]}»")
        act.addWidget(self.b_remove)
        act.addWidget(self.b_move)
        act.addStretch()
        more = QPushButton("Ещё ▾")
        menu = QMenu(more)
        menu.addAction("Импорт из файла…", self.import_file)
        menu.addAction("Экспорт в файл…", self.export_file)
        menu.addSeparator()
        menu.addAction("Очистить весь список…", self.clear)
        more.setMenu(menu)
        act.addWidget(more)
        v.addLayout(act)
        self._sel_changed()

    def fill(self, entries: list[tuple[str, str]]) -> None:
        self.title.setText(f"{TITLES[self.verdict]}  ·  {len(entries)}")
        self.tbl.setSortingEnabled(False)
        self.tbl.setRowCount(len(entries))
        order = sorted(entries, key=lambda e: (e[0] != "process", e[1].lower()))
        for i, (kind, value) in enumerate(order):
            shown = to_text([(kind, value)])
            set_row(self.tbl, i, [shown, KIND_TEXT.get(kind, kind)], (kind, value))
        self.tbl.setSortingEnabled(True)
        self.tbl.setVisible(bool(entries))
        self.empty.setVisible(not entries)
        self._filter()
        self._sel_changed()

    def selected(self) -> list[tuple[str, str]]:
        rows = {i.row() for i in self.tbl.selectedIndexes()}
        out = []
        for r in sorted(rows):
            it = self.tbl.item(r, 0)
            if it and not self.tbl.isRowHidden(r):
                out.append(tuple(it.data(Qt.UserRole)))
        return out

    def _sel_changed(self) -> None:
        has = bool(self.tbl.selectedIndexes())
        self.b_remove.setEnabled(has)
        self.b_move.setEnabled(has)

    def _filter(self) -> None:
        q = self.search.text().strip().lower()
        for r in range(self.tbl.rowCount()):
            it = self.tbl.item(r, 0)
            self.tbl.setRowHidden(r, bool(q) and q not in (it.text().lower() if it else ""))

    def remove(self) -> None:
        self.page.change(self.verdict, remove=self.selected())

    def move(self) -> None:
        other = "direct" if self.verdict == "proxy" else "proxy"
        self.page.change(other, add=self.selected())

    def clear(self) -> None:
        cur = self.page.entries(self.verdict)
        if cur and QMessageBox.question(self, "Очистить", f"Убрать все записи ({len(cur)}) из «{TITLES[self.verdict]}»?") \
                == QMessageBox.Yes:
            self.page.change(self.verdict, remove=cur)

    def import_file(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "Импорт списка", "", "Текст (*.txt *.list *.lst *.csv);;Все (*)")
        if fn:
            with open(fn, encoding="utf-8", errors="replace") as fh:
                entries, errors = parse_text(fh.read())
            self.page.change(self.verdict, add=entries)
            if errors:
                QMessageBox.information(self, "Импорт", f"Добавлено: {len(entries)}. Не распознано строк: "
                                        f"{len(errors)}:\n" + "\n".join(errors[:12]))

    def export_file(self) -> None:
        fn, _ = QFileDialog.getSaveFileName(self, "Экспорт списка", f"nexusvpn-{self.verdict}.txt", "Текст (*.txt)")
        if fn:
            with open(fn, "w", encoding="utf-8") as fh:
                fh.write(to_text(self.page.entries(self.verdict)) + "\n")


class CustomRoutingPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Своя маршрутизация", "Что идёт через VPN, а что напрямую. Всё применяется сразу — "
                                                     "без перезапуска, звонки не обрываются.", "mode_custom"))
        svc = QGroupBox("Сервисы через VPN — нажмите, чтобы включить или выключить")
        g = QGridLayout(svc)
        self.svc_buttons: dict[str, QPushButton] = {}
        for i, name in enumerate(SERVICES):
            b = QPushButton(name)
            b.setObjectName("toggle")
            b.setCheckable(True)
            b.setMinimumHeight(38)
            b.setToolTip("Входит: " + ", ".join(SERVICES[name][:12]) + (" …" if len(SERVICES[name]) > 12 else ""))
            b.clicked.connect(lambda checked, n=name: self.toggle_service(n, checked))
            g.addWidget(b, i // 5, i % 5)
            self.svc_buttons[name] = b
        v.addWidget(svc)
        cols = QHBoxLayout()
        self.panels = {verdict: ListPanel(self, verdict) for verdict in ("proxy", "direct")}
        for p in self.panels.values():
            cols.addWidget(p, 1)
        v.addLayout(cols, 1)
        self.use_presets = QCheckBox("Вместе со своими списками использовать готовые базы (заблокированные сайты, "
                                     "YouTube, Telegram, Discord…)")
        self.use_presets.toggled.connect(self._presets_toggled)
        v.addWidget(with_help(self.use_presets, "custom_presets"))
        self.load()

    # ---------- data ----------
    @property
    def learner(self):
        return self.app.engine.learner

    def entries(self, verdict: str) -> list[tuple[str, str]]:
        return [tuple(e) for e in self.learner.db.user_entries(verdict)]

    def load(self) -> None:
        for verdict, panel in self.panels.items():
            panel.fill(self.entries(verdict))
        proxy = set(self.entries("proxy"))
        for name, b in self.svc_buttons.items():
            on = set(SERVICE_ENTRIES[name]) <= proxy
            b.setChecked(on)
            b.setText(f"✓  {name}" if on else name)
        self.use_presets.blockSignals(True)
        self.use_presets.setChecked(bool(self.app.settings["custom_use_presets"]))
        self.use_presets.blockSignals(False)

    def change(self, verdict: str, add: list | None = None, remove: list | None = None) -> None:
        """Add to one list (taking the entries out of the other one) and/or remove from it; apply now."""
        add, remove = [tuple(e) for e in add or []], {tuple(e) for e in remove or []}
        other = "direct" if verdict == "proxy" else "proxy"
        mine = [e for e in self.entries(verdict) if e not in remove]
        mine += [e for e in add if e not in mine]
        theirs = [e for e in self.entries(other) if e not in set(add)]
        self.learner.db.replace_user(verdict, mine)
        self.learner.db.replace_user(other, theirs)
        self.learner.apply()
        self.load()
        if add:
            names = ", ".join(to_text([e]) for e in add[:3]) + (" …" if len(add) > 3 else "")
            self.app.status(f"{names} — теперь {TITLES[verdict].lower()}")
        elif remove:
            self.app.status(f"Убрано из «{TITLES[verdict]}»: {len(remove)}")

    def toggle_service(self, name: str, on: bool) -> None:
        if on:
            self.change("proxy", add=SERVICE_ENTRIES[name])
        else:
            self.change("proxy", remove=SERVICE_ENTRIES[name])

    def _presets_toggled(self, on: bool) -> None:
        self.app.settings["custom_use_presets"] = bool(on)
        self.app.settings.save()
        run_bg(self.app.engine.reload)

    # ---------- adding ----------
    def add_programs(self, verdict: str) -> None:
        from .pages3 import ProcessPicker
        listed = {v.lower() for k, v in self.entries(verdict) if k == "process"}
        dlg = ProcessPicker(self, f"Добавить в «{TITLES[verdict]}»", listed)
        if dlg.exec() and dlg.chosen:
            self.change(verdict, add=[("process", n) for n in dlg.chosen])

    def add_sites(self, verdict: str) -> None:
        from .pages3 import SitePicker
        listed = {v for k, v in self.entries(verdict) if k == "domain"}
        dlg = SitePicker(self, self.app, f"Добавить в «{TITLES[verdict]}»", listed)
        if dlg.exec() and dlg.chosen:
            self.change(verdict, add=dlg.chosen)

    def add_manual(self, verdict: str) -> None:
        dlg = ManualDialog(self, verdict)
        if not dlg.exec():
            return
        entries, errors = dlg.entries()
        if entries:
            self.change(verdict, add=entries)
        if errors:
            QMessageBox.information(self, "Не всё распознано", "Эти строки пропущены:\n" + "\n".join(errors[:15]))
