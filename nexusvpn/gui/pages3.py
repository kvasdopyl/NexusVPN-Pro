"""Pickers for running programs and visited sites, the «Игры» page, wheel protection for inputs."""
from __future__ import annotations

import os
from pathlib import PureWindowsPath

import psutil
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import (QAbstractScrollArea, QAbstractSpinBox, QApplication, QComboBox, QDialog,
                               QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox,
                               QTableWidget, QVBoxLayout, QWidget)

from ..learner import base_domain
from ..presets import GAME_MODES, GAME_PRESETS
from .common import HelpButton, run_bg
from .widgets import btn, page_title, selected_data, set_row, table

SKIP_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\systemapps\\")
SKIP_NAMES = {"nexusvpn pro.exe", "sing-box.exe", "xray.exe", "mihomo.exe", "openvpn.exe", "svchost.exe",
              "conhost.exe", "dllhost.exe", "runtimebroker.exe", "searchhost.exe", "taskhostw.exe"}


# ----------------------------------------------------------------------- wheel protection
class NoWheelUntilClicked(QObject):
    """Spin boxes and drop-downs ignore the mouse wheel until the user clicks them, so scrolling a
    page never changes a value by accident. The wheel scrolls the page instead."""

    def eventFilter(self, obj, event):
        if not isinstance(obj, (QAbstractSpinBox, QComboBox)):
            return False
        t = event.type()
        if t == QEvent.Polish:
            obj.setFocusPolicy(Qt.StrongFocus)
        elif t == QEvent.Wheel and not obj.hasFocus():
            w = obj.parentWidget()
            while w is not None and not isinstance(w, QAbstractScrollArea):
                w = w.parentWidget()
            if w is not None:
                QApplication.sendEvent(w.verticalScrollBar(), event)
            return True
        return False


# ----------------------------------------------------------------------- running programs
def running_programs() -> list[dict]:
    """One row per executable: name, path, number of network connections."""
    conns: dict[int, int] = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid:
                conns[c.pid] = conns.get(c.pid, 0) + 1
    except (psutil.Error, OSError):
        pass
    out: dict[str, dict] = {}
    for p in psutil.process_iter(["pid", "name", "exe"]):
        name, exe = p.info["name"] or "", p.info["exe"] or ""
        if not exe or name.lower() in SKIP_NAMES or any(d in exe.lower() for d in SKIP_DIRS):
            continue
        row = out.setdefault(exe.lower(), {"name": name, "exe": exe, "net": 0})
        row["net"] += conns.get(p.info["pid"], 0)
    return sorted(out.values(), key=lambda r: (-min(r["net"], 1), r["name"].lower()))


class ProcessPicker(QDialog):
    """Choose running programs. on_pick(verdict, [exe paths]) is called for «Через VPN» / «Напрямую»;
    with single=True it is a plain chooser that returns one path via .chosen."""

    def __init__(self, parent, on_pick=None, single: bool = False):
        super().__init__(parent)
        self.on_pick, self.chosen = on_pick, ""
        self.setWindowTitle("Запущенные программы")
        self.resize(900, 560)
        v = QVBoxLayout(self)
        hint = QLabel("Отметьте программы (можно несколько, с Ctrl). Сверху — те, что сейчас выходят в сеть.")
        hint.setObjectName("muted")
        v.addWidget(hint)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Поиск по названию или пути…")
        self.filter.textChanged.connect(self._apply_filter)
        v.addWidget(self.filter)
        self.tbl = table(["Программа", "Соединений", "Путь"], 2)
        self.tbl.setSelectionMode(QTableWidget.SingleSelection if single else QTableWidget.ExtendedSelection)
        self.tbl.doubleClicked.connect(lambda _i: self._pick("pick" if single else "proxy"))
        v.addWidget(self.tbl, 1)
        r = QHBoxLayout()
        if single:
            r.addWidget(btn("Выбрать", lambda: self._pick("pick"), "primary"))
        else:
            r.addWidget(btn("→ Через VPN", lambda: self._pick("proxy"), "primary"))
            r.addWidget(btn("→ Напрямую", lambda: self._pick("direct")))
        r.addWidget(btn("Обновить список", self.reload))
        r.addStretch()
        r.addWidget(btn("Закрыть", self.reject))
        v.addLayout(r)
        self.reload()

    def reload(self) -> None:
        rows = running_programs()
        self.tbl.setSortingEnabled(False)
        self.tbl.setRowCount(len(rows))
        for i, row in enumerate(rows):
            set_row(self.tbl, i, [row["name"], row["net"] or "", row["exe"]], row["exe"])
        self.tbl.setSortingEnabled(True)
        self._apply_filter()

    def _apply_filter(self) -> None:
        q = self.filter.text().strip().lower()
        for i in range(self.tbl.rowCount()):
            text = " ".join((self.tbl.item(i, c).text() if self.tbl.item(i, c) else "") for c in (0, 2)).lower()
            self.tbl.setRowHidden(i, bool(q) and q not in text)

    def _pick(self, verdict: str) -> None:
        exes = [e for e in selected_data(self.tbl) if e]
        if not exes:
            return
        if verdict == "pick":
            self.chosen = exes[0]
            self.accept()
            return
        self.on_pick(verdict, exes)
        self.tbl.clearSelection()


class SitePicker(QDialog):
    """Sites that went through NexusVPN since it was started."""

    def __init__(self, parent, app, on_pick):
        super().__init__(parent)
        self.app, self.on_pick = app, on_pick
        self.setWindowTitle("Сайты из соединений")
        self.resize(820, 540)
        v = QVBoxLayout(self)
        hint = QLabel("Сайты, которые сейчас открыты или открывались через NexusVPN. Сайты, которые уже идут "
                      "полностью мимо программы, здесь не видны — они и так напрямую.")
        hint.setWordWrap(True)
        hint.setObjectName("muted")
        v.addWidget(hint)
        self.tbl = table(["Сайт", "Программа", "Сейчас"], 0)
        v.addWidget(self.tbl, 1)
        r = QHBoxLayout()
        r.addWidget(btn("→ Через VPN", lambda: self._pick("proxy"), "primary"))
        r.addWidget(btn("→ Напрямую", lambda: self._pick("direct")))
        r.addWidget(btn("Обновить", self.reload))
        r.addStretch()
        r.addWidget(btn("Закрыть", self.reject))
        v.addLayout(r)
        self.seen: dict[str, tuple[str, str]] = {}
        self.reload()

    def reload(self) -> None:
        if self.app.engine.state != "running":
            self.tbl.setRowCount(0)
            return
        try:
            conns = self.app.engine.api().connections().get("connections") or []
        except OSError:
            conns = []
        for c in conns:
            md = c.get("metadata") or {}
            host = (md.get("host") or "").strip(".").lower()
            if not host or host.replace(".", "").isdigit():
                continue
            proc = PureWindowsPath((md.get("processPath") or "").split(" (")[0]).name
            route = "через VPN" if (c.get("chains") or ["direct"])[0] != "direct" else "напрямую"
            self.seen[base_domain(host)] = (proc, route)
        self.tbl.setSortingEnabled(False)
        self.tbl.setRowCount(len(self.seen))
        for i, (dom, (proc, route)) in enumerate(sorted(self.seen.items())):
            set_row(self.tbl, i, [dom, proc, route], dom)
        self.tbl.setSortingEnabled(True)

    def _pick(self, verdict: str) -> None:
        doms = [d for d in selected_data(self.tbl) if d]
        if doms:
            self.on_pick(verdict, doms)
            self.tbl.clearSelection()


# ----------------------------------------------------------------------- games
class GamesPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Игры", "Выберите, как пойдёт каждая игра. «Напрямую» — пинг как без VPN и ваш "
                                       "настоящий регион. «Через VPN» — если игра у вас заблокирована.", "games"))
        self.warn = QLabel()
        self.warn.setWordWrap(True)
        self.warn.setStyleSheet("color:#fbbf24")
        v.addWidget(self.warn)
        self.tbl = table(["Игра", "Режим", "Что входит"], 2)
        self.tbl.setSortingEnabled(False)
        v.addWidget(self.tbl, 1)
        r = QHBoxLayout()
        r.addWidget(btn("+ Своя игра из запущенных…", self.add_running))
        r.addWidget(btn("+ Своя игра: папка…", self.add_folder))
        r.addWidget(btn("Удалить свою игру", self.remove_custom))
        r.addStretch()
        r.addWidget(btn("Все «Не трогать»", self.all_off))
        r.addWidget(btn("Сохранить и применить", self.save, "primary"))
        r.addWidget(HelpButton("games"))
        v.addLayout(r)
        self.combos: list[tuple[str, QComboBox]] = []
        self.load()

    def _combo(self, mode: str) -> QComboBox:
        cb = QComboBox()
        for k, t in GAME_MODES.items():
            cb.addItem(t, k)
        cb.setCurrentIndex(max(0, cb.findData(mode)))
        cb.currentIndexChanged.connect(self._update_warning)
        return cb

    def load(self) -> None:
        s = self.app.settings
        games, custom = s["games"] or {}, s["custom_games"] or []
        rows = [(f"preset:{k}", name, ", ".join(folders) + (f" — {note}" if note else ""), games.get(k, "off"))
                for k, name, folders, note in GAME_PRESETS]
        rows += [(f"custom:{i}", f"★ {g['name']}", g["match"], g.get("mode", "off")) for i, g in enumerate(custom)]
        self.tbl.setRowCount(len(rows))
        self.combos = []
        for i, (key, name, what, mode) in enumerate(rows):
            set_row(self.tbl, i, [name, "", what], key)
            cb = self._combo(mode)
            self.tbl.setCellWidget(i, 1, cb)
            self.combos.append((key, cb))
        self.tbl.resizeColumnToContents(0)
        self.tbl.setColumnWidth(1, 190)
        self._update_warning()

    def _modes(self) -> tuple[dict, list]:
        games: dict[str, str] = {}
        custom = [dict(g) for g in self.app.settings["custom_games"] or []]
        for key, cb in self.combos:
            kind, ref = key.split(":", 1)
            if kind == "preset" and cb.currentData() != "off":
                games[ref] = cb.currentData()
            elif kind == "custom":
                custom[int(ref)]["mode"] = cb.currentData()
        return games, custom

    def _update_warning(self) -> None:
        games, custom = self._modes()
        vpn = any(m == "proxy" for m in games.values()) or any(g.get("mode") == "proxy" for g in custom)
        s = self.app.settings
        full = s["capture_mode"] == "tun" and s["direct_bypass"] == "full"
        self.warn.setText("Игры «Через VPN» в режиме полного обхода: соединения по TCP попадут в VPN сами, а "
                          "игровой UDP — нет. Для таких игр выберите в Настройках «Трафик мимо VPN» → «Через "
                          "программу»." if vpn and full else "")
        self.warn.setVisible(bool(self.warn.text()))

    def save(self) -> None:
        games, custom = self._modes()
        s = self.app.settings
        s["games"], s["custom_games"] = games, custom
        s.save()
        self.app.status("Игры сохранены")
        run_bg(self.app.engine.reload)

    def all_off(self) -> None:
        for _key, cb in self.combos:
            cb.setCurrentIndex(cb.findData("off"))

    def _add_custom(self, name: str, match: str) -> None:
        s = self.app.settings
        s["custom_games"] = list(s["custom_games"] or []) + [{"name": name, "match": match, "mode": "direct"}]
        s.save()
        self.load()
        self.app.status(f"Игра «{name}» добавлена — режим «Напрямую». Нажмите «Сохранить и применить».")

    def add_running(self) -> None:
        dlg = ProcessPicker(self, single=True)
        if dlg.exec() and dlg.chosen:
            folder = str(PureWindowsPath(dlg.chosen).parent)
            name, ok = QInputDialog.getText(self, "Своя игра", "Название:", text=PureWindowsPath(folder).name)
            if ok and name.strip():
                self._add_custom(name.strip(), folder)

    def add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Папка с игрой")
        if folder:
            folder = os.path.normpath(folder)
            self._add_custom(PureWindowsPath(folder).name or folder, folder)

    def remove_custom(self) -> None:
        keys = [k for k in selected_data(self.tbl) if k and k.startswith("custom:")]
        if not keys:
            QMessageBox.information(self, "Игры", "Выберите строку своей игры (со звёздочкой).")
            return
        drop = {int(k.split(":", 1)[1]) for k in keys}
        s = self.app.settings
        s["custom_games"] = [g for i, g in enumerate(s["custom_games"] or []) if i not in drop]
        s.save()
        self.load()
        run_bg(self.app.engine.reload)
