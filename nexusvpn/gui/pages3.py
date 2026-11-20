"""Pickers for running programs and visited sites, the «Игры» page, wheel protection for inputs."""
from __future__ import annotations

import os
from pathlib import PureWindowsPath

import psutil
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import (QAbstractScrollArea, QAbstractSpinBox, QApplication, QCheckBox, QComboBox, QDialog,
                               QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox,
                               QTableWidget, QVBoxLayout, QWidget)

from ..learner import base_domain
from ..presets import GAME_MODES, GAME_PRESETS
from .common import run_bg
from .widgets import Segmented, btn, page_title, selected_data, set_row, table

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
    """One row per executable: name, path, number of network connections. Slow on Windows: background."""
    conns: dict[int, int] = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid and c.raddr:
                conns[c.pid] = conns.get(c.pid, 0) + 1
    except (psutil.Error, OSError):
        pass
    out: dict[str, dict] = {}
    for p in psutil.process_iter(["pid", "name", "exe"]):
        name, exe = p.info["name"] or "", p.info["exe"] or ""
        if not exe or name.lower() in SKIP_NAMES:
            continue
        row = out.setdefault(exe.lower(), {"name": name, "exe": exe, "net": 0,
                                           "system": any(d in exe.lower() for d in SKIP_DIRS)})
        row["net"] += conns.get(p.info["pid"], 0)
    return sorted(out.values(), key=lambda r: (-min(r["net"], 1), r["name"].lower()))


class _Picker(QDialog):
    """Shared shell: hint, search, table, «Добавить выбранные (N)» enabled only with a selection."""

    def __init__(self, parent, title: str, action: str, headers: list[str], stretch: int, single: bool):
        super().__init__(parent)
        self.chosen: list = []
        self.setWindowTitle(title)
        self.resize(900, 580)
        self.v = QVBoxLayout(self)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        self.v.addWidget(self.hint)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Поиск…")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self._apply_filter)
        self.v.addWidget(self.filter)
        self.tbl = table(headers, stretch)
        self.tbl.setSelectionMode(QTableWidget.SingleSelection if single else QTableWidget.ExtendedSelection)
        self.tbl.itemSelectionChanged.connect(self._sel_changed)
        self.tbl.doubleClicked.connect(lambda _i: self._accept())
        self.v.addWidget(self.tbl, 1)
        self.bottom = QHBoxLayout()
        self.ok = btn(action, self._accept, "primary")
        self._action = action
        self.bottom.addStretch()
        self.bottom.addWidget(btn("Отмена", self.reject))
        self.bottom.addWidget(self.ok)
        self.v.addLayout(self.bottom)
        self._sel_changed()

    def _rows(self) -> list[int]:
        return sorted({i.row() for i in self.tbl.selectedIndexes()
                       if not self.tbl.isRowHidden(i.row()) and self.tbl.item(i.row(), 0)
                       and self.tbl.item(i.row(), 0).flags() & Qt.ItemIsEnabled})

    def _sel_changed(self) -> None:
        n = len(self._rows())
        self.ok.setEnabled(n > 0)
        self.ok.setText(f"{self._action} ({n})" if n > 1 else self._action)

    def _apply_filter(self) -> None:
        q = self.filter.text().strip().lower()
        for i in range(self.tbl.rowCount()):
            text = " ".join((self.tbl.item(i, c).text() if self.tbl.item(i, c) else "")
                            for c in range(self.tbl.columnCount())).lower()
            self.tbl.setRowHidden(i, (bool(q) and q not in text) or self._hidden_row(i))

    def _hidden_row(self, _row: int) -> bool:
        return False

    def _mark_listed(self, row: int, listed: bool) -> None:
        if not listed:
            return
        for c in range(self.tbl.columnCount()):
            it = self.tbl.item(row, c)
            if it:
                it.setFlags(it.flags() & ~Qt.ItemIsEnabled & ~Qt.ItemIsSelectable)
                if c == 0:
                    it.setText("✓ " + it.text())
                    it.setToolTip("Уже в списке")

    def _accept(self) -> None:
        rows = self._rows()
        if not rows:
            return
        self.chosen = [self.tbl.item(r, 0).data(Qt.UserRole) for r in rows]
        self.accept()


class ProcessPicker(_Picker):
    """Running programs. .chosen -> [exe name] (or [exe path] with want_path=True)."""

    def __init__(self, parent, action: str, listed: set[str] | None = None, single: bool = False,
                 want_path: bool = False):
        super().__init__(parent, "Выбор программы", action, ["Программа", "В сети", "Где находится"], 2, single)
        self.listed, self.want_path = {x.lower() for x in (listed or set())}, want_path
        self.hint.setText("Выделите программу (несколько — с зажатым Ctrl) и нажмите «" + action + "». "
                          "Сверху — программы, которые сейчас выходят в интернет. ✓ — уже в списке.")
        self.show_sys = QCheckBox("Показать системные программы Windows")
        self.show_sys.toggled.connect(self._apply_filter)
        self.bottom.insertWidget(0, self.show_sys)
        self.bottom.insertWidget(1, btn("Обновить список", self.reload))
        self.rows: list[dict] = []
        self.reload()

    def reload(self) -> None:
        self.tbl.setRowCount(0)
        self.setCursor(Qt.BusyCursor)
        run_bg(running_programs, done=self._fill, failed=lambda _e: self.unsetCursor())

    def _fill(self, rows: list[dict]) -> None:
        self.unsetCursor()
        self.rows = rows
        self.tbl.setSortingEnabled(False)
        self.tbl.setRowCount(len(rows))
        for i, row in enumerate(rows):
            data = row["exe"] if self.want_path else row["name"]
            set_row(self.tbl, i, [row["name"], "да" if row["net"] else "", row["exe"]], data)
            self._mark_listed(i, row["name"].lower() in self.listed)
        self._apply_filter()
        self._sel_changed()

    def _hidden_row(self, row: int) -> bool:
        return row < len(self.rows) and self.rows[row]["system"] and not self.show_sys.isChecked()


class SitePicker(_Picker):
    """Sites seen in the connections since the VPN was switched on, plus a field to type an address.
    .chosen -> [(kind, value)]"""

    def __init__(self, parent, app, action: str, listed: set[str] | None = None):
        super().__init__(parent, "Выбор сайта", action, ["Сайт", "Какая программа открывала", "Сейчас идёт"], 0,
                         False)
        self.app, self.listed = app, listed or set()
        self.hint.setText("Сайты, которые открывались, пока VPN включён. Выделите нужные и нажмите «" + action +
                          "». Нет нужного сайта — впишите адрес ниже.")
        row = QHBoxLayout()
        self.addr = QLineEdit()
        self.addr.setPlaceholderText("или впишите адрес: например, kinopoisk.ru")
        self.addr.returnPressed.connect(self._typed)
        row.addWidget(self.addr, 1)
        row.addWidget(btn("Добавить адрес", self._typed))
        self.v.insertLayout(3, row)
        self.bottom.insertWidget(0, btn("Обновить список", self.reload))
        self.reload()

    def reload(self) -> None:
        if self.app.engine.state != "running":
            self.hint.setText("VPN выключен — список открытых сайтов пуст. Впишите адрес вручную ниже.")
            return
        run_bg(lambda: self.app.engine.api().connections().get("connections") or [], done=self._fill)

    def _fill(self, conns: list) -> None:
        seen: dict[str, tuple[str, str]] = {}
        for c in conns:
            md = c.get("metadata") or {}
            host = (md.get("host") or "").strip(".").lower()
            if not host or host.replace(".", "").isdigit():
                continue
            proc = PureWindowsPath((md.get("processPath") or "").split(" (")[0]).name
            route = "через VPN" if (c.get("chains") or ["direct"])[0] != "direct" else "напрямую"
            seen[base_domain(host)] = (proc, route)
        self.tbl.setSortingEnabled(False)
        self.tbl.setRowCount(len(seen))
        for i, (dom, (proc, route)) in enumerate(sorted(seen.items())):
            set_row(self.tbl, i, [dom, proc, route], ("domain", dom))
            self._mark_listed(i, dom in self.listed)
        self.tbl.setSortingEnabled(True)
        self._apply_filter()
        self._sel_changed()

    def _typed(self) -> None:
        from ..rules_text import parse_text
        entries, errors = parse_text(self.addr.text())
        if errors or not entries:
            QMessageBox.information(self, "Адрес", "Не похоже на адрес сайта. Пример: kinopoisk.ru")
            return
        self.chosen = entries
        self.accept()


# ----------------------------------------------------------------------- games
class GamesPage(QWidget):
    """Every game: one row with three buttons — the chosen one is filled in. Applies at once."""

    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Игры", "«Напрямую» — пинг как без VPN и ваш настоящий регион. «Через VPN» — если "
                                       "игра у вас заблокирована. Изменения применяются сразу.", "games"))
        self.warn = QLabel()
        self.warn.setWordWrap(True)
        self.warn.setStyleSheet("color:#fbbf24")
        v.addWidget(self.warn)
        self.tbl = table(["Игра", "Как идёт", "Что входит"], 2)
        self.tbl.setSortingEnabled(False)
        self.tbl.setSelectionMode(QTableWidget.SingleSelection)
        self.tbl.verticalHeader().setDefaultSectionSize(36)
        self.tbl.itemSelectionChanged.connect(self._sel_changed)
        v.addWidget(self.tbl, 1)
        r = QHBoxLayout()
        r.addWidget(btn("+ Своя игра из запущенных…", self.add_running,
                        tip="Запустите игру, нажмите и выберите её из списка"))
        r.addWidget(btn("+ Своя игра: указать папку…", self.add_folder))
        self.b_remove = btn("Удалить свою игру", self.remove_custom, tip="Выделите строку своей игры (со ★)")
        r.addWidget(self.b_remove)
        r.addStretch()
        r.addWidget(btn("Все — «Не трогать»", self.all_off))
        v.addLayout(r)
        self.segs: list[tuple[str, Segmented]] = []
        self.load()

    def load(self) -> None:
        s = self.app.settings
        games, custom = s["games"] or {}, s["custom_games"] or []
        rows = [(f"preset:{k}", name, ", ".join(folders) + (f" — {note}" if note else ""), games.get(k, "off"))
                for k, name, folders, note in GAME_PRESETS]
        rows += [(f"custom:{i}", f"★ {g['name']}", g["match"], g.get("mode", "off")) for i, g in enumerate(custom)]
        self.tbl.setRowCount(len(rows))
        self.segs = []
        opts = [("off", GAME_MODES["off"], "Игра идёт по общим правилам"),
                ("direct", "Напрямую", "Мимо VPN: обычный пинг, ваш регион"),
                ("proxy", "Через VPN", "Если игра или её сервера заблокированы")]
        for i, (key, name, what, mode) in enumerate(rows):
            set_row(self.tbl, i, [name, "", what], key)
            seg = Segmented(opts, mode, lambda _m, k=key: self._changed(k))
            self.tbl.setCellWidget(i, 1, seg)
            self.segs.append((key, seg))
        self.tbl.resizeColumnToContents(0)
        self.tbl.resizeColumnToContents(1)
        self._update_warning()
        self._sel_changed()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._update_warning()

    def _sel_changed(self) -> None:
        keys = selected_data(self.tbl)
        self.b_remove.setEnabled(any(k and k.startswith("custom:") for k in keys))

    def _modes(self) -> tuple[dict, list]:
        games: dict[str, str] = {}
        custom = [dict(g) for g in self.app.settings["custom_games"] or []]
        for key, seg in self.segs:
            kind, ref = key.split(":", 1)
            if kind == "preset" and seg.key != "off":
                games[ref] = seg.key
            elif kind == "custom":
                custom[int(ref)]["mode"] = seg.key
        return games, custom

    def _update_warning(self) -> None:
        games, custom = self._modes()
        vpn = any(m == "proxy" for m in games.values()) or any(g.get("mode") == "proxy" for g in custom)
        s = self.app.settings
        full = s["capture_mode"] == "tun" and s["direct_bypass"] == "full"
        direct = any(m == "direct" for m in games.values()) or any(g.get("mode") == "direct" for g in custom)
        through_program = s["capture_mode"] == "both" or (s["capture_mode"] == "tun" and (
            s["routing_mode"] == "global" or s["direct_bypass"] != "full"))
        if vpn and full:
            text = ("Игры «Через VPN» при режиме «Мимо программы»: TCP-соединения игры попадут в VPN сами, а "
                    "игровой UDP — нет. Для таких игр включите в Настройках → «Трафик мимо VPN» → «Через программу».")
        elif direct and through_program:
            text = ("Сейчас весь трафик идёт через программу (режим «Всё через VPN» или «Трафик мимо VPN» → «Через "
                    "программу»), поэтому у игр «Напрямую» тип NAT будет строгим. Для открытого NAT выберите на главной "
                    "режим «Умная» или «Своя», а в Настройках → «Трафик мимо VPN» → «Мимо программы».")
        else:
            text = ""
        self.warn.setText(text)
        self.warn.setVisible(bool(self.warn.text()))

    def _changed(self, _key: str) -> None:
        self.save()

    def save(self) -> None:
        games, custom = self._modes()
        s = self.app.settings
        s["games"], s["custom_games"] = games, custom
        s.save()
        self._update_warning()
        self.app.status("Игры: изменения применены")
        self.app.engine.reload_later()

    def all_off(self) -> None:
        for _key, seg in self.segs:
            seg.pick("off")
        self.save()

    def _add_custom(self, name: str, match: str) -> None:
        s = self.app.settings
        s["custom_games"] = list(s["custom_games"] or []) + [{"name": name, "match": match, "mode": "direct"}]
        s.save()
        self.load()
        self.app.status(f"Игра «{name}» добавлена и идёт напрямую")
        self.app.engine.reload_later()

    def add_running(self) -> None:
        dlg = ProcessPicker(self, "Это моя игра", single=True, want_path=True)
        if dlg.exec() and dlg.chosen:
            folder = str(PureWindowsPath(dlg.chosen[0]).parent)
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
            return
        drop = {int(k.split(":", 1)[1]) for k in keys}
        s = self.app.settings
        s["custom_games"] = [g for i, g in enumerate(s["custom_games"] or []) if i not in drop]
        s.save()
        self.load()
        self.app.engine.reload_later()
