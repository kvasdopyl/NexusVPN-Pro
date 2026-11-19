"""Small shared widgets/helpers for pages."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QHBoxLayout, QHeaderView, QLabel, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .common import HelpButton


def table(headers: list[str], stretch: int = 0) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(28)
    h = t.horizontalHeader()
    h.setSectionResizeMode(QHeaderView.ResizeToContents)
    h.setSectionResizeMode(stretch, QHeaderView.Stretch)
    t.setSortingEnabled(True)
    return t


def set_row(t: QTableWidget, row: int, values: list, data=None) -> None:
    for c, v in enumerate(values):
        it = QTableWidgetItem()
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            it.setData(Qt.DisplayRole, v)
        else:
            it.setText(str(v))
        if c == 0 and data is not None:
            it.setData(Qt.UserRole, data)
        t.setItem(row, c, it)


def selected_data(t: QTableWidget) -> list:
    rows = sorted({i.row() for i in t.selectedIndexes()})
    return [t.item(r, 0).data(Qt.UserRole) for r in rows if t.item(r, 0)]


def btn(text: str, slot, obj: str = "", tip: str = "") -> QPushButton:
    b = QPushButton(text)
    if obj:
        b.setObjectName(obj)
    if tip:
        b.setToolTip(tip)
    b.clicked.connect(slot)
    return b


def page_title(text: str, sub: str = "", help_key: str = "") -> QWidget:
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 6)
    row = QHBoxLayout()
    h = QLabel(text)
    h.setObjectName("h1")
    row.addWidget(h)
    if help_key:
        row.addWidget(HelpButton(help_key))
    row.addStretch()
    v.addLayout(row)
    if sub:
        s = QLabel(sub)
        s.setObjectName("muted")
        s.setWordWrap(True)
        v.addWidget(s)
    return w


def group_header(title: str, help_key: str) -> QWidget:
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    lbl = QLabel(f"<b>{title}</b>")
    lbl.setStyleSheet("color:#93c5fd")
    h.addWidget(lbl)
    h.addWidget(HelpButton(help_key))
    h.addStretch()
    return w


class Segmented(QWidget):
    """A row of exclusive buttons: the chosen one is filled in. Used everywhere a thing can be
    «через VPN / напрямую / не трогать», so the current state is always visible at a glance."""

    def __init__(self, options: list[tuple[str, str, str]], current: str, on_change, parent=None):
        """options: [(key, label, tooltip)]"""
        super().__init__(parent)
        self.on_change = on_change
        h = QHBoxLayout(self)
        h.setContentsMargins(2, 1, 2, 1)
        h.setSpacing(0)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons: dict[str, QPushButton] = {}
        for i, (key, label, tip) in enumerate(options):
            b = QPushButton(label)
            b.setObjectName("seg")
            b.setCheckable(True)
            b.setProperty("pos", "first" if i == 0 else ("last" if i == len(options) - 1 else "mid"))
            b.setProperty("state", key)
            b.setChecked(key == current)
            b.setToolTip(tip)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.pick(k, notify=True))
            self.group.addButton(b)
            self.buttons[key] = b
            h.addWidget(b)
        self.key = current

    def pick(self, key: str, notify: bool = False) -> None:
        self.key = key
        self.buttons[key].setChecked(True)
        if notify and self.on_change:
            self.on_change(key)

    @staticmethod
    def verdict_options(direct_label: str = "Напрямую") -> list[tuple[str, str, str]]:
        return [("proxy", "Через VPN", "Всё соединение идёт через VPN-сервер"),
                ("direct", direct_label, "Как будто VPN выключен: напрямую через вашу сетевую карту"),
                ("auto", "Авто", "Решает программа: умная маршрутизация и базы правил")]
