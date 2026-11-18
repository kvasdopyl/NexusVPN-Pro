"""Small shared widgets/helpers for pages."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

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
