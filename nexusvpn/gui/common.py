"""Qt plumbing: thread-safe event bridge, background jobs, theme, icons."""
from __future__ import annotations

import traceback
from typing import Callable

from PySide6.QtCore import QObject, QPoint, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap, QBrush, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QToolButton, QVBoxLayout, QWidget

from .help_texts import HELP


class Bridge(QObject):
    """Engine threads call .emit_event(); slots run on the GUI thread (queued connection)."""
    event = Signal(str, dict)

    def emit_event(self, name: str, data: dict) -> None:
        self.event.emit(name, data)


class _JobSignals(QObject):
    done = Signal(object)
    failed = Signal(str)


class _Job(QRunnable):
    def __init__(self, fn: Callable, *args):
        super().__init__()
        self.fn, self.args = fn, args
        self.signals = _JobSignals()
        self.setAutoDelete(True)

    def run(self) -> None:
        try:
            res = self.fn(*self.args)
        except Exception as e:  # noqa: BLE001 - errors are shown to the user
            traceback.print_exc()
            self.signals.failed.emit(str(e))
        else:
            self.signals.done.emit(res)


_keep: set = set()


def run_bg(fn: Callable, *args, done: Callable | None = None, failed: Callable | None = None) -> None:
    job = _Job(fn, *args)
    _keep.add(job.signals)
    if done:
        job.signals.done.connect(done, Qt.QueuedConnection)
    if failed:
        job.signals.failed.connect(failed, Qt.QueuedConnection)
    job.signals.done.connect(lambda *_: _keep.discard(job.signals))
    job.signals.failed.connect(lambda *_: _keep.discard(job.signals))
    QThreadPool.globalInstance().start(job)


class HelpPopup(QFrame):
    """Small bubble that closes on any click outside (Qt.Popup)."""

    def __init__(self, html: str, parent=None):
        super().__init__(parent, Qt.Popup)
        self.setObjectName("helppopup")
        self.setAttribute(Qt.WA_DeleteOnClose)
        v = QVBoxLayout(self)
        v.setContentsMargins(14, 12, 14, 12)
        lbl = QLabel(html)
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.RichText)
        lbl.setMaximumWidth(420)
        lbl.setMinimumWidth(260)
        v.addWidget(lbl)


class HelpButton(QToolButton):
    """Round «?»: click shows a Russian explanation, hover shows it as a tooltip too."""

    def __init__(self, key_or_html: str, parent=None):
        super().__init__(parent)
        self.html = HELP.get(key_or_html, key_or_html)
        self.setText("?")
        self.setObjectName("help")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(self.html)
        self.setFixedSize(20, 20)
        self.clicked.connect(self.show_help)

    def show_help(self) -> None:
        pop = HelpPopup(self.html, self.window())
        pop.adjustSize()
        pos = self.mapToGlobal(QPoint(self.width() + 4, 0))
        pop.move(pos)
        pop.show()


def with_help(widget: QWidget, key: str, stretch: bool = False) -> QWidget:
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(6)
    h.addWidget(widget, 1 if stretch else 0)
    h.addWidget(HelpButton(key))
    if not stretch:
        h.addStretch()
    return w


def status_icon(color: str, size: int = 64) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QPen(QColor("#0b1220"), size * 0.06))
    p.setBrush(QBrush(QColor(color)))
    m = size * 0.08
    p.drawEllipse(int(m), int(m), int(size - 2 * m), int(size - 2 * m))
    p.setPen(QPen(QColor("white"), size * 0.09, Qt.SolidLine, Qt.RoundCap))
    c = size / 2
    # shield-ish check mark
    p.drawLine(int(c - size * 0.18), int(c), int(c - size * 0.04), int(c + size * 0.15))
    p.drawLine(int(c - size * 0.04), int(c + size * 0.15), int(c + size * 0.2), int(c - size * 0.14))
    p.end()
    return QIcon(pm)


COLORS = {"running": "#22c55e", "starting": "#f59e0b", "stopping": "#f59e0b", "stopped": "#64748b",
          "error": "#ef4444"}

STATE_TEXT = {"running": "Подключено", "starting": "Подключение…", "stopping": "Отключение…",
              "stopped": "Отключено", "error": "Ошибка"}


def human_bytes(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПБ"


THEME = """
* { font-family: "Segoe UI", "Inter", sans-serif; font-size: 10pt; }
QMainWindow, QWidget#root { background: #0f172a; }
QWidget { color: #e2e8f0; }
QListWidget#nav { background: #0b1220; border: none; padding-top: 12px; outline: 0; }
QListWidget#nav::item { padding: 11px 18px; border-radius: 8px; margin: 2px 8px; }
QListWidget#nav::item:selected { background: #1e293b; color: #38bdf8; }
QListWidget#nav::item:hover:!selected { background: #111a2e; }
QGroupBox { border: 1px solid #1e293b; border-radius: 10px; margin-top: 14px; padding: 12px 10px 10px 10px;
            background: #111827; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #93c5fd; font-weight: 600; }
QPushButton { background: #1e293b; border: 1px solid #334155; border-radius: 7px; padding: 6px 14px; }
QPushButton:hover { background: #273449; border-color: #38bdf8; }
QPushButton:pressed { background: #0ea5e9; }
QPushButton:disabled { color: #64748b; }
QPushButton#primary { background: #0284c7; border: none; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #0ea5e9; }
QPushButton#danger { background: #7f1d1d; border: none; }
QPushButton#bigconnect { font-size: 15pt; font-weight: 700; border-radius: 60px; min-width: 120px;
                         min-height: 120px; max-width: 120px; max-height: 120px; }
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit { background: #0b1220; border: 1px solid #334155;
            border-radius: 6px; padding: 5px; selection-background-color: #0369a1; }
QComboBox QAbstractItemView { background: #0b1220; selection-background-color: #0369a1; }
QTableWidget, QTableView { background: #0b1220; alternate-background-color: #0e1628; gridline-color: #1e293b;
            border: 1px solid #1e293b; border-radius: 6px; selection-background-color: #0c4a6e; }
QHeaderView::section { background: #111827; color: #94a3b8; border: none; border-bottom: 1px solid #1e293b;
            padding: 6px; font-weight: 600; }
QTabWidget::pane { border: 1px solid #1e293b; border-radius: 8px; top: -1px; }
QTabBar::tab { background: #111827; padding: 7px 16px; border-top-left-radius: 7px; border-top-right-radius: 7px;
            margin-right: 2px; color: #94a3b8; }
QTabBar::tab:selected { background: #1e293b; color: #e2e8f0; }
QCheckBox::indicator { width: 16px; height: 16px; }
QLabel#h1 { font-size: 17pt; font-weight: 700; }
QLabel#muted { color: #94a3b8; }
QLabel#card { background: #111827; border: 1px solid #1e293b; border-radius: 10px; padding: 12px; }
QStatusBar { background: #0b1220; color: #94a3b8; }
QScrollArea { border: none; }
QToolTip { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; padding: 6px; }
QToolButton#help { background: #1e3a5f; color: #7dd3fc; border: 1px solid #38bdf8; border-radius: 10px;
            font-weight: 700; font-size: 9pt; padding: 0; }
QToolButton#help:hover { background: #0284c7; color: white; }
QFrame#helppopup { background: #1e293b; border: 1px solid #38bdf8; border-radius: 10px; }
QFrame#helppopup QLabel { color: #e2e8f0; }
QPushButton#mode { font-size: 11pt; font-weight: 600; padding: 14px 10px; border-radius: 10px;
            background: #111827; border: 2px solid #334155; text-align: center; }
QPushButton#mode:checked { background: #0c4a6e; border-color: #38bdf8; color: white; }
QPushButton#mode:hover:!checked { border-color: #64748b; }
QLabel#brand { font-size: 19pt; font-weight: 800; color: #38bdf8; }
"""
