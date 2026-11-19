"""Qt plumbing: thread-safe event bridge, background jobs, theme, icons."""
from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, QPoint, QRunnable, QSize, Qt, QThreadPool, Signal
from PySide6.QtGui import QColor, QIcon, QImage, QPainter, QPalette, QPen, QPixmap
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QToolButton, QVBoxLayout, QWidget

from .. import paths
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


def app_icon() -> QIcon:
    """The same icon as the desktop shortcut. PyInstaller unpacks bundled assets into sys._MEIPASS."""
    base = Path(getattr(sys, "_MEIPASS", paths.BASE_DIR))
    return QIcon(str(base / "assets" / "icon.ico"))


def _crossed(pm: QPixmap) -> QPixmap:
    img = pm.toImage().convertToFormat(QImage.Format_ARGB32)
    for y in range(img.height()):
        for x in range(img.width()):
            c = img.pixelColor(x, y)
            g = int(0.3 * c.red() + 0.59 * c.green() + 0.11 * c.blue())
            img.setPixelColor(x, y, QColor(g, g, g, int(c.alpha() * 0.75)))
    out = QPixmap.fromImage(img)
    w = out.width()
    p = QPainter(out)
    p.setRenderHint(QPainter.Antialiasing)
    m = w * 0.1
    # dark outline first so the red line stays visible on light and dark taskbars
    for color, width in (("#0b1220", max(2.0, w * 0.2)), ("#ef4444", max(1.5, w * 0.12))):
        p.setPen(QPen(QColor(color), width, Qt.SolidLine, Qt.RoundCap))
        p.drawLine(int(m), int(m), int(w - m), int(w - m))
    p.end()
    return out


_TRAY: dict[bool, QIcon] = {}


def tray_icon(connected: bool) -> QIcon:
    """Tray: the bright app icon while the VPN is on, grey and crossed out otherwise."""
    if connected not in _TRAY:
        base = app_icon()
        if connected:
            _TRAY[True] = base
        else:
            icon = QIcon()
            for size in base.availableSizes() or [QSize(32, 32)]:
                if size.width() <= 64:
                    icon.addPixmap(_crossed(base.pixmap(size)))
            _TRAY[False] = icon
    return _TRAY[connected]


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


def apply_dark_theme(qapp) -> None:
    """Fusion + dark palette: dialogs, message boxes and the tray menu otherwise use the light Windows 11
    style while our stylesheet makes their text light — white on white."""
    qapp.setStyle("Fusion")
    p = QPalette()
    bg, base, alt, text, mid = QColor("#0f172a"), QColor("#0b1220"), QColor("#111827"), QColor("#e2e8f0"), \
        QColor("#334155")
    for role, color in ((QPalette.Window, bg), (QPalette.WindowText, text), (QPalette.Base, base),
                        (QPalette.AlternateBase, alt), (QPalette.ToolTipBase, QColor("#1e293b")),
                        (QPalette.ToolTipText, text), (QPalette.Text, text), (QPalette.Button, QColor("#1e293b")),
                        (QPalette.ButtonText, text), (QPalette.BrightText, QColor("#ffffff")),
                        (QPalette.Highlight, QColor("#0369a1")), (QPalette.HighlightedText, QColor("#ffffff")),
                        (QPalette.Link, QColor("#38bdf8")), (QPalette.PlaceholderText, QColor("#64748b")),
                        (QPalette.Mid, mid), (QPalette.Dark, base), (QPalette.Light, mid)):
        p.setColor(role, color)
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor("#64748b"))
    qapp.setPalette(p)


THEME = """
* { font-family: "Segoe UI", "Inter", sans-serif; font-size: 10pt; }
QMainWindow, QWidget#root, QDialog, QMessageBox, QInputDialog { background: #0f172a; }
QDialog QLabel, QMessageBox QLabel { color: #e2e8f0; }
QMenu { background: #111827; color: #e2e8f0; border: 1px solid #334155; padding: 4px; }
QMenu::item { padding: 6px 22px; border-radius: 5px; }
QMenu::item:selected { background: #0369a1; color: white; }
QMenu::item:disabled { color: #64748b; }
QMenu::separator { height: 1px; background: #334155; margin: 4px 8px; }
QCheckBox { color: #e2e8f0; spacing: 8px; }
QCheckBox::indicator { border: 2px solid #64748b; border-radius: 4px; background: #0b1220; }
QCheckBox::indicator:hover { border-color: #94a3b8; }
QCheckBox::indicator:checked { background: #0ea5e9; border: 2px solid #bae6fd; }
QCheckBox::indicator:disabled { border-color: #334155; background: #111827; }
QCheckBox::indicator:checked:disabled { background: #1e4e6b; border-color: #475569; }
QGroupBox::indicator { width: 14px; height: 14px; }
QWidget { color: #e2e8f0; }
QListWidget#nav { background: #0b1220; border: none; padding-top: 8px; outline: 0; }
QListWidget#nav QScrollBar:horizontal { height: 0; }
QListWidget#nav::item { padding: 11px 18px; border-radius: 8px; margin: 2px 8px; }
QListWidget#nav::item:selected { background: #0c4a6e; color: #ffffff; font-weight: 600;
            border-left: 3px solid #38bdf8; }
QListWidget#nav::item:hover:!selected { background: #111a2e; }
QGroupBox { border: 1px solid #1e293b; border-radius: 10px; margin-top: 14px; padding: 12px 10px 10px 10px;
            background: #111827; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #93c5fd; font-weight: 600; }
QPushButton { background: #1e293b; border: 1px solid #334155; border-radius: 7px; padding: 6px 14px; }
QPushButton:checked { background: #0c4a6e; border-color: #38bdf8; color: #f0f9ff; font-weight: 600; }
QPushButton:hover { background: #273449; border-color: #38bdf8; }
QPushButton:pressed { background: #0ea5e9; }
QPushButton:disabled { color: #475569; background: #0f172a; border-color: #1e293b; }
QPushButton#primary { background: #0284c7; border: none; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #0ea5e9; }
QPushButton#danger { background: #7f1d1d; border: none; }
QPushButton#bigconnect { font-size: 12pt; font-weight: 800; border-radius: 70px; min-width: 140px;
                         min-height: 140px; max-width: 140px; max-height: 140px; }
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
QTabBar::tab:selected { background: #0c4a6e; color: #ffffff; font-weight: 600; border-bottom: 2px solid #38bdf8; }
QCheckBox::indicator { width: 16px; height: 16px; }
QPushButton { min-height: 22px; }
QLabel#h1 { font-size: 17pt; font-weight: 700; }
QLabel#h2 { font-size: 12pt; font-weight: 700; color: #93c5fd; }
QPushButton#toggle { background: #0b1220; border: 1px dashed #475569; color: #94a3b8; font-weight: 600; }
QPushButton#toggle:hover:!checked { border-color: #94a3b8; color: #e2e8f0; }
QPushButton#toggle:checked { background: #15803d; border: 2px solid #4ade80; color: #ffffff; }
QPushButton#seg[state="off"]:checked { background: #475569; border-color: #94a3b8; }
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
QWidget#banner { background: #064e3b; border: 1px solid #10b981; border-radius: 10px; }
QWidget#banner QLabel { color: #d1fae5; }
QPushButton#seg { border-radius: 0; padding: 3px 10px; min-height: 20px; background: #0b1220;
            border: 1px solid #334155; color: #94a3b8; font-weight: 500; }
QPushButton#seg[pos="first"] { border-top-left-radius: 6px; border-bottom-left-radius: 6px; }
QPushButton#seg[pos="last"] { border-top-right-radius: 6px; border-bottom-right-radius: 6px; }
QPushButton#seg:checked { background: #0284c7; border-color: #38bdf8; color: white; font-weight: 700; }
QPushButton#seg:hover:!checked { background: #1e293b; color: #e2e8f0; }
QPushButton#seg[state="direct"]:checked { background: #15803d; border-color: #4ade80; }
QPushButton#seg[state="proxy"]:checked { background: #7c3aed; border-color: #a78bfa; }
QPushButton#seg[state="auto"]:checked { background: #475569; border-color: #94a3b8; }
QLabel#chip { background: #1e293b; border: 1px solid #334155; border-radius: 9px; padding: 2px 9px;
            color: #cbd5e1; font-size: 9pt; }
QLabel#chip[on="true"] { background: #064e3b; border-color: #10b981; color: #a7f3d0; }
QLabel#hint { color: #94a3b8; font-size: 9.5pt; }
QLabel#warn { color: #fbbf24; }
"""
