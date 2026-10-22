"""Reusable widgets: page header, stat card with sparkline, styled tables."""
import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import theme

pg.setConfigOptions(antialias=True, background=theme.SURFACE, foreground=theme.MUTED)
MONO_FONT = QFont("Cascadia Mono")
MONO_FONT.setStyleHint(QFont.Monospace)


def page_header(title: str, subtitle: str) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 8)
    lay.setSpacing(2)
    t = QLabel(title)
    t.setObjectName("pageTitle")
    s = QLabel(subtitle)
    s.setObjectName("pageSub")
    s.setWordWrap(True)
    lay.addWidget(t)
    lay.addWidget(s)
    return w


def label(text: str, name: str = "", wrap: bool = False) -> QLabel:
    lbl = QLabel(text)
    if name:
        lbl.setObjectName(name)
    lbl.setWordWrap(wrap)
    return lbl


class StatCard(QFrame):
    def __init__(self, title: str, color: str = theme.ACCENT):
        super().__init__()
        self.setObjectName("card")
        self.history: list[float] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 10)
        lay.setSpacing(2)
        lay.addWidget(label(title, "cardLabel"))
        self.value = label("--", "cardValue")
        self.sub = label("", "cardSub")
        lay.addWidget(self.value)
        lay.addWidget(self.sub)
        self.spark = pg.PlotWidget()
        self.spark.setFixedHeight(36)
        self.spark.hideAxis("left")
        self.spark.hideAxis("bottom")
        self.spark.setMouseEnabled(False, False)
        self.spark.setMenuEnabled(False)
        self.spark.hideButtons()
        self.spark.setYRange(0, 100)
        self.spark.setStyleSheet("border: none;")
        self.curve = self.spark.plot(pen=pg.mkPen(color, width=1.6))
        lay.addWidget(self.spark)

    def update_value(self, value: str, sub: str, spark_value: float, max_value: float | None = 100):
        self.value.setText(value)
        self.sub.setText(sub)
        self.history = (self.history + [spark_value])[-60:]
        if max_value is None:
            self.spark.setYRange(0, max(max(self.history), 1) * 1.15)
        self.curve.setData(self.history)


def make_table(headers: list[str], stretch_col: int = 0) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setWordWrap(False)
    t.setTextElideMode(Qt.ElideMiddle)   # long paths keep their file name visible
    h = t.horizontalHeader()
    h.setSectionResizeMode(QHeaderView.ResizeToContents)
    h.setSectionResizeMode(stretch_col, QHeaderView.Stretch)
    h.setHighlightSections(False)
    t.verticalHeader().setDefaultSectionSize(30)
    return t


def cell(text, color: str | None = None, mono: bool = False, bold: bool = False,
         align_right: bool = False, tooltip: str = "") -> QTableWidgetItem:
    it = QTableWidgetItem(str(text))
    if color:
        it.setForeground(QColor(color))
    if mono or bold:
        f = QFont(MONO_FONT) if mono else QFont()
        f.setBold(bold)
        it.setFont(f)
    if align_right:
        it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
    if tooltip:
        it.setToolTip(tooltip)
    return it


def hrow(*widgets) -> QHBoxLayout:
    """Horizontal row; None in the list becomes a stretch."""
    lay = QHBoxLayout()
    lay.setSpacing(8)
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        elif isinstance(w, QWidget):
            lay.addWidget(w)
        else:
            lay.addLayout(w)
    return lay
