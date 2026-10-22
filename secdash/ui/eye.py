"""The One Eye emblem, animated in code (sharper and lighter than a GIF).

Rings rotate in opposite directions and the pupil's red glow pulses. alert=True makes it pulse
faster and brighter, so the logo doubles as a live status light. Redraws only while visible.
"""
import math

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen, QPixmap, QRadialGradient
from PySide6.QtWidgets import QWidget

from ..core.settings import resource_dir
from . import theme


def asset(name: str) -> str:
    return str(resource_dir() / "assets" / name)


class EyeWidget(QWidget):
    def __init__(self, size: int, fps: int = 30):
        super().__init__()
        self.setFixedSize(size, size)
        self.pix = QPixmap(asset("eye.png")).scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.angle = self.phase = 0.0
        self.alert = False
        self.timer = QTimer(self)
        self.timer.setInterval(1000 // fps)
        self.timer.timeout.connect(self._tick)

    def showEvent(self, e):
        self.timer.start()

    def hideEvent(self, e):
        self.timer.stop()

    def _tick(self):
        if self.window().isMinimized():
            return
        self.angle = (self.angle + (4.0 if self.alert else 1.5)) % 360
        self.phase += 0.25 if self.alert else 0.08
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.drawPixmap(0, 0, self.pix)
        s = self.width()
        pen_w = max(1.5, s * 0.022)
        for inset, color, sweep, speed in ((0.03, theme.ACCENT, 70, 1), (0.13, "#C9CDD4", 45, -1.6)):
            r = QRectF(s * inset, s * inset, s * (1 - 2 * inset), s * (1 - 2 * inset))
            p.setPen(QPen(QColor(color), pen_w, Qt.SolidLine, Qt.FlatCap))
            for offset in (0, 180):   # two opposite arcs per ring
                p.drawArc(r, int((self.angle * speed + offset) * 16), sweep * 16)
        # pupil glow
        pulse = (math.sin(self.phase) + 1) / 2
        glow = QColor(theme.DANGER if self.alert else theme.ACCENT)
        glow.setAlpha(int(40 + (150 if self.alert else 80) * pulse))
        center = QPointF(s * 0.495, s * 0.485)
        g = QRadialGradient(center, s * 0.17)
        g.setColorAt(0, glow)
        g.setColorAt(1, QColor(0, 0, 0, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(g)
        p.drawEllipse(center, s * 0.17, s * 0.17)
