"""System Health: live usage, apps grouped by name, alerts, and ML learning/protect controls."""
import time

import pyqtgraph as pg
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QGridLayout, QHBoxLayout, QListWidget,
                               QListWidgetItem, QMenu, QMessageBox, QProgressBar, QPushButton, QVBoxLayout,
                               QWidget)

from ...core import response
from ...core.anomaly import LEARNING, PROTECTING
from ...core.signature import UNSIGNED, is_signed
from .. import theme
from ..engine import run_async
from ..widgets import StatCard, cell, label, make_table, page_header

APP_COLS = ["App", "Category", "Publisher", "Procs", "CPU %", "RAM MB", "Disk KB/s", "Conns", "Anomaly", "Status"]
MAX_ROWS = 40


class HealthPage(QWidget):
    ask_ai = Signal(str)
    block_app = Signal(str, str)          # exe path, app name

    def __init__(self, monitor, settings):
        super().__init__()
        self.setObjectName("page")
        self.monitor, self.settings = monitor, settings
        self.cpu_hist, self.ram_hist = [], []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(page_header("System Health",
                                   "Live resource usage per app, rule alerts, and ML anomaly detection."))

        cards = QGridLayout()
        cards.setSpacing(12)
        self.card_cpu = StatCard("CPU", theme.ACCENT)
        self.card_ram = StatCard("Memory", "#BC8CFF")
        self.card_disk = StatCard("Disk (system drive)", theme.WARN)
        self.card_net = StatCard("Network", theme.OK)
        for i, c in enumerate((self.card_cpu, self.card_ram, self.card_disk, self.card_net)):
            cards.addWidget(c, 0, i)
        root.addLayout(cards)

        mid = QHBoxLayout()
        mid.setSpacing(12)
        chart_box = QFrame()
        chart_box.setObjectName("card")
        cb = QVBoxLayout(chart_box)
        cb.setContentsMargins(12, 10, 12, 8)
        cb.addWidget(label(f"<span style='color:{theme.ACCENT}'>&#9632; CPU %</span> &nbsp; "
                           f"<span style='color:#BC8CFF'>&#9632; RAM %</span> &nbsp; "
                           f"<span style='color:{theme.MUTED}; font-weight:400'>last 2 minutes</span>",
                           "sectionTitle"))
        self.chart = pg.PlotWidget()
        self.chart.setYRange(0, 100)
        self.chart.setMouseEnabled(False, False)
        self.chart.setMenuEnabled(False)
        self.chart.hideButtons()
        self.chart.showGrid(x=False, y=True, alpha=0.15)
        self.chart.getAxis("bottom").setStyle(showValues=False)
        self.cpu_curve = self.chart.plot(pen=pg.mkPen(theme.ACCENT, width=2))
        self.ram_curve = self.chart.plot(pen=pg.mkPen("#BC8CFF", width=2))
        cb.addWidget(self.chart)
        mid.addWidget(chart_box, 3)

        alert_box = QVBoxLayout()
        alert_box.setSpacing(6)
        alert_box.addWidget(label("Alerts", "sectionTitle"))
        self.alerts = QListWidget()
        self.alerts.setObjectName("alerts")
        self.alerts.setWordWrap(True)
        alert_box.addWidget(self.alerts)
        aw = QWidget()
        aw.setLayout(alert_box)
        mid.addWidget(aw, 2)
        mid_w = QWidget()
        mid_w.setLayout(mid)
        mid_w.setFixedHeight(230)
        root.addWidget(mid_w)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.btn_learn = QPushButton("Start Learning")
        self.btn_learn.setObjectName("primary")
        self.btn_learn.setToolTip("Watch this PC for a few minutes to learn what 'normal' looks like")
        self.btn_learn.clicked.connect(self.start_learning)
        self.btn_ai = QPushButton("Analyze with AI")
        self.btn_ai.clicked.connect(lambda: self.ask_ai.emit("system health and running apps"))
        self.btn_focus = QPushButton("Focus mode")
        self.btn_focus.setCheckable(True)
        self.btn_focus.setToolTip("Gaming or rendering? Pauses performance and ML alerts.\n"
                                  "Security alerts (suspicious folder, bad IP, malware) stay on.")
        self.btn_focus.toggled.connect(self._toggle_focus)
        self.mode_label = label("", "muted")
        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setVisible(False)
        controls.addWidget(self.btn_learn)
        controls.addWidget(self.btn_ai)
        controls.addWidget(self.btn_focus)
        controls.addSpacing(12)
        controls.addWidget(self.mode_label)
        controls.addWidget(self.progress)
        controls.addStretch(1)
        root.addLayout(controls)

        root.addWidget(label("Top apps (processes grouped by app) · right-click an app to trust, freeze, end or block it",
                             "sectionTitle"))
        self.table = make_table(APP_COLS, stretch_col=2)   # Publisher takes the spare width
        self.table.setSelectionMode(QAbstractItemView.NoSelection)   # keeps the status colors visible
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._app_menu)
        self._rows = []
        root.addWidget(self.table, 1)

    # --- actions -------------------------------------------------------------
    def _process_action(self, action, g):
        if action != "resume" and QMessageBox.question(
                self, "Confirm", f"{action.capitalize()} {g.name} ({g.procs} process(es))?") != QMessageBox.Yes:
            return
        pids, name = list(g.pids), g.name
        run_async(lambda: response.process_action(action, pids, name),
                  lambda r: self.add_alert_text("LOW", "Action", str(r[1]) if isinstance(r, tuple) else str(r)))

    def _toggle_focus(self, on):
        self.monitor.focus = on
        self.btn_focus.setText("Focus mode: ON" if on else "Focus mode")
        self.mode_label.setToolTip("Focus mode: only security alerts are shown" if on else "")

    def _app_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if not 0 <= row < len(self._rows):
            return
        g = self._rows[row]
        trusted = list(self.settings.get("trusted"))
        menu = QMenu(self)
        trust = menu.addAction(f"Stop trusting {g.name}" if g.trust_key in trusted else f"Trust {g.name}")
        menu.addSeparator()
        acts = {menu.addAction("Freeze (suspend) for investigation"): "suspend",
                menu.addAction("Resume"): "resume",
                menu.addAction("End process"): "end"}
        block = menu.addAction("Block internet for this app")
        block.setEnabled(g.exe.lower().endswith(".exe"))
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is block:
            self.block_app.emit(g.exe, g.name)
        elif chosen in acts:
            self._process_action(acts[chosen], g)
        if chosen is not trust:
            return
        if g.trust_key in trusted:
            trusted.remove(g.trust_key)
        else:
            trusted.append(g.trust_key)
        self.settings.set("trusted", trusted)
        self.settings.save()
    def start_learning(self):
        secs = int(self.settings.get("learning_seconds"))
        with self.monitor.lock:
            self.monitor.detector.start_learning(secs)
        self.add_alert_text("LOW", "One Eye", f"Learning mode started for {secs // 60} min {secs % 60} s. "
                                              "Use the PC normally.")

    def add_alert_text(self, severity, app, message, ts=None):
        t = time.strftime("%H:%M:%S", time.localtime(ts or time.time()))
        message = message.replace("\\", "\\​")   # zero-width space lets long paths wrap
        item = QListWidgetItem(f"{severity} · {t} · {app}\n{message}")
        item.setForeground(QColor(theme.SEVERITY_COLORS.get(severity, theme.TEXT)))
        self.alerts.insertItem(0, item)
        while self.alerts.count() > 200:
            self.alerts.takeItem(self.alerts.count() - 1)

    # --- live update ---------------------------------------------------------
    def on_update(self, snap, conns, alerts):
        self.card_cpu.update_value(f"{snap.cpu:.0f}%", f"{len(snap.apps)} apps running", snap.cpu)
        self.card_ram.update_value(f"{snap.ram_percent:.0f}%",
                                   f"{snap.ram_used_gb:.1f} / {snap.ram_total_gb:.1f} GB", snap.ram_percent)
        self.card_disk.update_value(f"{snap.disk_percent:.0f}%", "used space", snap.disk_percent)
        self.card_net.update_value(f"{snap.net_down_kbs:,.0f}", f"KB/s down · {snap.net_up_kbs:,.0f} up",
                                   snap.net_down_kbs + snap.net_up_kbs, None)

        self.cpu_hist = (self.cpu_hist + [snap.cpu])[-60:]
        self.ram_hist = (self.ram_hist + [snap.ram_percent])[-60:]
        self.cpu_curve.setData(self.cpu_hist)
        self.ram_curve.setData(self.ram_hist)

        for a in alerts:
            self.add_alert_text(a.severity, a.app, a.message, a.ts)

        det = self.monitor.detector
        if det.mode == LEARNING:
            self.progress.setVisible(True)
            self.progress.setValue(int(det.learning_progress() * 100))
            self.mode_label.setText(f"Learning… {len(det.rows)} samples")
            self.btn_learn.setEnabled(False)
        else:
            self.progress.setVisible(False)
            self.btn_learn.setEnabled(True)
            if det.mode == PROTECTING:
                self.mode_label.setText("Protect mode: ML is scoring every app")
                self.btn_learn.setText("Re-learn")
            else:
                self.mode_label.setText("ML idle. Start learning to enable anomaly detection.")

        self._fill_table(snap.apps[:MAX_ROWS], det.mode == PROTECTING)

    def _fill_table(self, apps, scoring):
        t = self.table
        self._rows = apps
        t.setUpdatesEnabled(False)
        t.setRowCount(len(apps))
        threshold = float(self.settings.get("anomaly_threshold"))
        for r, g in enumerate(apps):
            t.setItem(r, 0, cell(g.name, bold=g.status != "OK", tooltip=g.exe))
            t.setItem(r, 1, cell(g.category, theme.CATEGORY_COLORS.get(g.category)))
            pub_color = theme.OK if is_signed(g.publisher) else theme.WARN if g.publisher == UNSIGNED else (
                theme.DANGER if g.publisher.startswith("Invalid") else theme.MUTED)
            t.setItem(r, 2, cell(g.publisher or "…", pub_color, tooltip="Code-signing publisher (Windows)"))
            t.setItem(r, 3, cell(g.procs, mono=True, align_right=True))
            t.setItem(r, 4, cell(f"{g.cpu:.1f}", theme.DANGER if g.cpu > 50 else None, mono=True, align_right=True))
            t.setItem(r, 5, cell(f"{g.ram_mb:,.0f}", mono=True, align_right=True))
            t.setItem(r, 6, cell(f"{g.io_kbs:,.0f}", mono=True, align_right=True))
            t.setItem(r, 7, cell(g.connections, mono=True, align_right=True))
            if scoring:
                color = theme.DANGER if g.anomaly >= threshold else theme.WARN if g.anomaly >= 0.5 else theme.OK
                bar = "█" * round(g.anomaly * 10) + "░" * (10 - round(g.anomaly * 10))
                t.setItem(r, 8, cell(f"{bar} {g.anomaly:.2f}", color, mono=True))
            else:
                t.setItem(r, 8, cell("-", theme.MUTED))
            status_color = theme.OK if g.status in ("OK", "Trusted") else theme.DANGER if g.status in (
                "Suspicious", "Anomaly", "High CPU") else theme.WARN
            t.setItem(r, 9, cell(g.status, status_color))
        t.setUpdatesEnabled(True)
