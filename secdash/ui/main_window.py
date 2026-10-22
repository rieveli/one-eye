"""Main window: sidebar navigation + pages + live status block."""
import time

from PySide6.QtWidgets import (QFrame, QHBoxLayout, QListWidget, QMainWindow, QStackedWidget,
                               QVBoxLayout, QWidget)

from .. import APP_NAME, __version__
from ..core.anomaly import LEARNING, PROTECTING
from ..core.firewall import is_admin
from . import theme
from ..core.settings import data_dir
from .engine import MonitorThread, run_async
from .eye import EyeWidget
from .pages.ai import AIPage
from .pages.connections import ConnectionsPage
from .pages.firewall import FirewallPage
from .pages.health import HealthPage
from .pages.scanner import ScannerPage
from .pages.settings import SettingsPage
from .widgets import label


class AppState:
    """Latest data, shared with pages that need it on demand (AI Assistant)."""

    def __init__(self):
        self.snap = None
        self.conns = []
        self.alerts = []


class MainWindow(QMainWindow):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.state = AppState()
        self.setWindowTitle(f"{APP_NAME} · Security Dashboard")
        self.resize(1360, 860)
        self.setMinimumSize(1100, 700)

        self.monitor = MonitorThread(settings)

        self.health = HealthPage(self.monitor, settings)
        self.connections = ConnectionsPage(self.monitor, settings)
        self.firewall = FirewallPage()
        self.scanner = ScannerPage(settings)
        self.ai = AIPage(settings, self.state)
        self.settings_page = SettingsPage(settings, self.monitor, self.scanner)
        pages = [("System Health", self.health), ("Connections", self.connections),
                 ("Response", self.firewall), ("Malware Scanner", self.scanner),
                 ("AI Assistant", self.ai), ("Settings", self.settings_page)]

        # --- sidebar ---------------------------------------------------------
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(230)
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(0, 0, 0, 0)
        sb.setSpacing(0)
        brand = QWidget()
        bl = QHBoxLayout(brand)
        bl.setContentsMargins(14, 16, 10, 14)
        bl.setSpacing(10)
        self.eye = EyeWidget(46, fps=20)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(label("ONE EYE", "brand"))
        names.addWidget(label(f"Endpoint security · v{__version__}", "brandSub"))
        bl.addWidget(self.eye)
        bl.addLayout(names, 1)
        sb.addWidget(brand)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        for name, _ in pages:
            self.nav.addItem(name)
        sb.addWidget(self.nav, 1)

        status = QFrame()
        status.setObjectName("statusBlock")
        st = QVBoxLayout(status)
        st.setContentsMargins(12, 10, 12, 10)
        st.setSpacing(4)
        self.st_protect = label("Protection: starting…", "statusLine")
        self.st_ai = label("", "statusLine")
        self.st_admin = label("", "statusLine")
        self.st_self = label("", "statusLine")
        self.st_self.setToolTip("One Eye measures its own footprint (native Qt UI, no browser engine)")
        for w in (self.st_protect, self.st_ai, self.st_admin, self.st_self):
            st.addWidget(w)
        sb.addWidget(status)

        self.stack = QStackedWidget()
        for _, page in pages:
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        root = QWidget()
        root.setObjectName("root")
        lay = QHBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(sidebar)
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        # --- wiring ----------------------------------------------------------
        self.health.ask_ai.connect(self.open_ai)
        self.health.block_app.connect(self.block_app)
        self.connections.ask_ai.connect(self.open_ai)
        self.connections.block_requested.connect(self.block_from_connections)
        self.monitor.updated.connect(self.on_update)
        self.settings_page.mode_changed.connect(self.apply_mode)
        self.apply_mode(bool(settings.get("advanced_mode")))
        self.monitor.start()
        self._auto_update_feeds()

    def _auto_update_feeds(self):
        """Refresh threat lists in the background if they are older than a day."""
        newest = max((f.stat().st_mtime for f in (data_dir() / "feeds").glob("*.txt")), default=0)
        if not self.settings.get("auto_update_feeds") or time.time() - newest < 86400:
            return
        intel, hashes = self.monitor.analyzer.intel, self.scanner.engines["builtin"]
        run_async(lambda: (intel.update_feeds(), hashes.update_feeds()),
                  lambda _: (self.connections._update_intel_label(), self.scanner._engine_changed()))

    def apply_mode(self, advanced: bool):
        """Simple mode hides expert controls; the defaults behind them are already tuned."""
        for page in (self.scanner, self.connections, self.settings_page):
            for w in page.advanced_widgets:
                w.setVisible(advanced)

    def open_ai(self, focus: str):
        self.nav.setCurrentRow(4)
        self.ai.analyze(focus)

    def block_app(self, exe: str, name: str):
        self.nav.setCurrentRow(2)
        self.firewall.request_block_app(exe, name)

    def block_from_connections(self, ip: str):
        self.nav.setCurrentRow(2)
        self.firewall.ip_input.setText(ip)
        self.firewall.request_block(ip)

    def on_update(self, snap, conns, alerts):
        self.state.snap, self.state.conns = snap, conns
        self.state.alerts = (self.state.alerts + alerts)[-200:]
        self.eye.alert = any(a.severity == "HIGH" and snap.ts - a.ts < 60 for a in self.state.alerts)
        self.health.on_update(snap, conns, alerts)
        self.connections.on_update(snap, conns, alerts)

        mode = self.monitor.detector.mode
        color = theme.OK if mode == PROTECTING else theme.INFO if mode == LEARNING else theme.MUTED
        self.st_protect.setText(f"Protection: <span style='color:{color}'>● {mode}</span>")
        self.st_ai.setText(f"AI: {self.ai.provider_label()}")
        self.st_admin.setText("Admin: yes" if is_admin() else "Admin: no (firewall read-only)")
        self.st_self.setText(f"One Eye itself: {snap.self_ram_mb:.0f} MB · {snap.self_cpu:.1f}% CPU")

    def closeEvent(self, e):
        self.settings_page.stop_demo()
        self.monitor.stop()
        super().closeEvent(e)
