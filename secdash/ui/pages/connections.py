"""Connection Analyzer page: process -> remote IP -> country -> risk, with one-click block."""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QPushButton, QVBoxLayout, QWidget

from .. import theme
from ..engine import run_async
from ..widgets import cell, hrow, label, make_table, page_header

COLS = ["Process", "PID", "Remote IP", "Port", "Country", "Organization", "State", "Risk", "Why"]


class ConnectionsPage(QWidget):
    ask_ai = Signal(str)
    block_requested = Signal(str)

    def __init__(self, monitor, settings):
        super().__init__()
        self.setObjectName("page")
        self.monitor, self.settings = monitor, settings
        self.conns = []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(page_header("Connection Analyzer",
                                   "Every active network connection: which app, which IP, which country, "
                                   "and how risky it looks."))

        self.public_only = QCheckBox("Public internet only")
        self.public_only.setChecked(True)
        self.public_only.toggled.connect(lambda: self._fill())
        self.btn_block = QPushButton("Block selected IP")
        self.btn_block.setObjectName("danger")
        self.btn_block.clicked.connect(self._block_selected)
        self.btn_feed = QPushButton("Update threat feed")
        self.btn_feed.setToolTip("Download abuse.ch Feodo Tracker botnet C2 IP list")
        self.btn_feed.clicked.connect(self._update_feed)
        self.btn_ai = QPushButton("Analyze with AI")
        self.btn_ai.clicked.connect(lambda: self.ask_ai.emit("network connections"))
        self.summary = label("", "muted")
        root.addLayout(hrow(self.public_only, self.summary, None, self.btn_feed, self.btn_ai, self.btn_block))
        self.advanced_widgets = [self.btn_feed]

        self.table = make_table(COLS, stretch_col=8)
        root.addWidget(self.table, 1)
        self.status = label("", "muted")
        root.addWidget(self.status)
        self._update_intel_label()

    def _update_intel_label(self):
        n = len(self.monitor.analyzer.intel.bad_ips)
        self.status.setText(f"Threat intel: {n} known-bad IPs loaded. Country lookup: "
                            + ("ipinfo.io (public IPs only)" if self.settings.get("online_ip_lookup") else "off"))

    def on_update(self, snap, conns, alerts):
        self.conns = conns
        self._fill()

    def _visible(self):
        return [c for c in self.conns if c.scope == "Public"] if self.public_only.isChecked() else self.conns

    def _fill(self):
        selected = self._selected_ip()
        rows = self._visible()
        risky = sum(1 for c in self.conns if c.risk in ("HIGH", "MED"))
        self.summary.setText(f"{len(self.conns)} connections · {risky} risky")
        t = self.table
        t.setUpdatesEnabled(False)
        t.setRowCount(len(rows))
        for r, c in enumerate(rows):
            t.setItem(r, 0, cell(c.process, bold=c.risk != "OK"))
            t.setItem(r, 1, cell(c.pid, mono=True, align_right=True))
            t.setItem(r, 2, cell(c.remote_ip, mono=True))
            t.setItem(r, 3, cell(c.remote_port, mono=True, align_right=True))
            t.setItem(r, 4, cell(c.country or ("-" if c.scope != "Public" else "…"), mono=True))
            t.setItem(r, 5, cell(c.org or c.scope, theme.MUTED))
            t.setItem(r, 6, cell(c.state, theme.MUTED))
            t.setItem(r, 7, cell(c.risk, theme.SEVERITY_COLORS[c.risk], bold=True))
            why = "; ".join(c.reasons)
            t.setItem(r, 8, cell(why, theme.MUTED, tooltip=why))
            if c.remote_ip == selected:
                t.selectRow(r)
        t.setUpdatesEnabled(True)

    def _selected_ip(self) -> str:
        row = self.table.currentRow()
        item = self.table.item(row, 2) if row >= 0 else None
        return item.text() if item and self.table.selectionModel().hasSelection() else ""

    def _block_selected(self):
        ip = self._selected_ip()
        if ip:
            self.block_requested.emit(ip)
        else:
            self.status.setText("Select a connection first.")

    def _update_feed(self):
        self.btn_feed.setEnabled(False)
        self.status.setText("Downloading threat feed…")

        def done(result):
            self.btn_feed.setEnabled(True)
            self.status.setText(str(result))
        run_async(self.monitor.analyzer.intel.update_feeds, done)
