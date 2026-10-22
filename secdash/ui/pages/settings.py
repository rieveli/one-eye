"""Settings page: Simple/Advanced mode, privacy, ML and plugin options, and harmless demo tools."""
import subprocess
import sys

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFormLayout, QFrame, QLineEdit,
                               QMessageBox, QPushButton, QSpinBox, QVBoxLayout, QWidget)

from ...core import demo
from ...core.settings import data_dir
from ..widgets import hrow, label, page_header

DEMO_SECONDS = 60
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class SettingsPage(QWidget):
    mode_changed = Signal(bool)          # True = Advanced mode

    def __init__(self, settings, monitor, scanner_page):
        super().__init__()
        self.setObjectName("page")
        self.settings, self.monitor = settings, monitor
        self._demo_proc = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(page_header("Settings", f"Saved to {data_dir() / 'settings.json'}. "
                                               "API keys are kept in Windows Credential Manager, not in this file."))

        general = QFrame()
        general.setObjectName("card")
        gl = QVBoxLayout(general)
        gl.setContentsMargins(18, 14, 18, 14)
        self.online = QCheckBox("Look up country/organization of public IPs (sends public IPs to ipinfo.io)")
        self.online.setChecked(bool(settings.get("online_ip_lookup")))
        self.online.toggled.connect(self._save)
        self.auto_feeds = QCheckBox("Update threat lists automatically once a day (abuse.ch, Emerging Threats; "
                                    "downloads only, nothing about this PC is sent)")
        self.auto_feeds.setChecked(bool(settings.get("auto_update_feeds")))
        self.auto_feeds.toggled.connect(self._save)
        self.advanced = QCheckBox("Advanced mode: show expert options (engines, feeds, ML tuning)")
        self.advanced.setChecked(bool(settings.get("advanced_mode")))
        self.advanced.toggled.connect(self._toggle_advanced)
        gl.addWidget(self.online)
        gl.addWidget(self.auto_feeds)
        gl.addWidget(self.advanced)
        root.addWidget(general)

        box = QFrame()
        box.setObjectName("card")
        form = QFormLayout(box)
        form.setContentsMargins(18, 16, 18, 16)
        form.setVerticalSpacing(12)
        form.setHorizontalSpacing(18)
        self.refresh = QSpinBox()
        self.refresh.setRange(1, 30)
        self.refresh.setSuffix(" s")
        self.refresh.setValue(int(settings.get("refresh_seconds")))
        form.addRow("Refresh interval", self.refresh)
        self.learning = QSpinBox()
        self.learning.setRange(60, 3600)
        self.learning.setSingleStep(60)
        self.learning.setSuffix(" s")
        self.learning.setValue(int(settings.get("learning_seconds")))
        form.addRow("ML learning duration", self.learning)
        self.threshold = QDoubleSpinBox()
        self.threshold.setRange(0.5, 0.99)
        self.threshold.setSingleStep(0.05)
        self.threshold.setValue(float(settings.get("anomaly_threshold")))
        form.addRow("Anomaly alert threshold", self.threshold)
        self.engine = QComboBox()
        for key, e in scanner_page.engines.items():
            self.engine.addItem(e.label, key)
        self.engine.setCurrentIndex(max(0, self.engine.findData(settings.get("scanner_engine"))))
        form.addRow("Default scanner engine", self.engine)
        for w in (self.refresh, self.learning, self.threshold):
            w.setMaximumWidth(160)
        self.engine.setMaximumWidth(420)
        self.clamav = QLineEdit(settings.get("clamav_path"))
        self.clamav.setPlaceholderText(r"e.g. C:\Program Files\ClamAV\clamscan.exe (must be under Program Files)")
        form.addRow("ClamAV plugin path", self.clamav)
        root.addWidget(box)

        save = QPushButton("Save settings")
        save.setObjectName("primary")
        save.clicked.connect(self._save)
        reset = QPushButton("Reset ML model")
        reset.setObjectName("danger")
        reset.clicked.connect(self._reset_ml)
        clear_trust = QPushButton("Clear trusted apps")
        clear_trust.clicked.connect(self._clear_trusted)
        root.addLayout(hrow(save, reset, clear_trust, None))
        self.status = label("", "muted")
        root.addWidget(self.status)

        root.addWidget(label("Demo (harmless, for testing One Eye)", "sectionTitle"))
        self.btn_demo = QPushButton(f"Run demo threat ({DEMO_SECONDS} s)")
        self.btn_demo.setToolTip("Starts a fake 'cryptominer' that only burns CPU. Stops by itself "
                                 "and when One Eye closes. Installs nothing.")
        self.btn_demo.clicked.connect(self._toggle_demo)
        files = QPushButton("Create demo files")
        files.setToolTip("Writes harmless test files to Downloads\\OneEye_Demo for the Malware Scanner")
        files.clicked.connect(self._demo_files)
        root.addLayout(hrow(self.btn_demo, files, None))
        root.addWidget(label("Tip: for the full demo, click Start Learning on System Health first, "
                             "wait until Protect mode, then run the demo threat.", "muted", wrap=True))

        plugins = label(
            "Plugins & third-party components: built-in engine (SHA-256 + heuristics, always on) · "
            "YARA rules (data files in rules/yara, needs yara-python) · ClamAV (separate program) · "
            "threat feeds: abuse.ch Feodo Tracker & MalwareBazaar (CC0) · IP lookup: ipinfo.io · Local AI: Ollama. "
            "Plugins are data or separate engines, never downloaded code.", "muted", wrap=True)
        root.addWidget(plugins)
        root.addStretch(1)
        self.advanced_widgets = [box, plugins]

    def _toggle_advanced(self, on):
        self.settings.set("advanced_mode", on)
        self.settings.save()
        self.mode_changed.emit(on)

    def _save(self):
        s = self.settings
        s.set("refresh_seconds", self.refresh.value())
        s.set("learning_seconds", self.learning.value())
        s.set("anomaly_threshold", round(self.threshold.value(), 2))
        s.set("online_ip_lookup", self.online.isChecked())
        s.set("auto_update_feeds", self.auto_feeds.isChecked())
        s.set("scanner_engine", self.engine.currentData())
        s.set("clamav_path", self.clamav.text().strip())
        s.save()
        self.status.setText("Saved.")

    def _reset_ml(self):
        if QMessageBox.question(self, "Reset ML model",
                                "Delete the learned baseline? You will need to run Learning mode again.") \
                != QMessageBox.Yes:
            return
        with self.monitor.lock:
            self.monitor.detector.reset()
        self.status.setText("ML model deleted.")

    def _clear_trusted(self):
        self.settings.set("trusted", [])
        self.settings.save()
        self.status.setText("Trusted apps cleared.")

    # --- demo ----------------------------------------------------------------
    def _toggle_demo(self):
        if self._demo_proc and self._demo_proc.poll() is None:
            demo.stop(self._demo_proc)
            return
        self._demo_proc = subprocess.Popen(demo.demo_threat_command(DEMO_SECONDS), creationflags=_NO_WINDOW)
        self.btn_demo.setText("Stop demo threat")
        self._watch_demo()

    def _watch_demo(self):
        if self._demo_proc and self._demo_proc.poll() is None:
            QTimer.singleShot(1000, self._watch_demo)
        else:
            self.btn_demo.setText(f"Run demo threat ({DEMO_SECONDS} s)")

    def _demo_files(self):
        folder = demo.make_demo_files()
        self.status.setText(f"Demo files written to {folder}. Scan it in Malware Scanner (Quick scan: Downloads).")

    def stop_demo(self):
        if self._demo_proc and self._demo_proc.poll() is None:
            demo.stop(self._demo_proc)
