"""Malware Scanner page with selectable engines (plugins)."""
import os
import tempfile
import threading
import time
from pathlib import Path

from PySide6.QtWidgets import (QComboBox, QFileDialog, QLineEdit, QMessageBox, QProgressBar, QPushButton,
                               QVBoxLayout, QWidget)

from ...core import response
from ...core.scanner import build_engines
from .. import theme
from ..engine import run_async
from ..widgets import cell, hrow, label, make_table, page_header


class ScannerPage(QWidget):
    def __init__(self, settings):
        super().__init__()
        self.setObjectName("page")
        self.settings = settings
        self.engines = build_engines(settings)
        self._cancel = threading.Event()

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(page_header("Malware Scanner",
                                   "Scan a folder with SHA-256 hash matching, YARA rules, or ClamAV. "
                                   "Nothing is moved or deleted unless you choose to: quarantine is reversible."))

        self.folder = QLineEdit(str(Path.home() / "Downloads"))
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        root.addLayout(hrow(label("Folder", "muted"), self.folder, browse))
        quick = [("Downloads", Path.home() / "Downloads", "Where downloaded files land"),
                 ("Temp", Path(tempfile.gettempdir()), "Malware often unpacks itself here"),
                 ("Startup folder", Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu"
                  / "Programs" / "Startup", "Programs here run at every login (persistence)")]
        buttons = []
        for text, path, tip in quick:
            b = QPushButton(f"Quick scan: {text}")
            b.setToolTip(f"{tip}\n{path}")
            b.clicked.connect(lambda _=False, p=path: self.scan_folder(p))
            buttons.append(b)
        root.addLayout(hrow(*buttons, None))

        self.engine_box = QComboBox()
        for e in self.engines.values():
            ok, why = e.available()
            self.engine_box.addItem(e.label + ("" if ok else "  (not installed)"), e.key)
            if not ok:
                self.engine_box.setItemData(self.engine_box.count() - 1, why, 3)  # tooltip role
        idx = self.engine_box.findData(settings.get("scanner_engine"))
        self.engine_box.setCurrentIndex(max(idx, 0))
        self.engine_box.currentIndexChanged.connect(self._engine_changed)
        self.btn_scan = QPushButton("Scan")
        self.btn_scan.setObjectName("primary")
        self.btn_scan.clicked.connect(self._scan)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel.set)
        self.btn_feed = QPushButton("Update hash feed")
        self.btn_feed.setToolTip("Download recent malware SHA-256 hashes from abuse.ch MalwareBazaar")
        self.btn_feed.clicked.connect(self._update_feed)
        engine_label = label("Engine", "muted")
        root.addLayout(hrow(engine_label, self.engine_box, self.btn_scan, self.btn_cancel, None, self.btn_feed))
        self.advanced_widgets = [engine_label, self.engine_box, self.btn_feed]

        self.engine_note = label("", "note", wrap=True)
        root.addWidget(self.engine_note)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.current = label("", "muted")
        root.addWidget(self.progress)
        root.addWidget(self.current)

        self.table = make_table(["Verdict", "File", "Detail", "Engine"], stretch_col=1)
        root.addWidget(self.table, 1)
        btn_q = QPushButton("Quarantine selected")
        btn_q.setObjectName("danger")
        btn_q.setToolTip("Moves the file into One Eye's quarantine (scrambled, can't run). You can restore it later.")
        btn_q.clicked.connect(self._quarantine_selected)
        root.addLayout(hrow(None, btn_q))

        root.addWidget(label("Quarantine", "sectionTitle"))
        self.qtable = make_table(["File (original location)", "Quarantined", "SHA-256"], stretch_col=0)
        root.addWidget(self.qtable, 1)
        btn_restore = QPushButton("Restore")
        btn_restore.clicked.connect(lambda: self._q_action("restore"))
        btn_delete = QPushButton("Delete permanently")
        btn_delete.setObjectName("danger")
        btn_delete.clicked.connect(lambda: self._q_action("delete"))
        self.q_status = label("", "muted")
        root.addLayout(hrow(self.q_status, None, btn_restore, btn_delete))
        self._findings, self._quarantined = [], []
        self._refresh_quarantine()
        self._engine_changed()

    def _engine(self):
        return self.engines[self.engine_box.currentData()]

    def _engine_changed(self):
        e = self._engine()
        ok, why = e.available()
        if e.key == "builtin":
            why = f"{len(e.hashes)} known-malware hashes loaded. Tip: Settings > 'Create demo files' makes harmless test files."
        self.engine_note.setText(why if why else "Plugin ready.")
        self.btn_scan.setEnabled(ok)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Folder to scan", self.folder.text())
        if d:
            self.folder.setText(d)

    def scan_folder(self, path: Path):
        if self.btn_cancel.isEnabled():   # a scan is already running
            return
        self.folder.setText(str(path))
        self._scan()

    def _scan(self):
        root = Path(self.folder.text())
        if not root.is_dir():
            self.current.setText("That folder does not exist.")
            return
        engine = self._engine()
        self._cancel.clear()
        self.table.setRowCount(0)
        self.btn_scan.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress.setRange(0, 0)

        def work(progress):
            return engine.scan(root, progress, self._cancel.is_set)

        run_async(work, self._done, self._on_progress)

    def _on_progress(self, i, total, text):
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(i)
        self.current.setText(text if len(text) < 120 else "…" + text[-118:])

    def _done(self, result):
        self.btn_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        if isinstance(result, Exception):
            self.current.setText(f"Scan failed: {result}")
            return
        self._findings = result
        self.table.setRowCount(len(result))
        for r, f in enumerate(result):
            color = theme.DANGER if f.verdict == "MALICIOUS" else theme.WARN
            self.table.setItem(r, 0, cell(f.verdict, color, bold=True))
            self.table.setItem(r, 1, cell(f.path, tooltip=f.path))
            self.table.setItem(r, 2, cell(f.detail))
            self.table.setItem(r, 3, cell(f.engine, theme.MUTED))
        state = "cancelled" if self._cancel.is_set() else "finished"
        self.current.setText(f"Scan {state}: {len(result)} finding(s)."
                             + ("" if result else " Nothing suspicious found."))

    # --- quarantine (always confirmed, always logged) ------------------------
    def _quarantine_selected(self):
        row = self.table.currentRow()
        if not 0 <= row < len(self._findings) or not self.table.selectionModel().hasSelection():
            self.q_status.setText("Select a finding first.")
            return
        path = self._findings[row].path
        if QMessageBox.question(self, "Quarantine", f"Move this file into quarantine?\n{path}") != QMessageBox.Yes:
            return
        ok, msg = response.quarantine(path)
        self.q_status.setText(("✔ " if ok else "✖ ") + msg)
        if ok:
            self.table.removeRow(row)
            del self._findings[row]
        self._refresh_quarantine()

    def _q_action(self, action):
        row = self.qtable.currentRow()
        if not 0 <= row < len(self._quarantined) or not self.qtable.selectionModel().hasSelection():
            self.q_status.setText("Select a quarantined file first.")
            return
        q = self._quarantined[row]
        question = (f"Restore this file to its original location?\n{q['original']}" if action == "restore" else
                    f"Delete this file permanently? This cannot be undone.\n{q['original']}")
        if QMessageBox.question(self, action.capitalize(), question) != QMessageBox.Yes:
            return
        ok, msg = (response.restore if action == "restore" else response.delete)(q["id"])
        self.q_status.setText(("✔ " if ok else "✖ ") + msg)
        self._refresh_quarantine()

    def _refresh_quarantine(self):
        self._quarantined = response.list_quarantine()
        self.qtable.setRowCount(len(self._quarantined))
        for r, q in enumerate(self._quarantined):
            self.qtable.setItem(r, 0, cell(q["original"], tooltip=q["original"]))
            self.qtable.setItem(r, 1, cell(time.strftime("%Y-%m-%d %H:%M", time.localtime(q["ts"])), mono=True))
            self.qtable.setItem(r, 2, cell(q["sha256"][:16] + "…", theme.MUTED, mono=True, tooltip=q["sha256"]))

    def _update_feed(self):
        self.btn_feed.setEnabled(False)
        self.engine_note.setText("Downloading hash feed…")

        def done(msg):
            self.btn_feed.setEnabled(True)
            self.engine_note.setText(str(msg))
        run_async(self.engines["builtin"].update_feeds, done)
