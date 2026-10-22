"""Response page: firewall rules (IPs and apps) and the action log. Every change is confirmed by the user."""
import sys
import time

from PySide6.QtWidgets import QLineEdit, QMessageBox, QPushButton, QVBoxLayout, QWidget

from ...core import firewall, response
from .. import theme
from ..engine import run_async
from ..widgets import cell, hrow, label, make_table, page_header


def relaunch_as_admin():
    """Restart One Eye with a UAC prompt (Windows)."""
    if sys.platform != "win32":
        return False
    import ctypes
    import os
    # absolute script path + working folder: elevated processes start in System32
    args = sys.argv[1:] if getattr(sys, "frozen", False) else [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    params = " ".join(f'"{a}"' for a in args)
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1) > 32


class FirewallPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("page")
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(page_header("Response",
                                   "Contain threats: block an IP or an app's internet in Windows Firewall. "
                                   "Every action you take in One Eye is recorded in the action log below."))

        self.admin_note = label("", "note", wrap=True)
        self.btn_admin = QPushButton("Restart as administrator")
        self.btn_admin.clicked.connect(self._relaunch)
        row = hrow(self.admin_note, self.btn_admin)
        row.setStretch(0, 1)
        root.addLayout(row)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP address to block, e.g. 203.0.113.66")
        self.ip_input.returnPressed.connect(lambda: self.request_block(self.ip_input.text()))
        self.btn_block = QPushButton("Block IP")
        self.btn_block.setObjectName("danger")
        self.btn_block.clicked.connect(lambda: self.request_block(self.ip_input.text()))
        root.addLayout(hrow(self.ip_input, self.btn_block))

        self.btn_unblock = QPushButton("Remove selected rule")
        self.btn_unblock.clicked.connect(self._unblock_selected)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        root.addLayout(hrow(label("Firewall rules by One Eye", "sectionTitle"), None, refresh, self.btn_unblock))
        self.table = make_table(["Target", "Type", "Direction", "Enabled"], stretch_col=0)
        self._rules = []
        root.addWidget(self.table, 1)

        root.addWidget(label("Action log (audit trail)", "sectionTitle"))
        self.log_table = make_table(["Time", "Action", "Target", "Result"], stretch_col=2)
        root.addWidget(self.log_table, 1)
        self.status = label("", "muted", wrap=True)
        root.addWidget(self.status)
        self._update_admin()

    def _update_admin(self):
        admin = firewall.is_admin()
        self.admin_note.setText("Running as administrator: firewall changes are enabled." if admin else
                                "Not running as administrator. Viewing works, but blocking needs admin rights "
                                "(least privilege: One Eye only asks for them when you need them).")
        self.btn_admin.setVisible(not admin)
        self.btn_block.setEnabled(admin)
        self.btn_unblock.setEnabled(admin)

    def _relaunch(self):
        if relaunch_as_admin():
            from PySide6.QtWidgets import QApplication
            QApplication.instance().quit()
        else:
            self.status.setText("Could not restart as administrator (UAC prompt was cancelled).")

    def showEvent(self, e):
        super().showEvent(e)
        self.refresh()

    def refresh(self):
        def done(rules):
            if isinstance(rules, Exception):
                self.status.setText(f"Could not list rules: {rules}")
                return
            self._rules = rules
            self.table.setRowCount(len(rules))
            for r, d in enumerate(rules):
                self.table.setItem(r, 0, cell(d["target"], mono=d["kind"] == "IP", tooltip=d["rule"]))
                self.table.setItem(r, 1, cell(d["kind"]))
                self.table.setItem(r, 2, cell(d["directions"]))
                self.table.setItem(r, 3, cell("Yes" if d["enabled"] else "No",
                                              theme.DANGER if d["enabled"] else theme.MUTED))
        run_async(firewall.list_blocked, done)
        entries = response.read_log()
        self.log_table.setRowCount(len(entries))
        for r, e in enumerate(entries):
            self.log_table.setItem(r, 0, cell(time.strftime("%m-%d %H:%M:%S", time.localtime(e["ts"])), mono=True))
            self.log_table.setItem(r, 1, cell(e["action"]))
            self.log_table.setItem(r, 2, cell(e["target"], tooltip=e.get("detail", "")))
            self.log_table.setItem(r, 3, cell("OK" if e["ok"] else "Failed", theme.OK if e["ok"] else theme.DANGER))

    # --- changes (always confirmed by the human, always logged) ---------------
    def _confirm_and_run(self, title, question, action, target, fn):
        if not firewall.is_admin():
            self.status.setText("This needs administrator rights. Use 'Restart as administrator'.")
            return
        if QMessageBox.question(self, title, question) != QMessageBox.Yes:
            return

        def done(result):
            ok, msg = (False, str(result)) if isinstance(result, Exception) else result
            response.log(action, target, ok, "" if ok else msg)
            self.status.setText(("✔ " if ok else "✖ ") + msg)
            self.refresh()
        run_async(fn, done)

    def request_block(self, text: str):
        try:
            ip = firewall.validate_ip(text)
        except ValueError as e:
            self.status.setText(str(e))
            return
        self.ip_input.clear()
        self._confirm_and_run("Block IP address", f"Block all traffic to and from {ip}?", "block IP", ip,
                              lambda: firewall.block_ip(ip))

    def request_block_app(self, exe: str, name: str):
        try:
            exe = firewall.validate_app(exe)
        except ValueError as e:
            self.status.setText(str(e))
            return
        self._confirm_and_run("Block app internet", f"Block all internet access for {name}?\n{exe}",
                              "block app", exe, lambda: firewall.block_app(exe))

    def _unblock_selected(self):
        row = self.table.currentRow()
        if not 0 <= row < len(self._rules):
            self.status.setText("Select a rule first.")
            return
        d = self._rules[row]
        self._confirm_and_run("Remove rule", f"Remove the One Eye block for {d['target']}?", "unblock",
                              d["target"], lambda: firewall.remove_rule(d["rule"]))
