"""AI Assistant page. Advisory only: it reads a redacted snapshot and returns text."""
import json

from PySide6.QtWidgets import (QComboBox, QLineEdit, QPlainTextEdit, QPushButton, QStackedWidget,
                               QVBoxLayout, QWidget)

from ...core import ai
from ..engine import run_async
from ..widgets import hrow, label, page_header

PROVIDERS = [("Local AI (Ollama)", "ollama"), ("Claude API", "claude"), ("Off", "off")]
CLAUDE_MODELS = ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]


class AIPage(QWidget):
    def __init__(self, settings, state):
        super().__init__()
        self.setObjectName("page")
        self.settings, self.state = settings, state
        self._last_data = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(page_header("AI Assistant",
                                   "Sends a redacted snapshot of this PC to the selected model and explains "
                                   "what it sees in plain language."))
        note = label("🔒  AI is advisory only. It cannot change your system: it has no access to the "
                     "firewall, processes or files. You make every change yourself.", "note", wrap=True)
        root.addWidget(note)

        self.provider = QComboBox()
        for text, key in PROVIDERS:
            self.provider.addItem(text, key)
        self.provider.setCurrentIndex(max(0, self.provider.findData(settings.get("ai_provider"))))
        self.provider.currentIndexChanged.connect(self._provider_changed)

        # provider-specific options
        self.options = QStackedWidget()
        ollama_w = QWidget()
        self.ollama_model = QComboBox()
        self.ollama_model.setEditable(True)
        self.ollama_model.setMinimumWidth(200)
        self.ollama_model.setCurrentText(settings.get("ollama_model"))
        self.ollama_url = QLineEdit(settings.get("ollama_url"))
        refresh = QPushButton("Find models")
        refresh.clicked.connect(self._refresh_ollama)
        ol = hrow(label("Model", "muted"), self.ollama_model, label("URL", "muted"), self.ollama_url, refresh)
        ol.setContentsMargins(0, 0, 0, 0)
        ollama_w.setLayout(ol)

        claude_w = QWidget()
        self.claude_model = QComboBox()
        self.claude_model.setEditable(True)
        self.claude_model.addItems(CLAUDE_MODELS)
        self.claude_model.setCurrentText(settings.get("claude_model"))
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.Password)
        self.api_key.setPlaceholderText("API key (stored in Windows Credential Manager)")
        if settings.get_secret("anthropic_api_key"):
            self.api_key.setPlaceholderText("API key saved ✔ (type to replace)")
        save_key = QPushButton("Save key")
        save_key.clicked.connect(self._save_key)
        cl = hrow(label("Model", "muted"), self.claude_model, self.api_key, save_key)
        cl.setContentsMargins(0, 0, 0, 0)
        claude_w.setLayout(cl)

        off_w = QWidget()
        offl = hrow(label("AI features are turned off.", "muted"))
        offl.setContentsMargins(0, 0, 0, 0)
        off_w.setLayout(offl)
        for w in (ollama_w, claude_w, off_w):
            self.options.addWidget(w)
        self.options.setFixedHeight(42)
        root.addLayout(hrow(label("Provider", "muted"), self.provider, self.options))

        self.focus = QComboBox()
        self.focus.addItems(["everything", "system health and running apps", "network connections",
                             "alerts"])
        self.question = QLineEdit()
        self.question.setPlaceholderText("Optional question, e.g. 'Why is my PC slow?' or 'Is anything suspicious?'")
        self.question.returnPressed.connect(lambda: self.analyze())
        self.btn_go = QPushButton("Analyze current snapshot")
        self.btn_go.setObjectName("primary")
        self.btn_go.clicked.connect(lambda: self.analyze())
        self.btn_show = QPushButton("Show data sent")
        self.btn_show.setToolTip("Transparency: see exactly what was sent to the AI")
        self.btn_show.clicked.connect(self._show_data)
        root.addLayout(hrow(label("Focus", "muted"), self.focus, self.question))
        root.addLayout(hrow(self.btn_go, self.btn_show, None))

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("The AI's analysis will appear here.")
        root.addWidget(self.output, 1)
        self.status = label("", "muted")
        root.addWidget(self.status)
        self._provider_changed()

    def provider_label(self) -> str:
        key = self.provider.currentData()
        if key == "ollama":
            return f"Ollama · {self.ollama_model.currentText()}"
        if key == "claude":
            return f"Claude · {self.claude_model.currentText()}"
        return "Off"

    def _provider_changed(self):
        key = self.provider.currentData()
        self.options.setCurrentIndex([k for _, k in PROVIDERS].index(key))
        self.btn_go.setEnabled(key != "off")
        self.settings.set("ai_provider", key)
        self.settings.save()
        if key == "ollama":
            self._refresh_ollama()

    def _refresh_ollama(self):
        url = self.ollama_url.text().strip()

        def done(models):
            current = self.ollama_model.currentText()
            self.ollama_model.clear()
            if isinstance(models, list) and models:
                self.ollama_model.addItems(models)
                if current not in models:
                    current = models[0]
                self.status.setText(f"Ollama: {len(models)} model(s) installed.")
            else:
                self.status.setText("Ollama not reachable. Install: winget install Ollama.Ollama, "
                                    "then: ollama pull llama3.2")
            self.ollama_model.setCurrentText(current)
        run_async(lambda: ai.ollama_models(url), done)

    def _save_key(self):
        self.settings.set_secret("anthropic_api_key", self.api_key.text().strip())
        self.api_key.clear()
        self.api_key.setPlaceholderText("API key saved ✔ (type to replace)")
        self.status.setText("API key saved to Windows Credential Manager.")

    def _show_data(self):
        if self._last_data is None and self.state.snap is not None:
            self._last_data = ai.build_snapshot(self.state.snap, self.state.conns, self.state.alerts)
        self.output.setPlainText("Data sent to the AI (redacted):\n\n" + json.dumps(self._last_data, indent=2)
                                 if self._last_data else "No data yet.")

    def analyze(self, focus: str | None = None):
        if focus:
            self.focus.setCurrentText(focus)
        if self.state.snap is None:
            self.status.setText("Waiting for the first system sample…")
            return
        key = self.provider.currentData()
        if key == "off":
            self.status.setText("AI is turned off. Choose a provider first.")
            return
        data = ai.build_snapshot(self.state.snap, self.state.conns, self.state.alerts,
                                 self.focus.currentText())
        self._last_data = data
        question = self.question.text()
        self.settings.set("ollama_model", self.ollama_model.currentText())
        self.settings.set("ollama_url", self.ollama_url.text().strip())
        self.settings.set("claude_model", self.claude_model.currentText())
        self.settings.save()

        if key == "ollama":
            url, model = self.ollama_url.text().strip(), self.ollama_model.currentText()
            job = lambda: ai.ask_ollama(url, model, data, question)  # noqa: E731
        else:
            api_key, model = self.settings.get_secret("anthropic_api_key"), self.claude_model.currentText()
            job = lambda: ai.ask_claude(api_key, model, data, question)  # noqa: E731

        self.btn_go.setEnabled(False)
        self.output.setPlainText(f"Analyzing with {self.provider_label()}…")
        self.status.setText("Sending redacted snapshot…")

        def done(text):
            self.btn_go.setEnabled(True)
            self.output.setPlainText(str(text))
            self.status.setText(f"Answer from {self.provider_label()}. Advisory only: review before acting.")
        run_async(job, done)
