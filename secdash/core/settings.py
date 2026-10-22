"""User settings stored as JSON in %APPDATA%\\One Eye (or ~/.secdash on Linux).

Secrets (API keys) are NOT stored here. They go to the OS credential store via `keyring`.
"""
import json
import os
import sys
from pathlib import Path

import keyring

KEYRING_SERVICE = "OneEye"

DEFAULTS = {
    "refresh_seconds": 2,
    "learning_seconds": 120,
    "advanced_mode": False,          # Simple mode hides expert options; defaults are already tuned
    "trusted": [],                   # ["name|exe path"] the user marked as trusted
    "anomaly_threshold": 0.70,
    "auto_update_feeds": True,         # refresh threat lists daily (downloads only, sends nothing)
    "online_ip_lookup": True,          # sends PUBLIC remote IPs to ipinfo.io for country info
    "scanner_engine": "builtin",       # builtin | yara | clamav
    "clamav_path": "",
    "ai_provider": "ollama",           # ollama | claude | off
    "ollama_url": "http://localhost:11434",
    "ollama_model": "llama3.2",
    "claude_model": "claude-opus-5-5",
}


def data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
        d = base / "OneEye"
    else:
        d = Path.home() / ".oneeye"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resource_dir() -> Path:
    """Folder with bundled read-only files (rules/). Works for source runs and PyInstaller .exe."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parents[2]


class Settings:
    def __init__(self):
        self.path = data_dir() / "settings.json"
        self.values = dict(DEFAULTS)
        self.load()

    def load(self):
        try:
            self.values.update(json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass

    def save(self):
        self.path.write_text(json.dumps(self.values, indent=2), encoding="utf-8")

    def get(self, key):
        return self.values.get(key, DEFAULTS.get(key))

    def set(self, key, value):
        self.values[key] = value

    # --- secrets: Windows Credential Manager / OS keychain -------------------
    @staticmethod
    def get_secret(name: str) -> str:
        try:
            return keyring.get_password(KEYRING_SERVICE, name) or ""
        except Exception:
            return ""

    @staticmethod
    def set_secret(name: str, value: str):
        if value:
            keyring.set_password(KEYRING_SERVICE, name, value)
        else:
            try:
                keyring.delete_password(KEYRING_SERVICE, name)
            except Exception:
                pass
