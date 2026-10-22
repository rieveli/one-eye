"""Malware Scanner with pluggable engines.

- builtin : SHA-256 hash matching against known-malware lists + simple heuristics
- yara    : YARA rules from rules/yara/*.yar (needs the optional `yara-python` package)
- clamav  : the open-source ClamAV engine (needs clamscan installed)

Third-party engines are treated as untrusted plugins: optional, disclosed, and version-pinned.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import requests

from .collector import is_suspicious_path
from .settings import data_dir, resource_dir

MAX_FILE_MB = 100
EXEC_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com"}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|jpg|png|txt|zip)\.(exe|scr|bat|cmd|js|vbs|com)$", re.I)
HASH_FEEDS = {
    # abuse.ch MalwareBazaar: SHA-256 of recently seen malware (CC0)
    "malwarebazaar_recent.txt": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
}
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


@dataclass
class Finding:
    path: str
    verdict: str        # MALICIOUS | SUSPICIOUS
    detail: str
    engine: str


def is_admin_only_path(path: str) -> bool:
    p = os.path.normcase(os.path.realpath(path))
    roots = [os.environ.get(v) for v in ("ProgramFiles", "ProgramFiles(x86)", "SystemRoot")]
    return any(r and p.startswith(os.path.normcase(r) + os.sep) for r in roots)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(root: Path):
    for dirpath, _, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            try:
                if p.is_file() and p.stat().st_size <= MAX_FILE_MB * 1_048_576:
                    yield p
            except OSError:
                continue


class Engine:
    key = ""
    label = ""

    def available(self) -> tuple[bool, str]:
        return True, ""

    def scan(self, root: Path, progress, cancelled) -> list[Finding]:
        raise NotImplementedError


class BuiltinEngine(Engine):
    key, label = "builtin", "Built-in (SHA-256 hashes + heuristics)"

    def __init__(self):
        self.hashes: dict[str, str] = {}
        self.reload()

    def reload(self):
        hashes = {}
        sources = [(resource_dir() / "rules" / "bad_hashes.txt", "One Eye list")]
        sources += [(data_dir() / "feeds" / n, "MalwareBazaar") for n in HASH_FEEDS]
        for path, label in sources:
            try:
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip().strip('"').lower()
                    if len(line) >= 64 and not line.startswith("#"):
                        hashes[line[:64]] = label
            except OSError:
                pass
        self.hashes = hashes

    def update_feeds(self) -> str:
        folder = data_dir() / "feeds"
        folder.mkdir(exist_ok=True)
        msgs = []
        for name, url in HASH_FEEDS.items():
            try:
                r = requests.get(url, timeout=20)
                r.raise_for_status()
                (folder / name).write_text(r.text, encoding="utf-8")
                msgs.append(f"{name}: OK")
            except requests.RequestException as e:
                msgs.append(f"{name}: failed ({e.__class__.__name__})")
        self.reload()
        return f"{'; '.join(msgs)}. {len(self.hashes)} malware hashes loaded."

    def scan(self, root, progress, cancelled):
        files = list(iter_files(root))
        out = []
        for i, p in enumerate(files, 1):
            if cancelled():
                break
            if i % 50 == 0 or i == len(files):   # fewer UI updates, so big folders don't freeze it
                progress(i, len(files), str(p))
            try:
                digest = sha256_file(p)
            except OSError:
                continue
            if digest in self.hashes:
                out.append(Finding(str(p), "MALICIOUS",
                                   f"SHA-256 matches {self.hashes[digest]} ({digest[:16]}…)", self.key))
                continue
            if DOUBLE_EXT.search(p.name):
                out.append(Finding(str(p), "SUSPICIOUS", "Double extension (e.g. invoice.pdf.exe)", self.key))
            elif p.suffix.lower() in EXEC_EXT and is_suspicious_path(str(p)):
                out.append(Finding(str(p), "SUSPICIOUS", "Executable inside a Temp/Downloads/Public folder",
                                   self.key))
        return out


class YaraEngine(Engine):
    key, label = "yara", "YARA rules (plugin)"

    def available(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            return False, "Install the optional plugin: pip install yara-python"
        if not list((resource_dir() / "rules" / "yara").glob("*.yar")):
            return False, "No .yar files in rules/yara/"
        return True, ""

    def scan(self, root, progress, cancelled):
        import yara
        files_map = {f.stem: str(f) for f in (resource_dir() / "rules" / "yara").glob("*.yar")}
        rules = yara.compile(filepaths=files_map)
        files = list(iter_files(root))
        out = []
        for i, p in enumerate(files, 1):
            if cancelled():
                break
            if i % 50 == 0 or i == len(files):   # fewer UI updates, so big folders don't freeze it
                progress(i, len(files), str(p))
            try:
                matches = rules.match(str(p), timeout=10)
            except yara.Error:
                continue
            if matches:
                out.append(Finding(str(p), "MALICIOUS", "YARA: " + ", ".join(m.rule for m in matches),
                                   self.key))
        return out


class ClamAVEngine(Engine):
    key, label = "clamav", "ClamAV (plugin)"

    def __init__(self, settings):
        self.settings = settings

    def _exe(self):
        # Only run a clamscan that lives in an admin-only folder: settings.json is user-writable,
        # and One Eye may run as admin, so a planted path must not get admin rights.
        for c in (self.settings.get("clamav_path"), shutil.which("clamscan")):
            if c and Path(c).is_file() and is_admin_only_path(c):
                return c
        return ""

    def available(self):
        if not self._exe():
            return False, ("ClamAV not found. Install it (clamav.net) under C:\\Program Files "
                           "and set its path in Settings.")
        return True, ""

    def scan(self, root, progress, cancelled):
        progress(0, 0, "ClamAV is scanning (this can take a while)…")
        try:
            r = subprocess.run([self._exe(), "-r", "--infected", "--no-summary", str(root)],
                               capture_output=True, text=True, timeout=3600, creationflags=_NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"ClamAV failed: {e}")
        if r.returncode == 2:   # 0 = clean, 1 = found, 2 = error (e.g. no virus database yet)
            raise RuntimeError("ClamAV error: " + (r.stderr.strip().splitlines() or ["unknown"])[-1]
                               + " (run freshclam first?)")
        out = []
        for line in r.stdout.splitlines():
            if line.endswith(" FOUND") and ": " in line:
                path, sig = line.rsplit(": ", 1)
                out.append(Finding(path, "MALICIOUS", "ClamAV: " + sig.removesuffix(" FOUND"), self.key))
        return out


def build_engines(settings) -> dict[str, Engine]:
    engines = [BuiltinEngine(), YaraEngine(), ClamAVEngine(settings)]
    return {e.key: e for e in engines}
