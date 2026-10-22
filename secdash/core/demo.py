"""HARMLESS demo helpers, so testers without Python can see One Eye detect things.

- make_demo_files(): a plain-text file whose SHA-256 is in rules/bad_hashes.txt, plus an empty
  file with a double extension. Neither is malware.
- run_demo_threat(): a fake "cryptominer" that only burns CPU. It mines nothing, connects nowhere,
  installs nothing, stops by itself, and also stops as soon as One Eye closes.
"""
import hashlib
import os
import sys
import threading
import time
from pathlib import Path

import psutil

from .settings import resource_dir

FLAG = "--demo-threat"
DISPLAY_NAME = "Demo threat (harmless)"
SAMPLE = b"SecDash harmless test sample. This is NOT malware; it exists only to demo hash-based detection.\n"
SAMPLE_SHA256 = "3873801dbdece4c81398036c9a8a4c116d75ecadfbacd56fdc2ed14ad358310b"


def make_demo_files(folder: Path | None = None) -> Path:
    folder = folder or Path.home() / "Downloads" / "OneEye_Demo"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "suspicious_sample.bin").write_bytes(SAMPLE)
    (folder / "invoice.pdf.exe").write_bytes(b"")
    return folder


def demo_threat_command(seconds: int) -> list[str]:
    """Command that starts this same program (exe or main.py) in demo-threat mode."""
    me = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, str(resource_dir() / "main.py")]
    return me + [FLAG, str(seconds), str(os.getpid())]


def run_demo_threat(seconds: int, parent_pid: int):
    stop = threading.Event()

    def burn():
        buf = os.urandom(1 << 20)
        while not stop.is_set():
            hashlib.sha256(buf).digest()   # hashlib releases the GIL, so threads use real cores

    for _ in range(max(1, (os.cpu_count() or 2) // 2)):
        threading.Thread(target=burn, daemon=True).start()
    end = time.time() + seconds
    while time.time() < end and psutil.pid_exists(parent_pid):
        time.sleep(1)
    stop.set()


def stop(proc):
    """Kill the demo and its children (a venv python.exe is a launcher with the real one as child)."""
    try:
        for p in [psutil.Process(proc.pid)] + psutil.Process(proc.pid).children(recursive=True):
            p.kill()
    except psutil.Error:
        pass


def main_from_argv(argv: list[str]):
    i = argv.index(FLAG)
    run_demo_threat(int(argv[i + 1]), int(argv[i + 2]))
