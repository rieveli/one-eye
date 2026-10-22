"""Incident response: quarantine files, freeze/end processes, and an action log.

Every action is started by the user in the UI (never by the AI) and written to the action log,
following contain -> investigate -> eradicate. Quarantine is reversible; delete only from quarantine.
"""
import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path

import psutil

from .settings import data_dir

KEY = 0xA5   # files are XOR-scrambled in quarantine so they can't run and AVs don't re-flag them
# killing these crashes Windows (blue screen): never offer it
CRITICAL = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
            "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "memory compression", "secure system"}


def _qdir() -> Path:
    d = data_dir() / "quarantine"
    d.mkdir(exist_ok=True)
    return d


def _scramble(data: bytes) -> bytes:
    return bytes(b ^ KEY for b in data)


# --- action log -----------------------------------------------------------
# shortcut: the log sits in a user-writable folder, so malware running as you could edit it;
# upgrade to the Windows Event Log if One Eye is used beyond a single trusted PC.
def log(action: str, target: str, ok: bool, detail: str = ""):
    entry = {"ts": time.time(), "action": action, "target": target, "ok": ok, "detail": detail}
    with open(data_dir() / "actions.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_log(limit: int = 200) -> list[dict]:
    try:
        lines = (data_dir() / "actions.log").read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# --- files ----------------------------------------------------------------
def quarantine(path: str) -> tuple[bool, str]:
    src = Path(path)
    try:
        data = src.read_bytes()
        qid = uuid.uuid4().hex
        blob = _qdir() / f"{qid}.bin"
        blob.write_bytes(_scramble(data))
        if blob.stat().st_size != len(data):          # copy must be complete before the original goes
            blob.unlink()
            raise OSError("quarantine copy incomplete")
        (_qdir() / f"{qid}.json").write_text(json.dumps({
            "original": str(src.resolve()), "sha256": hashlib.sha256(data).hexdigest(), "ts": time.time()}))
        try:
            src.unlink()
        except OSError:
            blob.unlink(missing_ok=True)
            (_qdir() / f"{qid}.json").unlink(missing_ok=True)
            raise
    except OSError as e:
        log("quarantine", path, False, str(e))
        return False, f"Could not quarantine (file in use or access denied): {e}"
    log("quarantine", path, True)
    return True, f"Quarantined {src.name}"


def list_quarantine() -> list[dict]:
    out = []
    for meta in sorted(_qdir().glob("*.json")):
        try:
            d = json.loads(meta.read_text(encoding="utf-8"))
            out.append({"id": meta.stem, "original": str(d["original"]), "sha256": str(d.get("sha256", "")),
                        "ts": float(d.get("ts", 0))})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return out


def _entry(qid: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", qid):       # no path tricks via the id
        raise ValueError("bad quarantine id")
    return json.loads((_qdir() / f"{qid}.json").read_text(encoding="utf-8"))


def restore(qid: str) -> tuple[bool, str]:
    try:
        target = Path(_entry(qid)["original"]).resolve()
        # The record lives in a user-writable folder; when One Eye runs as admin, an edited record
        # must not let anyone write files outside the user's own folder.
        if Path.home().resolve() not in target.parents:
            raise ValueError("restore is only allowed inside your user folder")
        if target.exists():
            raise ValueError("a file with that name already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_scramble((_qdir() / f"{qid}.bin").read_bytes()))
        (_qdir() / f"{qid}.bin").unlink()
        (_qdir() / f"{qid}.json").unlink()
    except (OSError, ValueError, KeyError) as e:
        log("restore", qid, False, str(e))
        return False, f"Could not restore: {e}"
    log("restore", str(target), True)
    return True, f"Restored {target.name}"


def delete(qid: str) -> tuple[bool, str]:
    try:
        original = _entry(qid)["original"]
        (_qdir() / f"{qid}.bin").unlink()
        (_qdir() / f"{qid}.json").unlink()
    except (OSError, ValueError, KeyError) as e:
        log("delete", qid, False, str(e))
        return False, f"Could not delete: {e}"
    log("delete", original, True)
    return True, f"Deleted {Path(original).name} permanently"


# --- processes ------------------------------------------------------------
def process_action(action: str, pids: list[int], name: str) -> tuple[bool, str]:
    """action: suspend | resume | end. Works on every process of an app (and children on end)."""
    procs = []
    for pid in pids:
        try:
            p = psutil.Process(pid)
            if pid == os.getpid() or pid <= 4 or p.name().lower() in CRITICAL:
                return False, f"Refusing to {action} {p.name()}: critical system process or One Eye itself"
            procs.append(p)
            if action == "end":
                procs += p.children(recursive=True)
        except psutil.Error:
            continue
    errors = []
    for p in procs:
        try:
            {"suspend": p.suspend, "resume": p.resume, "end": p.kill}[action]()
        except psutil.NoSuchProcess:
            continue
        except psutil.Error as e:
            errors.append(str(e))
    ok = bool(procs) and not errors
    log(action, name, ok, "; ".join(errors[:3]))
    if not procs:
        return False, f"{name}: no running process found"
    return ok, f"{action.capitalize()}: {name} ({len(procs)} process(es))" + (
        "" if ok else f". Some failed (admin needed?): {errors[0]}")
