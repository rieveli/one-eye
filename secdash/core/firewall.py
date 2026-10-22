"""Firewall Control: block IPs or an app's internet access using Windows Firewall.

Security notes (see docs/DECISIONS.md, point 5):
- IPs are validated with `ipaddress` and app paths are checked before they reach a command
- commands run as argument lists, never through a shell, so there is no command injection
- every rule we create starts with "OneEye-", and we only ever remove rules matching our own pattern
"""
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PREFIX = "OneEye-Block-"       # + IP
APP_PREFIX = "OneEye-App-"     # + short hash of the program path (the path itself goes in the description)
OWN_RULE = re.compile(r"OneEye-(Block-[0-9A-Fa-f:.]+|App-[0-9a-f]{12})")
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:   # not Windows
        return False


def validate_ip(text: str) -> str:
    """Return the normalized IP or raise ValueError with a user-friendly reason."""
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        raise ValueError(f"'{text}' is not a valid IP address")
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError(f"Refusing to block {ip}: loopback/unspecified/multicast address")
    return str(ip)


def validate_app(path: str) -> str:
    p = Path(path)
    if not (p.is_absolute() and p.is_file() and p.suffix.lower() == ".exe"):
        raise ValueError(f"Not a program file: {path}")
    windows = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + os.sep
    if os.path.normcase(str(p.resolve())).startswith(windows):
        raise ValueError("Refusing to block Windows components (it could break your PC)")
    return str(p.resolve())


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30, creationflags=_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return r.returncode == 0, ((r.stdout or "") + (r.stderr or "")).strip()


def _add(name: str, directions: tuple[str, ...], match: list[str]) -> tuple[bool, str]:
    if not is_admin():
        return False, "Administrator rights are required. Use 'Restart as administrator'."
    for direction in directions:
        ok, msg = _run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                        f"dir={direction}", "action=block", "enable=yes", *match])
        if not ok:
            remove_rule(name)   # no half-block
            return False, msg
    return True, ""


def block_ip(text: str) -> tuple[bool, str]:
    ip = validate_ip(text)
    ok, msg = _add(PREFIX + ip, ("out", "in"), [f"remoteip={ip}"])
    return ok, f"Blocked {ip} (inbound + outbound)" if ok else msg


def block_app(path: str) -> tuple[bool, str]:
    exe = validate_app(path)
    name = APP_PREFIX + hashlib.sha256(exe.lower().encode()).hexdigest()[:12]
    ok, msg = _add(name, ("out",), [f"program={exe}", f"description={exe}"])
    return ok, (f"Blocked internet for {Path(exe).name}. New connections are blocked; end the process "
                "to cut ones already open.") if ok else msg


def remove_rule(name: str) -> tuple[bool, str]:
    if not OWN_RULE.fullmatch(name):
        return False, "Not a One Eye rule"
    ok, msg = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    return ok, f"Removed {name}" if ok else msg


def list_blocked() -> list[dict]:
    """One Eye's rules: [{'rule', 'kind': 'IP'|'App', 'target', 'directions', 'enabled'}]."""
    if sys.platform != "win32":
        return []
    ps = ("Get-NetFirewallRule -DisplayName 'OneEye-*' -ErrorAction SilentlyContinue | "
          "Select-Object DisplayName, Description, @{n='Direction';e={$_.Direction.ToString()}}, "
          "@{n='Enabled';e={$_.Enabled.ToString()}} | ConvertTo-Json -Compress")
    ok, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
    try:
        data = json.loads(out) if ok and out else []
    except ValueError:
        return []
    rules: dict[str, dict] = {}
    for r in [data] if isinstance(data, dict) else data:
        name = r.get("DisplayName", "")
        if not OWN_RULE.fullmatch(name):
            continue
        app = name.startswith(APP_PREFIX)
        d = rules.setdefault(name, {"rule": name, "kind": "App" if app else "IP", "directions": [], "enabled": True,
                                    "target": (r.get("Description") or name) if app else name[len(PREFIX):]})
        d["directions"].append("In" if r.get("Direction") == "Inbound" else "Out")
        d["enabled"] = d["enabled"] and r.get("Enabled") == "True"
    for d in rules.values():
        d["directions"] = ", ".join(sorted(d["directions"]))
    return sorted(rules.values(), key=lambda d: (d["kind"], d["target"].lower()))
