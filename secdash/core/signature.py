"""Code-signing check: is this program digitally signed, and by whom (e.g. "Valve Corp.")?

Uses Windows' own Get-AuthenticodeSignature, once per new file, in a background thread.
Paths go in through stdin as JSON, never into the command line, so a file name can't inject commands.
"""
import json
import subprocess
import sys
import threading

UNSIGNED, UNKNOWN = "Unsigned", "?"
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_SCRIPT = (
    "$p = [Console]::In.ReadToEnd() | ConvertFrom-Json; "
    "@($p | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue } "
    "| ForEach-Object { [pscustomobject]@{ "
    "Path = $_.Path; Status = $_.Status.ToString(); "
    "Signer = $(if ($_.SignerCertificate) { $_.SignerCertificate.GetNameInfo('SimpleName', $false) } else { '' }) "
    "} }) | ConvertTo-Json -Compress"
)


def is_signed(label: str) -> bool:
    """True when the label is a publisher name (a valid signature)."""
    return bool(label) and label not in (UNSIGNED, UNKNOWN) and not label.startswith("Invalid")


def label_for(status: str, signer: str) -> str:
    if status == "Valid":
        return signer or UNKNOWN
    if status in ("NotSigned", "UnknownError", "NotSupportedFileFormat"):   # scripts can't carry one
        return UNSIGNED
    return f"Invalid ({status})"     # HashMismatch = file changed after signing: a red flag


def check(paths: list[str]) -> dict[str, str]:
    """{path: label} for each path. One PowerShell run for the whole list."""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _SCRIPT],
                           input=json.dumps(paths), capture_output=True, text=True, timeout=120,
                           creationflags=_NO_WINDOW)
        rows = json.loads(r.stdout or "[]")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {p: UNKNOWN for p in paths}
    if isinstance(rows, dict):
        rows = [rows]
    out = {p: UNKNOWN for p in paths}
    lower = {p.lower(): p for p in paths}
    for row in rows:
        p = lower.get(str(row.get("Path", "")).lower())
        if p:
            out[p] = label_for(row.get("Status", ""), row.get("Signer", ""))
    return out


class SignatureCache:
    def __init__(self):
        self.labels: dict[str, str] = {}
        self._busy = threading.Lock()

    def refresh(self, paths):
        """Start a background check for paths not seen yet (no-op if one is already running)."""
        new = [p for p in dict.fromkeys(paths) if p and p not in self.labels]
        if new and self._busy.acquire(blocking=False):
            threading.Thread(target=self._run, args=(new[:200],), daemon=True).start()

    def _run(self, paths):
        try:
            self.labels.update(check(paths))
        finally:
            self._busy.release()
