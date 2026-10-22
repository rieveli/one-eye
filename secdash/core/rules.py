"""Rule-based alerts. Rules catch KNOWN problems; the ML detector catches UNKNOWN ones."""
import time
from collections import defaultdict
from dataclasses import dataclass

from .categories import BACKGROUND, GAME, SECURITY, WATCHED
from .signature import is_signed

HIGH, MED, LOW = "HIGH", "MED", "LOW"
SUSTAINED_SAMPLES = 3        # condition must hold this many samples in a row
REPEAT_AFTER_S = 120         # don't repeat the same alert more often than this


@dataclass
class Alert:
    ts: float
    severity: str
    app: str
    message: str
    source: str = "rule"     # rule | ml | net


class RuleEngine:
    def __init__(self):
        self._streak = defaultdict(int)
        self._last_fired: dict[str, float] = {}

    def fire(self, out, key, severity, app, message, source="rule", repeat_after=REPEAT_AFTER_S):
        now = time.time()
        if now - self._last_fired.get(key, 0) < repeat_after:
            return
        self._last_fired[key] = now
        out.append(Alert(now, severity, app, message, source))

    def _sustained(self, key, condition: bool) -> bool:
        self._streak[key] = self._streak[key] + 1 if condition else 0
        return self._streak[key] >= SUSTAINED_SAMPLES

    def evaluate(self, snap, focus: bool = False) -> list[Alert]:
        """Security alerts always run. Performance alerts are skipped in Focus mode and for trusted apps."""
        out: list[Alert] = []
        ram_total_mb = snap.ram_total_gb * 1024
        for g in snap.apps:
            if g.category == SECURITY and g.name.startswith("One Eye"):
                continue
            if g.suspicious_path:
                g.status = "Suspicious"
                self.fire(out, f"path:{g.name}", HIGH, g.name,
                           f"Running from a suspicious location: {g.exe}")
            perf = not (focus or g.trusted)
            # unverified + unsigned apps get a lower bar: a miner throttled to a few cores is still a problem
            strict = g.category in WATCHED and not is_signed(g.publisher)
            cpu_limit = 20 if strict else 50
            if self._sustained(f"cpu:{g.name}", perf and g.cpu > cpu_limit and g.category != GAME):
                sev = HIGH if strict else MED
                g.status = "High CPU"
                self.fire(out, f"cpu:{g.name}", sev, g.name,
                           f"Sustained high CPU: {g.cpu:.0f}%"
                           + (" (unverified, unsigned app: possible cryptominer)" if strict else ""))
            if perf and g.ram_mb > max(2048, ram_total_mb * 0.25):
                g.status = "High RAM" if g.status == "OK" else g.status
                self.fire(out, f"ram:{g.name}", MED, g.name,
                           f"Using {g.ram_mb / 1024:.1f} GB RAM ({g.ram_mb / ram_total_mb:.0%} of total)")
            if (perf and g.category in (BACKGROUND, GAME) and g.cpu < 0.5 and g.ram_mb > 300
                    and time.time() - g.oldest_start > 1800):
                g.status = "Idle" if g.status == "OK" else g.status
                self.fire(out, f"idle:{g.name}", LOW, g.name,
                           f"Idle in background for a long time but holding {g.ram_mb:.0f} MB RAM. Close it?")
            if strict and not g.trusted and g.connections > 20:
                self.fire(out, f"conn:{g.name}", MED, g.name,
                           f"Unknown app with {g.connections} open network connections")
        if self._sustained("sys:ram", not focus and snap.ram_percent > 90):
            self.fire(out, "sys:ram", MED, "System", f"RAM almost full: {snap.ram_percent:.0f}%")
        if self._sustained("sys:cpu", not focus and snap.cpu > 90):
            self.fire(out, "sys:cpu", MED, "System", f"CPU saturated: {snap.cpu:.0f}%")
        return out
