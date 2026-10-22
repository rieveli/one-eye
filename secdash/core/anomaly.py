"""ML anomaly detection: per-app baselines + Isolation Forest.

Learning mode: record each app's behavior every sample (this machine's "normal").
Training:
  1. For every app, compute its own baseline (median + spread of each feature).
     Firefox is compared with Firefox, not with Notepad, so big normal apps are not flagged.
  2. Turn every learned row into "how far is this from the app's own normal" (deviation).
  3. Fit an Isolation Forest on those deviations: it learns which deviations are normal noise.
Protect mode: score each app's current deviation. Apps never seen while learning are compared
with a pooled "typical app" baseline, so a brand-new process burning 97% CPU stands out.
Unsupervised: no labeled data needed, and training takes under a second.
"""
import json
import math
import time
from collections import defaultdict

import numpy as np

from .settings import data_dir

IDLE, LEARNING, PROTECTING = "Idle", "Learning", "Protecting"
MIN_ROWS = 60
MIN_APP_SAMPLES = 8      # apps seen fewer times than this use the pooled baseline
FLAG_STREAK = 3          # anomalous this many samples in a row before alerting
CLIP = 10.0
# minimum spread per feature, so tiny jitter on a very stable app isn't "huge deviation"
FLOOR = np.array([3.0, 0.3, 2.5, 0.7, 0.5])
SMOOTHING = 0.5          # score = 50% new + 50% previous, so one-off spikes don't flash red


def features(g) -> list[float]:
    # log1p squashes big values so a 4 GB app doesn't dwarf everything else
    return [
        g.cpu,
        math.log1p(g.ram_mb),
        math.log1p(g.io_kbs),
        math.log1p(g.connections),
        math.log1p(g.procs),
    ]


def _baseline(rows: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    med = np.median(rows, axis=0)
    mad = np.median(np.abs(rows - med), axis=0) * 1.4826   # robust standard deviation
    return med, np.maximum(mad, FLOOR)


class AnomalyDetector:
    def __init__(self):
        self.mode = IDLE
        self.model = None          # sklearn IsolationForest, imported only when needed
        self.baselines: dict[str, tuple] = {}
        self.pooled: tuple | None = None
        self.rows: list[tuple[str, list[float]]] = []
        self.learn_started = 0.0
        self.learn_until = 0.0
        self._streak: dict[str, int] = {}
        self._smoothed: dict[str, float] = {}
        self.model_path = data_dir() / "anomaly_rows.json"

    # --- persistence: Protect mode survives an app restart -------------------
    # Plain JSON rows + retrain (<1 s), never pickle: One Eye can run as admin, and a pickle in a
    # user-writable folder would let any program run code as admin.
    def load(self):
        try:
            rows = json.loads(self.model_path.read_text(encoding="utf-8"))
            self.rows = [(str(n), [float(v) for v in x]) for n, x in rows
                         if len(x) == len(FLOOR) and all(math.isfinite(float(v)) for v in x)]
        except (OSError, ValueError, TypeError):
            return
        self.train(save=False)

    def _save(self):
        try:
            self.model_path.write_text(json.dumps(self.rows), encoding="utf-8")
        except OSError:
            pass

    # --- control -------------------------------------------------------------
    def start_learning(self, seconds: int):
        self.rows = []
        self.mode = LEARNING
        self.learn_started = time.time()
        self.learn_until = self.learn_started + seconds

    def learning_progress(self) -> float:
        if self.mode != LEARNING:
            return 0.0
        total = max(self.learn_until - self.learn_started, 1)
        return min(1.0, 1.0 - max(0.0, self.learn_until - time.time()) / total)

    def _deviation(self, name: str, x: np.ndarray) -> np.ndarray:
        med, scale = self.baselines.get(name, self.pooled)
        return np.clip((x - med) / scale, -CLIP, CLIP)

    def train(self, save: bool = True) -> bool:
        if len(self.rows) < MIN_ROWS:
            return False
        per_app = defaultdict(list)
        for name, x in self.rows:
            per_app[name].append(x)
        all_rows = np.array([x for _, x in self.rows])
        self.pooled = _baseline(all_rows)
        self.baselines = {n: _baseline(np.array(xs)) for n, xs in per_app.items()
                          if len(xs) >= MIN_APP_SAMPLES}
        dev = np.array([self._deviation(n, np.array(x)) for n, x in self.rows])
        from sklearn.ensemble import IsolationForest   # heavy import, only when training
        self.model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
        self.model.fit(dev)
        self.mode = PROTECTING
        self._streak.clear()
        self._smoothed.clear()
        if save:
            self._save()
        return True

    def reset(self):
        self.model, self.baselines, self.pooled, self.rows, self.mode = None, {}, None, [], IDLE
        self._streak.clear()
        self._smoothed.clear()
        self.model_path.unlink(missing_ok=True)

    # --- per sample ----------------------------------------------------------
    def process(self, apps):
        """Learn from the apps (Learning mode) or set g.anomaly on each (Protect mode)."""
        if self.mode == LEARNING:
            for g in apps:
                if not g.name.startswith("One Eye"):
                    self.rows.append((g.name, features(g)))
            if time.time() >= self.learn_until:
                if not self.train():
                    self.learn_until = time.time() + 30   # not enough data yet, keep learning
            return

        if self.mode != PROTECTING or self.model is None or not apps:
            return

        dev = np.array([self._deviation(g.name, np.array(features(g))) for g in apps])
        df = self.model.decision_function(dev)            # >0 normal, <0 anomalous
        for g, d, z in zip(apps, df, dev):
            # Isolation Forest also flags "unusually quiet"; only "more activity than normal" matters here
            if z.max() < 3.0:
                d = max(d, 0.05)
            raw = 1.0 / (1.0 + math.exp(d * 20))           # sigmoid -> 0..1, 0.5 at the boundary
            prev = self._smoothed.get(g.name, raw if g.name not in self.baselines else 0.27)
            g.anomaly = SMOOTHING * raw + (1 - SMOOTHING) * prev
            self._smoothed[g.name] = g.anomaly
            if g.name.startswith("One Eye"):
                g.anomaly = 0.0

    def flag(self, apps, threshold: float) -> list:
        """Apps above threshold for FLAG_STREAK samples in a row."""
        out = []
        for g in apps:
            if g.anomaly >= threshold:
                self._streak[g.name] = self._streak.get(g.name, 0) + 1
                if self._streak[g.name] == FLAG_STREAK:
                    out.append(g)
            else:
                self._streak[g.name] = 0
        return out
