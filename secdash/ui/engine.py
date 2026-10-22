"""Background monitoring thread + helper to run slow jobs off the UI thread."""
import threading
import time

from PySide6.QtCore import QObject, QRunnable, QThread, QThreadPool, Signal

from ..core.anomaly import AnomalyDetector
from ..core.collector import Collector
from ..core.connections import ConnectionAnalyzer
from ..core.rules import HIGH, MED, Alert, RuleEngine
from ..core.signature import SignatureCache, is_signed


class MonitorThread(QThread):
    """Samples the system every N seconds and emits the results to the UI."""

    updated = Signal(object, object, object)   # snapshot, connections, new alerts

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.collector = Collector()
        self.rules = RuleEngine()
        self.detector = AnomalyDetector()
        self.analyzer = ConnectionAnalyzer(settings)
        self.signatures = SignatureCache()
        self.focus = False                    # Focus mode: gaming/rendering, performance alerts paused
        self.lock = threading.Lock()          # guards detector use from UI thread
        self._stop = threading.Event()

    def run(self):
        with self.lock:
            self.detector.load()              # retrain from saved rows, off the UI thread
        self.collector.sample()               # prime CPU counters
        while not self._stop.is_set():
            started = time.time()
            try:
                self._tick()
            except Exception as e:            # never let the monitor thread die
                print("monitor error:", e)
            wait = max(0.2, float(self.settings.get("refresh_seconds")) - (time.time() - started))
            self._stop.wait(wait)

    def _tick(self):
        snap = self.collector.sample()
        self.signatures.refresh([g.exe for g in snap.apps])
        trusted = set(self.settings.get("trusted"))
        for g in snap.apps:
            g.publisher = self.signatures.labels.get(g.exe, "")
            g.trusted = g.trust_key in trusted
        with self.lock:
            self.detector.process(snap.apps)
            flagged = self.detector.flag(snap.apps, float(self.settings.get("anomaly_threshold")))
        alerts = self.rules.evaluate(snap, self.focus)
        for g in flagged:
            if self.focus or g.trusted:
                continue
            g.status = "Anomaly"
            alerts.append(Alert(snap.ts, HIGH if g.anomaly > 0.85 and not is_signed(g.publisher) else MED, g.name,
                                f"ML anomaly score {g.anomaly:.2f}: behavior is unusual for this PC "
                                f"(CPU {g.cpu:.0f}%, RAM {g.ram_mb:.0f} MB, {g.connections} conns)", "ml"))
        for g in snap.apps:
            if g.trusted and g.status == "OK":
                g.status = "Trusted"
            elif g.anomaly >= float(self.settings.get("anomaly_threshold")) and g.status == "OK":
                g.status = "Anomaly"
        conns = self.analyzer.analyze(snap.connections, snap.apps)
        for c in conns:
            if c.risk == "HIGH":
                self.rules.fire(alerts, f"net:{c.remote_ip}", HIGH, c.process,
                                f"Risky connection to {c.remote_ip}:{c.remote_port}: " + "; ".join(c.reasons),
                                "net", repeat_after=300)
        self.updated.emit(snap, conns, alerts)

    def stop(self):
        self._stop.set()
        self.wait(5000)


class _Signals(QObject):
    done = Signal(object)
    progress = Signal(int, int, str)


class _Job(QRunnable):
    def __init__(self, fn, with_progress):
        super().__init__()
        self.fn, self.with_progress = fn, with_progress
        self.signals = _Signals()

    def run(self):
        try:
            result = self.fn(self.signals.progress.emit) if self.with_progress else self.fn()
        except Exception as e:
            result = e
        try:
            self.signals.done.emit(result)
        except RuntimeError:   # window closed while the job was running: nobody left to tell
            pass


_running: set = set()


def run_async(fn, on_done, on_progress=None):
    """Run fn() in a worker thread; on_done(result) runs on the UI thread.
    If on_progress is given, fn receives a progress(i, total, text) callback."""
    job = _Job(fn, on_progress is not None)
    _running.add(job)

    def finished(result):
        _running.discard(job)
        on_done(result)

    job.signals.done.connect(finished)
    if on_progress:
        job.signals.progress.connect(on_progress)
    QThreadPool.globalInstance().start(job)
