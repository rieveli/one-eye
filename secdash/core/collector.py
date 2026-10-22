"""Collects system stats and per-process usage, grouped by application.

Chrome runs 30+ processes, so we sum them into one "Google Chrome" row.
On Windows, all process stats come from ONE system call per sample (see winproc.py);
psutil is only used once per new process to look up its path.
"""
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field

import psutil

from . import demo, winproc
from .categories import PROTECTED, SECURITY, UNKNOWN, classify

CPU_COUNT = psutil.cpu_count() or 1
INTERPRETERS = {"python.exe", "pythonw.exe", "python", "python3"}
OWN_EXE = os.path.basename(sys.executable).lower()   # OneEye.exe when built

# Executables running from these folders are a classic malware indicator.
SUSPICIOUS_DIRS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\",
                   "\\users\\public\\", "\\$recycle.bin\\", "/tmp/", "/dev/shm/")


@dataclass
class AppGroup:
    name: str
    category: str
    pids: list = field(default_factory=list)
    exe: str = ""
    cpu: float = 0.0            # % of whole machine (0-100)
    ram_mb: float = 0.0
    io_kbs: float = 0.0         # disk read+write KB/s
    connections: int = 0
    suspicious_path: bool = False
    oldest_start: float = 0.0
    anomaly: float = 0.0        # filled in by the detector
    status: str = "OK"
    publisher: str = ""         # code-signing label (see signature.py), "" while unchecked
    trusted: bool = False       # user marked it trusted: no performance/ML alerts

    @property
    def trust_key(self) -> str:
        return f"{self.name}|{self.exe.lower()}"   # name AND path, so a copy elsewhere isn't trusted

    @property
    def procs(self) -> int:
        return len(self.pids)


@dataclass
class Snapshot:
    ts: float
    cpu: float
    ram_percent: float
    ram_used_gb: float
    ram_total_gb: float
    disk_percent: float
    net_up_kbs: float
    net_down_kbs: float
    apps: list
    connections: list           # raw psutil connections (inet)
    self_ram_mb: float
    self_cpu: float


def is_suspicious_path(path: str) -> bool:
    p = (path or "").lower()
    return any(d in p for d in SUSPICIOUS_DIRS)


class Collector:
    def __init__(self):
        # pid -> (create_time key, display, category, exe, start epoch)
        self._ident: dict[int, tuple] = {}
        self._prev: dict[int, tuple[float, int]] = {}   # pid -> (cpu_time, io_bytes)
        self._prev_ts = 0.0
        self._net_prev = None
        self._self_pid = os.getpid()
        psutil.cpu_percent(None)

    # --- identity (looked up once per process) -------------------------------
    @staticmethod
    def _script_of(proc) -> str:
        """Return the .py script an interpreter process is running, if any."""
        try:
            cmd = proc.cmdline()
            for arg in cmd[1:]:
                if arg.lower().endswith((".py", ".pyw")):
                    return arg
            # multiprocessing workers have no script name: use their parent's
            if "--multiprocessing-fork" in cmd or any("spawn_main" in a for a in cmd):
                parent = proc.parent()
                if parent is not None:
                    return Collector._script_of(parent)
        except psutil.Error:
            pass
        return ""

    def _identify(self, pid: int, name: str) -> tuple[str, str, str, float]:
        """(display name, category, exe/script path, start epoch) for a new process."""
        exe, start = "", time.time()
        try:
            proc = psutil.Process(pid)
            start = proc.create_time()
            exe = proc.exe() or ""
        except psutil.Error:
            proc = None
        if pid == self._self_pid:
            return "One Eye (this app)", SECURITY, exe, start
        if proc is not None and name.lower() in INTERPRETERS | {OWN_EXE}:
            try:
                if demo.FLAG in proc.cmdline():
                    # label by script, not python.exe (which is signed by the Python Software Foundation)
                    return demo.DISPLAY_NAME, UNKNOWN, self._script_of(proc) or exe, start
            except psutil.Error:
                pass
        if proc is not None and name.lower() in INTERPRETERS:
            # Scripts all run as python.exe; name them by script so each is visible.
            script = self._script_of(proc)
            if script:
                return f"{name.split('.')[0]}: {os.path.basename(script)}", UNKNOWN, script, start
        display, category = classify(name, exe)
        if not exe and category == UNKNOWN and proc is not None:
            # path hidden from normal users; malware running as SYSTEM looks like this too
            category = PROTECTED
        return display, category, exe, start

    # --- raw per-process stats: {pid: (name, cpu_time_s, rss_bytes, io_bytes, create_key)} ----
    def _raw_stats(self) -> dict[int, tuple]:
        fast = winproc.snapshot()
        if fast is not None:
            return {pid: tuple(s) for pid, s in fast.items()}
        out = {}
        for p in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                with p.oneshot():
                    t = p.cpu_times()
                    rss = p.memory_info().rss
                    try:
                        io = p.io_counters()
                        io_b = io.read_bytes + io.write_bytes
                    except (psutil.AccessDenied, AttributeError):
                        io_b = 0
                out[p.pid] = (p.info["name"] or "?", t.user + t.system, rss, io_b, p.info["create_time"])
            except psutil.Error:
                continue
        return out

    def _system_drive(self) -> str:
        return os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/"

    def sample(self) -> Snapshot:
        now = time.time()
        dt = now - self._prev_ts if self._prev_ts else 0.0

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []
        conn_count = defaultdict(int)
        for c in conns:
            if c.pid and c.raddr:
                conn_count[c.pid] += 1

        raw = self._raw_stats()
        groups: dict[str, AppGroup] = {}
        new_prev = {}
        self_cpu = self_ram = 0.0
        for pid, (name, cpu_time, rss, io_bytes, create_key) in raw.items():
            if pid == 0:
                continue  # System Idle Process: its "CPU" is free CPU
            ident = self._ident.get(pid)
            if ident is None or ident[0] != create_key:       # new process (or PID reused)
                ident = (create_key,) + self._identify(pid, name or "?")
                self._ident[pid] = ident
                prev = None
            else:
                prev = self._prev.get(pid)
            _, display, category, exe, start = ident
            new_prev[pid] = (cpu_time, io_bytes)

            cpu = io_kbs = 0.0
            if prev and dt > 0:
                cpu = max(0.0, (cpu_time - prev[0]) / dt / CPU_COUNT * 100)
                io_kbs = max(0.0, (io_bytes - prev[1]) / dt / 1024)
            ram = rss / 1_048_576
            if pid == self._self_pid:
                self_cpu, self_ram = cpu, ram

            g = groups.get(display)
            if g is None:
                g = groups[display] = AppGroup(name=display, category=category, exe=exe, oldest_start=start)
            g.pids.append(pid)
            g.cpu += cpu
            g.ram_mb += ram
            g.io_kbs += io_kbs
            g.connections += conn_count.get(pid, 0)
            if exe and not g.exe:
                g.exe = exe
            if is_suspicious_path(exe):
                g.suspicious_path = True
                g.exe = exe
            g.oldest_start = min(g.oldest_start, start)

        # forget processes that exited
        self._prev, self._prev_ts = new_prev, now
        for pid in list(self._ident):
            if pid not in raw:
                del self._ident[pid]

        # --- whole system ----------------------------------------------------
        vm = psutil.virtual_memory()
        try:
            disk = psutil.disk_usage(self._system_drive()).percent
        except OSError:
            disk = 0.0
        net = psutil.net_io_counters()
        up = down = 0.0
        if self._net_prev:
            t0, s0, r0 = self._net_prev
            ndt = max(now - t0, 1e-6)
            up, down = (net.bytes_sent - s0) / ndt / 1024, (net.bytes_recv - r0) / ndt / 1024
        self._net_prev = (now, net.bytes_sent, net.bytes_recv)

        apps = sorted(groups.values(), key=lambda g: (g.cpu, g.ram_mb), reverse=True)
        return Snapshot(
            ts=now, cpu=psutil.cpu_percent(None), ram_percent=vm.percent,
            ram_used_gb=vm.used / 1024**3, ram_total_gb=vm.total / 1024**3,
            disk_percent=disk, net_up_kbs=up, net_down_kbs=down,
            apps=apps, connections=conns, self_ram_mb=self_ram, self_cpu=self_cpu,
        )
