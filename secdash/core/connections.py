"""Connection Analyzer: which process talks to which IP, where it is, and how risky it looks."""
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import psutil
import requests

from .categories import WATCHED
from .signature import is_signed
from .settings import data_dir, resource_dir

# Remote ports worth a second look, with the reason shown to the user.
SUSPICIOUS_PORTS = {
    4444: "Metasploit default port",
    1337: "Common backdoor port",
    31337: "Classic backdoor port (Back Orifice)",
    6667: "IRC, often used for botnet C2",
    5555: "Android Debug Bridge",
    23: "Telnet (plaintext)",
    21: "FTP (plaintext)",
    3389: "Outbound RDP",
    9001: "Tor relay port",
}

FEEDS = {   # file name -> (url, label). Downloaded and checked locally: nothing about this PC is sent.
    "feodo_ips.txt": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Feodo Tracker (botnet C2)"),
    "et_compromised_ips.txt": ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                               "Emerging Threats (compromised host)"),
}


@dataclass
class ConnInfo:
    process: str
    pid: int
    local: str
    remote_ip: str
    remote_port: int
    state: str
    scope: str                 # Public | Private | Loopback
    country: str = ""
    org: str = ""
    risk: str = "OK"           # OK | LOW | MED | HIGH
    reasons: list = field(default_factory=list)


def ip_scope(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "Invalid"
    if a.is_loopback:
        return "Loopback"
    if a.is_private or a.is_link_local or a.is_multicast or a.is_unspecified:
        return "Private"
    return "Public"


class ThreatIntel:
    """Known-bad IP list from a bundled file plus downloaded public feeds."""

    def __init__(self):
        self.bad_ips: dict[str, str] = {}
        self.reload()

    @staticmethod
    def _parse(path, label, out):
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                token = line.split()[0].split(",")[0]
                try:
                    out[str(ipaddress.ip_address(token))] = label
                except ValueError:
                    continue
        except OSError:
            pass

    def reload(self):
        bad = {}
        self._parse(resource_dir() / "rules" / "bad_ips.txt", "One Eye list", bad)
        for name, (_, label) in FEEDS.items():
            self._parse(data_dir() / "feeds" / name, label, bad)
        self.bad_ips = bad

    def update_feeds(self) -> str:
        folder = data_dir() / "feeds"
        folder.mkdir(exist_ok=True)
        results = []
        for name, (url, _) in FEEDS.items():
            try:
                r = requests.get(url, timeout=15)
                r.raise_for_status()
                (folder / name).write_text(r.text, encoding="utf-8")
                results.append(f"{name}: OK")
            except requests.RequestException as e:
                results.append(f"{name}: failed ({e.__class__.__name__})")
        self.reload()
        return f"{'; '.join(results)}. {len(self.bad_ips)} bad IPs loaded."


class GeoLookup:
    """Country/organization for public IPs via ipinfo.io. Cached, background, rate-limited."""

    def __init__(self):
        self.cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=4)

    def get(self, ip: str) -> dict | None:
        with self._lock:
            if ip in self.cache:
                return self.cache[ip]
            self.cache[ip] = {}          # mark pending
        self._pool.submit(self._fetch, ip)
        return None

    def _fetch(self, ip: str):
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            d = r.json() if r.ok else {}
        except (requests.RequestException, ValueError):
            d = {}
        with self._lock:
            self.cache[ip] = {"country": d.get("country", "?"), "org": d.get("org", "")}


class ConnectionAnalyzer:
    def __init__(self, settings):
        self.settings = settings
        self.intel = ThreatIntel()
        self.geo = GeoLookup()

    def analyze(self, raw_conns, apps) -> list[ConnInfo]:
        pid_to_app = {pid: g for g in apps for pid in g.pids}
        out = []
        for c in raw_conns:
            # skip sockets that are already closing (no owning process any more)
            if not c.raddr or (not c.pid and c.status in ("TIME_WAIT", "CLOSE_WAIT", "CLOSING")):
                continue
            ip, port = c.raddr.ip, c.raddr.port
            scope = ip_scope(ip)
            g = pid_to_app.get(c.pid)
            name = g.name if g else (self._name(c.pid) or "?")
            info = ConnInfo(name, c.pid or 0, f"{c.laddr.ip}:{c.laddr.port}", ip, port,
                            c.status, scope)

            if scope == "Public" and self.settings.get("online_ip_lookup"):
                geo = self.geo.get(ip)
                if geo:
                    info.country, info.org = geo.get("country", ""), geo.get("org", "")

            score = 0
            if ip in self.intel.bad_ips:
                score += 3
                info.reasons.append(f"Known-bad IP ({self.intel.bad_ips[ip]})")
            if port in SUSPICIOUS_PORTS:
                score += 2
                info.reasons.append(f"Port {port}: {SUSPICIOUS_PORTS[port]}")
            if g and g.suspicious_path:
                score += 2
                info.reasons.append("Process runs from a suspicious folder")
            if g and g.category in WATCHED and not is_signed(g.publisher) and scope == "Public":
                score += 1
                info.reasons.append(f"{g.category} app talking to the internet")
            if port == 80 and scope == "Public":
                info.reasons.append("Plain HTTP (unencrypted)")
                score = max(score, 1)
            info.risk = "HIGH" if score >= 3 else "MED" if score == 2 else "LOW" if score == 1 else "OK"
            out.append(info)
        order = {"HIGH": 0, "MED": 1, "LOW": 2, "OK": 3}
        out.sort(key=lambda i: (order[i.risk], i.scope != "Public", i.process.lower()))
        return out

    @staticmethod
    def _name(pid):
        try:
            return psutil.Process(pid).name() if pid else ""
        except psutil.Error:
            return ""
