"""Core logic tests.  Run:  .venv\\Scripts\\python -m unittest discover tests"""
import getpass
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secdash.core import ai, demo, firewall, response, scanner, signature, winproc  # noqa: E402
from secdash.core.anomaly import PROTECTING, AnomalyDetector  # noqa: E402
from secdash.core.collector import AppGroup, Snapshot  # noqa: E402
from secdash.core.rules import RuleEngine  # noqa: E402


def snap_of(*apps):
    return Snapshot(time.time(), 10, 50, 8, 16, 50, 0, 0, list(apps), [], 100, 1)


class Firewall(unittest.TestCase):
    def test_validate_ip(self):
        self.assertEqual(firewall.validate_ip(" 203.0.113.66 "), "203.0.113.66")
        for bad in ["1.2.3.4; calc", "1.2.3.4 & del x", "abc", "127.0.0.1", "0.0.0.0", "224.0.0.1"]:
            with self.assertRaises(ValueError, msg=bad):
                firewall.validate_ip(bad)


class Scanner(unittest.TestCase):
    def test_admin_only_path(self):
        self.assertTrue(scanner.is_admin_only_path(os.path.join(os.environ["ProgramFiles"], "ClamAV", "clamscan.exe")))
        self.assertFalse(scanner.is_admin_only_path(os.path.join(os.environ["APPDATA"], "clamscan.exe")))
        # "..": must not escape via path tricks
        self.assertFalse(scanner.is_admin_only_path(os.environ["ProgramFiles"] + r"\..\Users\x\clamscan.exe"))

    def test_clamav_error_is_not_clean(self):
        eng = scanner.ClamAVEngine({})
        failed = subprocess.CompletedProcess([], 2, stdout="", stderr="LibClamAV Error: no database\n")
        with mock.patch.object(eng, "_exe", return_value="clamscan"), \
                mock.patch.object(scanner.subprocess, "run", return_value=failed):
            with self.assertRaises(RuntimeError):
                eng.scan(Path("."), lambda *a: None, lambda: False)

    def test_demo_files_detected(self):
        with tempfile.TemporaryDirectory() as d:
            demo.make_demo_files(Path(d))
            found = {Path(f.path).name: f.verdict for f in
                     scanner.BuiltinEngine().scan(Path(d), lambda *a: None, lambda: False)}
        self.assertEqual(found, {"suspicious_sample.bin": "MALICIOUS", "invoice.pdf.exe": "SUSPICIOUS"})


class Anomaly(unittest.TestCase):
    def test_learns_per_app_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            det = AnomalyDetector()
            det.model_path = Path(d) / "rows.json"
            det.start_learning(0)
            for i in range(40):   # a big normal app and a small one
                det.rows.append(("Firefox", [5 + i % 3, 8.1, 3, 2.3, 3.1]))
                det.rows.append(("Notepad", [0.2, 4.7, 0, 0, 0.7]))
            self.assertTrue(det.train())
            firefox = AppGroup("Firefox", "Browser", pids=list(range(22)), cpu=6, ram_mb=3300, io_kbs=20, connections=9)
            miner = AppGroup("python: miner_x.py", "Unknown", pids=[1], cpu=95, ram_mb=150)
            for _ in range(4):
                det.process([firefox, miner])
            self.assertLess(firefox.anomaly, 0.5)
            self.assertGreater(miner.anomaly, 0.8)

            det2 = AnomalyDetector()       # restart: rebuilt from JSON, no pickle
            det2.model_path = det.model_path
            det2.load()
            self.assertEqual(det2.mode, PROTECTING)


class Rules(unittest.TestCase):
    def test_focus_and_trust_keep_security_alerts(self):
        def run(focus=False, trusted=False):
            miner = AppGroup("x", "Unknown", pids=[1], cpu=90, exe=r"C:\Users\a\AppData\Local\Temp\x.exe",
                             suspicious_path=True, trusted=trusted)
            r = RuleEngine()
            return {a.message.split(":")[0] for _ in range(3) for a in r.evaluate(snap_of(miner), focus)}
        self.assertIn("Sustained high CPU", run())
        for kwargs in ({"focus": True}, {"trusted": True}):
            got = run(**kwargs)
            self.assertNotIn("Sustained high CPU", got)
            self.assertIn("Running from a suspicious location", got)

    def test_signed_app_gets_normal_cpu_limit(self):
        def alerts(publisher):
            g = AppGroup("render.exe", "Unknown", pids=[1], cpu=30, publisher=publisher)
            r = RuleEngine()
            return [a for _ in range(3) for a in r.evaluate(snap_of(g))]
        self.assertTrue(alerts(signature.UNSIGNED))        # 30% > 20% limit for unsigned unknown apps
        self.assertFalse(alerts("Blender Foundation"))     # signed: 50% limit


class Signature(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(signature.label_for("Valid", "Valve Corp."), "Valve Corp.")
        self.assertEqual(signature.label_for("NotSigned", ""), signature.UNSIGNED)
        self.assertFalse(signature.is_signed(signature.label_for("HashMismatch", "Valve Corp.")))
        self.assertFalse(signature.is_signed(""))


@unittest.skipUnless(winproc.available(), "Windows only")
class WinProc(unittest.TestCase):
    def test_matches_psutil(self):
        import psutil
        me = winproc.snapshot()[os.getpid()]
        self.assertIn(me.name.lower(), ("python.exe", "pythonw.exe"))
        self.assertAlmostEqual(me.rss, psutil.Process().memory_info().rss, delta=20 * 1_048_576)


class AI(unittest.TestCase):
    def test_redaction(self):
        user = getpass.getuser()
        app = AppGroup("x", "Unknown", pids=[1], exe=rf"C:\Users\{user}\AppData\Local\Temp\x.exe")
        data = ai.build_snapshot(snap_of(app), [], [])
        self.assertNotIn(user.lower(), str(data).lower())
        self.assertIn(r"C:\\Users\\<user>", str(data))


class Response(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(response, "data_dir", lambda: Path(self.tmp.name))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_quarantine_restore_delete(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            f = Path(d) / "bad.bin"
            f.write_bytes(demo.SAMPLE)
            self.assertTrue(response.quarantine(str(f))[0])
            self.assertFalse(f.exists())
            (q,) = response.list_quarantine()
            self.assertNotEqual((Path(self.tmp.name) / "quarantine" / f"{q['id']}.bin").read_bytes(), demo.SAMPLE)
            self.assertTrue(response.restore(q["id"])[0])
            self.assertEqual(f.read_bytes(), demo.SAMPLE)          # restored byte for byte
            response.quarantine(str(f))
            self.assertTrue(response.delete(response.list_quarantine()[0]["id"])[0])
            self.assertEqual(response.list_quarantine(), [])
        actions = [e["action"] for e in response.read_log()]
        self.assertEqual(actions, ["delete", "quarantine", "restore", "quarantine"])

    def test_restore_refuses_tampered_record(self):
        qdir = Path(self.tmp.name) / "quarantine"
        qdir.mkdir()
        qid = "a" * 32
        (qdir / f"{qid}.bin").write_bytes(b"x")
        (qdir / f"{qid}.json").write_text('{"original": "C:\\\\Windows\\\\System32\\\\evil.dll"}')
        self.assertFalse(response.restore(qid)[0])                 # outside the user folder
        self.assertFalse(response.restore("../../settings")[0])    # path trick in the id

    def test_refuses_critical_and_self(self):
        import psutil
        lsass = [p.pid for p in psutil.process_iter(["name"]) if (p.info["name"] or "").lower() == "lsass.exe"]
        for pids in ([os.getpid()], lsass[:1] or [4]):
            ok, msg = response.process_action("end", pids, "x")
            self.assertFalse(ok)
            self.assertIn("Refusing", msg)


class FirewallApps(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            firewall.validate_app(os.path.join(os.environ["SystemRoot"], "System32", "notepad.exe"))
        with self.assertRaises(ValueError):
            firewall.validate_app("not a path.exe")
        self.assertTrue(firewall.OWN_RULE.fullmatch("OneEye-Block-203.0.113.66"))
        self.assertFalse(firewall.OWN_RULE.fullmatch("Core Networking - DNS"))       # never touch other rules
        self.assertFalse(firewall.remove_rule("Remote Desktop")[0])


class AIIsAdvisoryOnly(unittest.TestCase):
    def test_ai_module_cannot_reach_actions(self):
        import ast
        tree = ast.parse(Path(ai.__file__).read_text(encoding="utf-8"))
        imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                    for a in n.names} | {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertFalse(imported & {"firewall", "response", "scanner", "subprocess", "shutil"}, imported)
        self.assertFalse(called & {"remove", "unlink", "kill", "terminate", "suspend", "system", "Popen"}, called)


if __name__ == "__main__":
    unittest.main()
