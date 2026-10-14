import contextlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from universal.broker import environment_identity, run_pool
from universal.core import Runtime, digest


class BrokerRecoveryTests(unittest.TestCase):
    def test_actual_broker_crash_after_commit_recovers_without_second_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite"
            with Runtime(path) as runtime:
                runtime.put_resource("input", "bonjour")
                runtime.put_resource("output", "")
                runtime.add_task("T", "input", "output", "uppercase", digest("BONJOUR"))
            program = """import os,sys
from universal.broker import WorkerGate,run_pool
original=WorkerGate.handle
def crash(self,message):
 result=original(self,message)
 if message['op']=='write':os._exit(81)
 return result
WorkerGate.handle=crash
run_pool(sys.argv[1],workers=1)
"""
            failed = subprocess.run([sys.executable, "-c", program, str(path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(failed.returncode, 81, failed.stdout + failed.stderr)
            with Runtime(path) as runtime:
                self.assertEqual(runtime.task("T")["status"], "RESULT_READY")
                self.assertEqual(runtime.resource("output")["version"], 2)
                self.assertEqual(runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
            report = run_pool(path, workers=1)
            recovery = next(item for item in report if item.get("role") == "controller")
            self.assertTrue(recovery["results"][0]["recovered_committed_result"])
            with Runtime(path) as runtime:
                self.assertEqual(runtime.task("T")["status"], "VERIFIED")
                self.assertEqual(runtime.resource("output")["version"], 2)
                self.assertEqual(runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
                self.assertEqual(runtime.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)
                proof = runtime.db.execute("SELECT id FROM evidence").fetchone()[0]
                self.assertTrue(runtime.proof_is_accepted_for_gate(proof, environment_identity()))

    def test_verification_environment_covers_worker_and_broker_policy(self):
        from unittest.mock import patch
        original = Path.read_bytes
        current = environment_identity()
        for filename in ("worker.py", "broker.py", "dag.py"):
            def changed(path):
                data = original(path)
                return data + b"\n# changed policy" if path.name == filename else data
            with patch.object(Path, "read_bytes", changed):
                self.assertNotEqual(environment_identity(), current)
