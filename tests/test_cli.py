import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from universal.core import digest


class CLITests(unittest.TestCase):
    def run_cli(self, path, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "universal", "--db", str(path), *args], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_actual_cli_flow_export_and_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cli.sqlite"
            self.assertEqual(self.run_cli(path, "init")["schema"], 4)
            self.run_cli(path, "put", "input", "--text", "bonjour")
            self.run_cli(path, "put", "output", "--text", "")
            self.run_cli(path, "task", "T1", "--source", "input", "--output", "output", "--action", "uppercase", "--expected-sha", digest("BONJOUR"))
            pool = self.run_cli(path, "run", "--workers", "2")
            self.assertEqual(sum(len(worker["results"]) for worker in pool), 1)
            snapshot = self.run_cli(path, "status")
            self.assertEqual(snapshot["tasks"][0]["status"], "VERIFIED")
            self.assertNotIn("token_hash", json.dumps(snapshot))
            backup = Path(temp) / "backup.sqlite"
            self.run_cli(path, "backup", str(backup))
            self.assertEqual(self.run_cli(backup, "status")["tasks"][0]["status"], "VERIFIED")
            export = Path(temp) / "export.json"
            self.assertFalse(self.run_cli(path, "export", str(export))["chatgpt_sources_updated"])
            self.assertEqual(json.loads(export.read_text())["schema_version"], 4)

    def test_failed_verification_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cli.sqlite"
            self.run_cli(path, "put", "input", "--text", "bonjour")
            self.run_cli(path, "put", "output", "--text", "")
            self.run_cli(path, "task", "T1", "--source", "input", "--output", "output", "--action", "uppercase", "--expected-sha", digest("wrong"))
            self.run_cli(path, "run", "--workers", "1", expected=2)
            self.assertEqual(self.run_cli(path, "status")["tasks"][0]["status"], "FAILED")
