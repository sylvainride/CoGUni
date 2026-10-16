"""Targeted Android gate contracts without falsifying sys.platform.

AST proves only platform eligibility. Real Linux CI tests use the original
P5 guardian; they are NOT certification of any Android device.
"""
import ast
import hashlib
from pathlib import Path
import sys
import unittest

from universal import host_process
from tools.android_termux_p5_qualification import PINS, source_pins

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'universal' / 'host_process.py'
EXPECTED_BLOB = '5b144f8ad9d3763973dcef1b97d21b8575c984a9'


def platform_checks(tree):
    result = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            matches = [
                c for c in ast.walk(node.test)
                if isinstance(c, ast.Compare) and isinstance(c.left, ast.Attribute)
                and isinstance(c.left.value, ast.Name) and c.left.value.id == 'sys'
                and c.left.attr == 'platform'
            ]
            if matches:
                result.append((node, matches))
    return result


class AndroidPlatformGatePatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.tree = ast.parse(cls.source, filename=str(SOURCE))
        cls.guards = platform_checks(cls.tree)

    def test_exact_reviewed_host_process_blob(self):
        raw = self.source
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        self.assertEqual(blob, EXPECTED_BLOB)

    def test_only_linux_android_platforms_enter_next_gates(self):
        self.assertEqual(len(self.guards), 2)
        for _, comparisons in self.guards:
            self.assertEqual(len(comparisons), 1)
            comp = comparisons[0]
            self.assertEqual(len(comp.ops), 1)
            self.assertIsInstance(comp.ops[0], ast.NotIn)
            self.assertEqual(len(comp.comparators), 1)
            names = ast.literal_eval(comp.comparators[0])
            self.assertEqual(names, ('linux', 'android'))
            for name in ('linux', 'android'):
                self.assertIn(name, names)
            for name in ('darwin', 'win32', 'ios', 'freebsd', '', 'ANDROID'):
                with self.subTest(name=name):
                    self.assertNotIn(name, names)

    def test_api_guard_preserves_proc_directory_requirement(self):
        entry = next(n for n in self.tree.body
                     if isinstance(n, ast.FunctionDef) and n.name == 'run_bounded')
        target = next(n for n in ast.walk(entry) if isinstance(n, ast.If)
                      and 'sys.platform' in ast.unparse(n.test))
        self.assertIsInstance(target.test, ast.BoolOp)
        self.assertIsInstance(target.test.op, ast.Or)
        expression = ast.unparse(target.test)
        self.assertIn("sys.platform not in ('linux', 'android')", expression)
        self.assertIn("not os.path.isdir('/proc/self/task')", expression)

    def test_guardian_entry_preserves_exact_argv_requirement(self):
        entry = next(n for n in self.tree.body
                     if isinstance(n, ast.If) and '__name__' in ast.unparse(n.test))
        inner = next(n for n in entry.body if isinstance(n, ast.If))
        self.assertIsInstance(inner.test, ast.BoolOp)
        self.assertIsInstance(inner.test.op, ast.Or)
        expression = ast.unparse(inner.test)
        self.assertIn("sys.argv[1:] != ['--guardian']", expression)
        self.assertIn("sys.platform not in ('linux', 'android')", expression)

    def test_parent_cannot_report_ok_when_cleanup_is_false(self):
        # Evaluate the ORIGINAL unchanged response conditional, not a fake OS.
        parent = next(n for n in self.tree.body
                      if isinstance(n, ast.FunctionDef) and n.name == 'run_bounded')
        branches = [n.value for n in ast.walk(parent)
                    if isinstance(n, ast.Assign) and isinstance(n.value, ast.IfExp)
                    and "data['cleanup_verified']" in ast.unparse(n.value.test)]
        self.assertEqual(len(branches), 1)
        expression = compile(ast.Expression(body=branches[0]), str(SOURCE), 'eval')
        for state in ('OK', 'TIMEOUT', 'FAILED', 'OUTPUT_LIMIT'):
            self.assertEqual(eval(expression, {'data': {
                'state': state, 'cleanup_verified': False}}), 'FAILED')
        self.assertEqual(eval(expression, {'data': {
            'state': 'OK', 'cleanup_verified': True}}), 'OK')

    def test_guardian_fails_closed_if_cleanup_not_verified(self):
        guardian = next(n for n in self.tree.body
                        if isinstance(n, ast.FunctionDef) and n.name == '_guardian')
        matches = [n for n in ast.walk(guardian)
                   if isinstance(n, ast.If) and ast.unparse(n.test) == 'not cleanup_verified'
                   and len(n.body) == 1 and isinstance(n.body[0], ast.Assign)
                   and ast.unparse(n.body[0]) == "state = 'FAILED'"]
        self.assertEqual(len(matches), 1)

    def test_exact_updated_source_pin(self):
        self.assertEqual(PINS['universal/host_process.py'], EXPECTED_BLOB)
        self.assertEqual(source_pins()['status'], 'PASS')
        self.assertEqual(len(PINS), 6)

    def test_real_linux_guardian_still_executes_and_reaps(self):
        # No sys.platform monkeypatch: use this runner's actual OS only.
        if sys.platform != 'linux':
            return
        result = host_process.run_bounded(
            [sys.executable, '-B', '-c', "print('p5-real-linux')"], b'',
            timeout_seconds=2.0, max_output_bytes=1024)
        self.assertEqual(result.state, 'OK')
        self.assertEqual(result.stdout, b'p5-real-linux\n')
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(result.returncode, 0)
        self.assertGreater(result.child_pid, 1)
        self.assertFalse(Path('/proc/%d' % result.child_pid).exists())

    def test_real_linux_reader_nonzero_never_claims_ok(self):
        if sys.platform != 'linux':
            return
        result = host_process.run_bounded(
            [sys.executable, '-B', '-c', 'import os;os._exit(7)'], b'',
            timeout_seconds=2.0, max_output_bytes=1024)
        self.assertEqual(result.state, 'FAILED')
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(Path('/proc/%d' % result.child_pid).exists())


if __name__ == '__main__':
    unittest.main()
