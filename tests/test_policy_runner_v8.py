"""Real untrusted-code probes; no external packets, model calls or owner DBs."""
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from universal.policy_runner import (CAPTURE_BYTES, CRITERIA, MAX_FILE_BYTES,
                                     MAX_OUTPUT_BYTES, git_tree_sha,
                                     run_policy_checks, validate_policy)


def policy(tests=None, seconds=3):
    return {"version": 1, "entrypoint": "candidate.py", "function": "solve",
            "tests": tests if tests is not None else [{"args": [2, 3], "expected": 5}],
            "allowed_licenses": ["MIT"], "forbidden_markers": [], "max_seconds": seconds}


def files(source="def solve(a, b):\n    return a + b\n"):
    return {"candidate.py": source, "LICENSE": "SPDX-License-Identifier: MIT\n"}


class PolicyInputTests(unittest.TestCase):
    def test_real_git_tree_matches_independent_checkout(self):
        candidate = files()
        candidate["docs/guide.md"] = "Unicode texte: é\n"
        with tempfile.TemporaryDirectory(prefix="cup-v8-independent-git-") as root:
            environment = {"PATH": os.defpath, "HOME": root, "GIT_CONFIG_NOSYSTEM": "1",
                           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
            subprocess.run(["git", "init", "--quiet", "--object-format=sha1", root], env=environment, check=True)
            for name, text in candidate.items():
                path = Path(root) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "--all"], env=environment, check=True)
            expected = subprocess.check_output(["git", "-C", root, "write-tree"], env=environment).decode().strip()
        self.assertEqual(git_tree_sha(candidate), expected)
        self.assertEqual(git_tree_sha(dict(reversed(list(candidate.items())))), expected)

    def test_git_identity_changes_on_content_path_and_unicode_change(self):
        original = git_tree_sha(files())
        edited = files("def solve(a, b):\n return a+b\n")
        self.assertNotEqual(git_tree_sha(edited), original)
        edited = files()
        edited["COPYING"] = edited.pop("LICENSE")
        self.assertNotEqual(git_tree_sha(edited), original)
        self.assertNotEqual(git_tree_sha({"readme": "é"}), git_tree_sha({"readme": "e"}))

    def test_git_inherited_config_and_hooks_cannot_change_identity(self):
        expected = git_tree_sha(files())
        with tempfile.TemporaryDirectory() as root:
            config = Path(root) / "config"
            config.write_text("[core]\n repositoryformatversion = 1\n[extensions]\n objectformat = sha256\n")
            with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_COUNT": "1",
                                         "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": root,
                                         "GIT_DEFAULT_HASH": "sha256", "GIT_OBJECT_DIRECTORY": root}):
                self.assertEqual(git_tree_sha(files()), expected)

    def test_unsafe_paths_rejected(self):
        for name in ("../candidate.py", "/candidate.py", ".git/config", ".GIT/x", "a/../b", "a//b", "a\\b", "a b", "a\nb", ".", ".."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                git_tree_sha({name: "text"})

    def test_text_only_and_utf8_scalar_limits(self):
        for value in (b"binary", Path("symlink"), "a\0b", "\x01", "\ud800", "x" * (MAX_FILE_BYTES + 1)):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                git_tree_sha({"candidate.py": value})
        with self.assertRaises(ValueError):
            git_tree_sha({str(index): "x" for index in range(33)})
        with self.assertRaises(ValueError):
            git_tree_sha({str(index): "x" * MAX_FILE_BYTES for index in range(5)})
        with self.assertRaises(ValueError):
            git_tree_sha({"a": "x", "a/b": "y"})

    def test_exact_policy_schema_and_bounded_cases(self):
        invalid = []
        for key, value in (("version", True), ("entrypoint", "alternate.py"), ("function", "__dunder"),
                           ("tests", []), ("tests", [{"args": [], "expected": 1}] * 21),
                           ("allowed_licenses", []), ("allowed_licenses", ["MIT OR GPL-3.0-only"]),
                           ("forbidden_markers", [""]), ("max_seconds", float("nan")), ("max_seconds", True),
                           ("max_seconds", 11)):
            candidate = policy()
            candidate[key] = value
            invalid.append(candidate)
        extra = policy()
        extra["verdict"] = "PASS"
        invalid.append(extra)
        for candidate in invalid:
            with self.subTest(candidate=str(candidate)[:80]), self.assertRaises(ValueError):
                validate_policy(candidate)

    def test_policy_snapshot_has_no_mutable_owner_aliases(self):
        original = policy()
        frozen = validate_policy(original)
        original["tests"][0]["expected"] = "mutated"
        self.assertEqual(frozen["tests"][0]["expected"], 5)

    def test_context_plain_json_and_timeout_limits(self):
        for context in ({"invalid": set()}, {"invalid": float("inf")}, {"invalid": "x" * 16_385}, []):
            with self.subTest(context=str(context)[:50]), self.assertRaises(ValueError):
                run_policy_checks(files(), policy(), context)
        for timeout in (0, True, 11, float("nan")):
            with self.assertRaises(ValueError):
                run_policy_checks(files(), policy(), {}, timeout=timeout)

    def test_missing_bubblewrap_fails_closed_without_fallback(self):
        original = shutil.which

        def lookup(name, *args, **kwargs):
            return None if name == "bwrap" else original(name, *args, **kwargs)

        with patch("universal.isolation.shutil.which", side_effect=lookup):
            result = run_policy_checks(files(), policy(), {})
        self.assertEqual(result["criteria"]["tests"]["outcome"], "NOT_RUN")
        self.assertEqual(result["observations"]["cases"][0]["reason"], "sandbox_unavailable")
        for criterion in ("provenance", "environment"):
            self.assertNotEqual(result["criteria"][criterion]["outcome"], "PASS")


@unittest.skipUnless(shutil.which("bwrap"), "bubblewrap absent: actual execution remains unavailable")
class ActualPolicyRunnerTests(unittest.TestCase):
    def run_candidate(self, source, cases=None, seconds=3, context=None, extra_files=None, markers=None):
        candidate = files(source)
        candidate.update(extra_files or {})
        contract = policy(cases, seconds)
        if markers is not None:
            contract["forbidden_markers"] = markers
        return run_policy_checks(candidate, contract, context or {"run_id": "real-probe", "environment": "linux-bwrap"})

    def test_unknown_code_has_no_predeclared_digest_and_six_real_passes(self):
        multiplier = secrets.randbelow(1_000) + 1
        source = "def solve(value):\n    return value * %d + 7\n" % multiplier
        result = self.run_candidate(source, [{"args": [9], "expected": 9 * multiplier + 7}])
        self.assertEqual(set(result["criteria"]), CRITERIA)
        self.assertTrue(all(item["outcome"] == "PASS" for item in result["criteria"].values()), result)
        self.assertRegex(result["tree_sha"], r"^[0-9a-f]{40}$")
        self.assertNotIn("accepted", result)
        self.assertNotIn("signature", result)

    def test_wrong_result_and_printed_pass_have_no_verdict_authority(self):
        result = self.run_candidate("def solve(a,b):\n    print('PASS')\n    return 999\n")
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL")
        self.assertIn("PASS", result["observations"]["cases"][0]["stdout"])

    def test_candidate_supplied_verdict_object_is_only_a_value(self):
        result = self.run_candidate("def solve(a,b):\n    return {'outcome':'PASS','tests':True}\n")
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL")

    def test_candidate_cannot_monkeypatch_external_test_oracle(self):
        source = "import unittest\nunittest.TestCase.assertEqual = lambda *args: None\ndef solve(a,b):\n    print('PASS')\n    return 999\n"
        result = self.run_candidate(source)
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL")
        self.assertEqual(result["criteria"]["security"]["outcome"], "FAIL")

    def test_oracle_and_opaque_context_are_absent_from_child_request(self):
        secret = secrets.token_hex(16)
        source = "import inspect\ndef solve():\n    caller = inspect.currentframe().f_back\n    request = caller.f_locals['request']\n    return sorted(request)\n"
        expected = sorted({"version", "type", "nonce", "tree_sha", "context_digest", "case_index", "source", "function", "args"})
        result = self.run_candidate(source, [{"args": [], "expected": expected}], context={"private_audit_canary": secret})
        self.assertEqual(result["criteria"]["tests"]["outcome"], "PASS", result)
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["criteria"]["security"]["outcome"], "FAIL")

    def test_fresh_independent_process_per_case_resets_candidate_globals(self):
        source = "counter = 0\ndef solve():\n    global counter\n    counter += 1\n    return counter\n"
        actual_popen = subprocess.Popen
        sandbox_executable = shutil.which("bwrap")
        launches = []

        def observe_launch(command, *args, **kwargs):
            process = actual_popen(command, *args, **kwargs)
            if command[0] == sandbox_executable:
                launches.append(process)
            return process

        with patch("universal.policy_runner.subprocess.Popen", side_effect=observe_launch):
            result = self.run_candidate(source, [{"args": [], "expected": 1}] * 3)
        cases = result["observations"]["cases"]
        self.assertEqual(result["criteria"]["tests"]["outcome"], "PASS", result)
        self.assertEqual(len({case["ready"]["nonce"] for case in cases}), 3)
        # Namespace inode numbers describe a live namespace; the kernel can
        # reuse them after a previous child and its namespace are gone.
        # Observe three real launches and completed executions instead.
        self.assertEqual(len(launches), 3)
        self.assertTrue(all(process.poll() == 0 for process in launches))
        print(json.dumps({"fresh_process_probe": {
            "actual_sandbox_launches": len(launches),
            "case_count": len(cases),
            "unique_nonces": len({case["ready"]["nonce"] for case in cases}),
            "distinct_observed_pid_namespace_numbers": len({case["ready"]["namespaces"]["pid"] for case in cases}),
            "all_processes_completed": all(process.poll() == 0 for process in launches),
        }}, sort_keys=True))

    def test_bool_int_float_comparison_is_strict_json(self):
        for returned, expected in (("True", 1), ("1", True), ("1.0", 1), ("False", 0)):
            with self.subTest(returned=returned, expected=expected):
                result = self.run_candidate("def solve():\n    return " + returned, [{"args": [], "expected": expected}])
                self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL")

    def test_safe_stdlib_function_is_executed(self):
        result = self.run_candidate("import math\ndef solve(value):\n    return math.factorial(value)\n", [{"args": [6], "expected": 720}])
        self.assertTrue(all(item["outcome"] == "PASS" for item in result["criteria"].values()), result)

    def test_syntax_error_is_a_real_failure(self):
        result = self.run_candidate("def solve(:\n return 1")
        self.assertEqual(result["criteria"]["lint"]["outcome"], "FAIL")
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL")
        self.assertEqual(result["criteria"]["security"]["outcome"], "UNKNOWN")

    def test_missing_entrypoint_is_not_executed(self):
        result = run_policy_checks({"LICENSE": "SPDX-License-Identifier: MIT\n"}, policy(), {})
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL")
        self.assertEqual(result["criteria"]["environment"]["outcome"], "NOT_RUN")

    def test_security_marker_is_checked_in_all_actual_text_files(self):
        result = self.run_candidate("def solve(a,b):\n return a+b", extra_files={"notes.txt": "PRIVATE-MARKER"}, markers=["PRIVATE-MARKER"])
        self.assertEqual(result["criteria"]["tests"]["outcome"], "PASS")
        self.assertEqual(result["criteria"]["security"]["outcome"], "FAIL")
        self.assertIn("notes.txt", result["observations"]["security_files"])

    def test_license_checks_real_file_spdx_not_worker_claim(self):
        for text, expected in (("MIT", "UNKNOWN"), ("SPDX-License-Identifier: GPL-3.0-only", "FAIL"),
                               ("SPDX-License-Identifier: MIT\nSPDX-License-Identifier: MIT", "FAIL")):
            with self.subTest(text=text):
                result = self.run_candidate("def solve(a,b):\n return a+b", extra_files={"LICENSE": text})
                self.assertEqual(result["criteria"]["licenses"]["outcome"], expected)
        result = run_policy_checks({"candidate.py": "def solve(a,b):\n return a+b"}, policy(), {})
        self.assertEqual(result["criteria"]["licenses"]["outcome"], "UNKNOWN")

    def test_print_flood_is_bounded_and_killed_without_pipe_deadlock(self):
        started = time.monotonic()
        result = self.run_candidate("def solve():\n    while True:\n        print('x'*8192)\n", [{"args": [], "expected": 1}], seconds=1)
        case = result["observations"]["cases"][0]
        self.assertEqual(case["outcome"], "FAIL", result)
        self.assertEqual(case["reason"], "child_output_limit", result)
        self.assertLessEqual(len(case["stdout"]), CAPTURE_BYTES)
        self.assertLessEqual(case["output_bytes"], MAX_OUTPUT_BYTES + 8192)
        self.assertLess(time.monotonic() - started, 2)

    def test_finite_output_after_computed_result_is_also_bounded(self):
        source = "import atexit\ndef solve():\n    atexit.register(lambda: print('x'*70000))\n    return 1\n"
        result = self.run_candidate(source, [{"args": [], "expected": 1}])
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL", result)
        self.assertEqual(result["observations"]["cases"][0]["reason"], "child_output_limit")

    def test_stderr_flood_is_drained_and_bounded(self):
        source = "import sys\ndef solve():\n    while True:\n        sys.stderr.write('e'*8192)\n"
        result = self.run_candidate(source, [{"args": [], "expected": 1}], seconds=1)
        case = result["observations"]["cases"][0]
        self.assertEqual(case["outcome"], "FAIL", result)
        self.assertEqual(case["reason"], "child_output_limit", result)
        self.assertLessEqual(len(case["stderr"]), CAPTURE_BYTES)
        self.assertLessEqual(case["output_bytes"], MAX_OUTPUT_BYTES + 8192)

    def test_busy_loop_has_one_wall_deadline(self):
        started = time.monotonic()
        result = self.run_candidate("def solve():\n    while True:\n        pass\n", [{"args": [], "expected": 1}], seconds=0.4)
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL", result)
        self.assertEqual(result["observations"]["cases"][0]["reason"], "child_deadline")
        self.assertLess(time.monotonic() - started, 1.4)

    def test_total_deadline_is_not_reset_for_remaining_cases(self):
        source = "import time\ndef solve():\n    time.sleep(0.2)\n    return 1\n"
        started = time.monotonic()
        result = self.run_candidate(source, [{"args": [], "expected": 1}] * 20, seconds=0.5)
        self.assertNotEqual(result["criteria"]["tests"]["outcome"], "PASS")
        self.assertTrue(any(case["outcome"] == "NOT_RUN" for case in result["observations"]["cases"]))
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertLess(len(json.dumps(result["observations"]).encode()), 65_536)

    def test_non_json_and_oversized_results_fail(self):
        for expression in ("{1,2}", "float('nan')", "'x'*17000"):
            with self.subTest(expression=expression):
                result = self.run_candidate("def solve():\n return " + expression, [{"args": [], "expected": 1}])
                self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL")

    def test_observations_bound_includes_invalid_utf8_expansion(self):
        source = "import os\ndef solve():\n    os.write(1,b'\\xff'*512)\n    os.write(2,b'\\xff'*512)\n    return 1\n"
        result = self.run_candidate(source, [{"args": [], "expected": 1}] * 20, seconds=5)
        self.assertEqual(result["criteria"]["tests"]["outcome"], "PASS", result)
        encoded = json.dumps(result["observations"], ensure_ascii=False, separators=(",", ":")).encode()
        self.assertLessEqual(len(encoded), 65_536)

    def test_oversized_spdx_claim_cannot_expand_observations(self):
        result = self.run_candidate("def solve(a,b):\n return a+b", extra_files={"LICENSE": "SPDX-License-Identifier: " + "X"*100_000})
        self.assertEqual(result["criteria"]["licenses"]["outcome"], "FAIL")
        self.assertLessEqual(len(result["observations"]["license_identifiers"][0]), 80)

    def test_ipc_flood_cannot_claim_pass_or_allocate_unbounded_parent_buffer(self):
        source = "import inspect\ndef solve():\n    channel = inspect.currentframe().f_back.f_locals['channel']\n    channel.sendall(b'x'*65536)\n    return 1\n"
        result = self.run_candidate(source, [{"args": [], "expected": 1}])
        self.assertEqual(result["criteria"]["tests"]["outcome"], "FAIL", result)
        self.assertEqual(result["observations"]["cases"][0]["reason"], "child_frame_limit")

    def test_host_canary_env_fd_db_process_shell_and_egress_are_blocked(self):
        with tempfile.TemporaryDirectory(prefix="cup-v8-owner-private-") as root:
            canary = Path(root) / "secret"
            database = Path(root) / "owner.sqlite"
            secret = secrets.token_hex(24)
            canary.write_text(secret)
            database.write_text("OWNER-UNCHANGED")
            descriptor = os.open(canary, os.O_RDONLY)
            number = 42 if platform.machine().lower() in {"x86_64", "amd64"} else 203
            source = '''
def solve(canary, database, parent_pid, owner_fd, connect_number):
    import os, socket, subprocess, sys, resource, ctypes
    def denied(operation):
        try:
            operation()
            return False
        except (OSError, ValueError, ImportError):
            return True
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    connect_result = libc.syscall(connect_number, -1, 0, 0)
    return {
        'canary': denied(lambda: open(canary).read()),
        'database': denied(lambda: open(database, 'w').write('CORRUPTED')),
        'host_proc': denied(lambda: open('/proc/%d/environ' % parent_pid).read()),
        'owner_fd': denied(lambda: os.fstat(owner_fd)),
        'owner_import': denied(lambda: __import__('universal.core')),
        'environment': os.getenv('CUP_RUNNER_PRIVATE_SECRET') is None,
        'fork': denied(os.fork),
        'exec': denied(lambda: os.execv(sys.executable, [sys.executable, '-c', 'pass'])),
        'subprocess': denied(lambda: subprocess.run([sys.executable, '-c', 'pass'])),
        'shell': denied(lambda: subprocess.run(['/bin/sh', '-c', 'true'])),
        'socket': denied(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)),
        'unix_socket': denied(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)),
        'connect': connect_result == -1 and ctypes.get_errno() == 1,
        'memory_limit': denied(lambda: resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))),
        'package_write': denied(lambda: open('/app/universal/protocol.py', 'w').write('MUTATED')),
    }
'''
            labels = ("canary", "database", "host_proc", "owner_fd", "owner_import", "environment", "fork", "exec", "subprocess", "shell", "socket", "unix_socket", "connect", "memory_limit", "package_write")
            try:
                with patch.dict(os.environ, {"CUP_RUNNER_PRIVATE_SECRET": secret}):
                    result = self.run_candidate(source, [{"args": [str(canary), str(database), os.getpid(), descriptor, number], "expected": dict.fromkeys(labels, True)}])
                self.assertEqual(result["criteria"]["tests"]["outcome"], "PASS", result)
                self.assertEqual(result["criteria"]["security"]["outcome"], "FAIL")
                self.assertEqual(database.read_text(), "OWNER-UNCHANGED")
                self.assertEqual(canary.read_text(), secret)
                self.assertNotIn(secret, json.dumps(result))
            finally:
                os.close(descriptor)

    def test_private_file_inside_owner_package_is_not_mounted(self):
        import universal.policy_runner as runner
        with tempfile.TemporaryDirectory(prefix="cup-v8-private-package-") as root:
            package = Path(root) / "universal"
            package.mkdir()
            actual = Path(runner.__file__).parent
            for name in ("isolation.py", "protocol.py", "generative_child.py"):
                shutil.copyfile(actual / name, package / name)
            (package / "private.txt").write_text("OWNER-PACKAGE-PRIVATE")
            source = "def solve():\n    try:\n        open('/app/universal/private.txt').read()\n        return False\n    except FileNotFoundError:\n        return True\n"
            with patch.object(runner, "__file__", str(package / "policy_runner.py")):
                result = self.run_candidate(source, [{"args": [], "expected": True}])
            self.assertEqual(result["criteria"]["tests"]["outcome"], "PASS", result)
            self.assertNotIn("OWNER-PACKAGE-PRIVATE", json.dumps(result))

    def test_context_policy_and_tree_digests_bind_the_actual_run(self):
        context = {"run": "opaque-id", "source_version": 7, "output_version": 8, "environment": "linux"}
        contract = policy()
        result = run_policy_checks(files(), contract, context)
        canonical = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(result["context_digest"], hashlib.sha256(canonical(context)).hexdigest())
        self.assertEqual(result["policy_digest"], hashlib.sha256(canonical(contract)).hexdigest())
        ready = result["observations"]["cases"][0]["ready"]
        self.assertEqual(ready["tree_sha"], git_tree_sha(files()))
        self.assertEqual(ready["context_digest"], result["context_digest"])
        self.assertEqual(ready["uid"], 65534)
        self.assertTrue(ready["seccomp"])
        context["output_version"] = 9
        drifted = run_policy_checks(files(), contract, context)
        self.assertNotEqual(drifted["context_digest"], result["context_digest"])


if __name__ == "__main__":
    unittest.main()
