"""Explicit V8 checks; skips, incomplete execution and source drift refuse green.

No isolation fallback, model call, remote effect or whole-environment dump.
JSON evidence has test identities and outcomes; raw tracebacks stay local.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest

OWNER_TESTS = (
    "tests.test_adversarial", "tests.test_binding_races_v7",
    "tests.test_binding_v7", "tests.test_bundle_v6",
    "tests.test_continuity_v8", "tests.test_credentials_v7",
    "tests.test_dag_v6", "tests.test_gates_v7", "tests.test_outbox_v7",
    "tests.test_proof_v6", "tests.test_core.CoreTests",
    "tests.test_ipc_v6.FramingV6Tests", "tests.test_ipc_v6.GateV6Tests",
    "tests.test_policy_runner_v8.PolicyInputTests",
    "tests.test_isolation_v6.TestIsolationV6.test_missing_bubblewrap_never_returns_unconfined_command",
    "tests.test_ci_binding", "tests.test_ci_checks", "tests.test_consent",
    # Cheap, no-untrusted-worker checks for the offline Chat bridge. These
    # belong in owner-contracts too: passing sandbox-runtime alone must not
    # hide a protocol regression or a spoofed worker receipt.
    "tests.test_mission_contracts", "tests.test_mission_transitions",
    "tests.test_mission_admission", "tests.test_mission_liveness",
    "tests.test_mission_polling", "tests.test_mission_versioning",
    "tests.test_mission_handoff", "tests.test_mission_chat_fixture",
    "tests.test_mission_redaction", "tests.test_mission_crash_recovery",
    "tests.test_mission_projects",
) + tuple("tests.test_generative_v8.GenerativeTests." + name for name in (
    "test_strict_default_still_requires_sha_and_registered_action",
    "test_generative_requires_mode_policy_action_and_absent_expected_sha",
    "test_caller_sha_verifier_cannot_certify_generative_candidate",
    "test_candidate_envelope_duplicate_keys_traversal_and_extra_pass_denied",
    "test_actual_environment_and_run_identity_required",
    "test_producer_policy_ambiguity_and_sha_mode_mix_denied",
    "test_worker_ipc_can_submit_candidate_but_not_verify_or_select_policy",
))


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []
        self.current = {}

    def startTest(self, test):
        self.current[test.id()] = {"id": test.id(), "status": "UNKNOWN", "started": time.monotonic()}
        super().startTest(test)

    def mark(self, test, status):
        row = self.current.get(test.id())
        if row is None and len(self.current) == 1:
            row = next(iter(self.current.values()))  # A subtest of the sequential test.
        if row is None:
            self.records.append({"id": test.id(), "status": status, "seconds": 0.0})
        else:
            priority = {"UNKNOWN": 0, "PASS": 1, "EXPECTED_FAILURE": 2,
                        "UNEXPECTED_SUCCESS": 3, "NOT_RUN": 4, "FAIL": 5, "ERROR": 6}
            if priority[status] > priority[row["status"]]:
                row["status"] = status

    def addSuccess(self, test):
        self.mark(test, "PASS")
        super().addSuccess(test)

    def addFailure(self, test, err):
        self.mark(test, "FAIL")
        super().addFailure(test, err)

    def addError(self, test, err):
        self.mark(test, "ERROR")
        super().addError(test, err)

    def addSkip(self, test, reason):
        self.mark(test, "NOT_RUN")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self.mark(test, "EXPECTED_FAILURE")
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self.mark(test, "UNEXPECTED_SUCCESS")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.mark(test, "FAIL" if issubclass(err[0], test.failureException) else "ERROR")
        super().addSubTest(test, subtest, err)

    def stopTest(self, test):
        row = self.current.pop(test.id())
        row["seconds"] = time.monotonic() - row.pop("started")
        self.records.append(row)
        super().stopTest(test)


def checks_passed(result, expected_ids, source_unchanged):
    return (bool(expected_ids) and source_unchanged and result.wasSuccessful()
            and result.testsRun == len(expected_ids)
            and len(result.records) == len(expected_ids)
            and {row["id"] for row in result.records} == set(expected_ids)
            and all(row["status"] == "PASS" for row in result.records))


def source_identity(root):
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root)
    commit = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    names = [name for name in git("ls-files", "-z").decode().split("\0") if name]
    if not names:
        raise ValueError("source snapshot is empty")
    hashes = {}
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("tracked source must be regular files")
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"commit": commit, "tree": tree, "file_sha256": hashes,
            "clean": not bool(git("status", "--porcelain", "--untracked-files=all"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("owner", "isolation", "full"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    sys.path.insert(0, str(root))
    before = source_identity(root)
    if not before["clean"]:
        raise SystemExit("refuse checks against an uncommitted or dirty snapshot")
    output = arguments.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    loader = unittest.TestLoader()
    discovered = list(flatten(loader.discover(str(root / "tests"), top_level_dir=str(root))))
    discovered_ids = [test.id() for test in discovered]
    if loader.errors or len(set(discovered_ids)) != len(discovered_ids):
        raise SystemExit("test discovery failed or produced duplicate identities")
    if arguments.mode == "full":
        selected = discovered
    else:
        names = OWNER_TESTS if arguments.mode == "owner" else ("tests.test_isolation_v6",)
        selected = list(flatten(loader.loadTestsFromNames(names)))
    selected_ids = [test.id() for test in selected]
    if loader.errors or len(set(selected_ids)) != len(selected_ids) or not set(selected_ids) <= set(discovered_ids):
        raise SystemExit("selection does not match the discovered test inventory")
    started = time.monotonic()
    with (output / "tests.log").open("x", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2,
                                         resultclass=RecordedResult).run(unittest.TestSuite(selected))
    try:
        after = source_identity(root)
        stable = before == after
    except (OSError, ValueError, subprocess.CalledProcessError):
        after = None
        stable = False
    passed = checks_passed(result, selected_ids, stable)
    payload = {
        "created_utc": datetime.now(timezone.utc).isoformat(), "mode": arguments.mode, "passed": passed,
        "scope": "EXPLICIT_TEST_CAMPAIGN_ONLY_NO_PRODUCT_CERTIFICATION",
        "python": platform.python_version(), "platform": platform.platform(),
        "bubblewrap_present": bool(shutil.which("bwrap")),
        "discovered": len(discovered), "selected": len(selected), "executed": result.testsRun,
        "status_counts": dict(Counter(row["status"] for row in result.records)),
        "source_before": before, "source_after": after, "source_unchanged": stable,
        "records": result.records, "not_selected": sorted(set(discovered_ids) - set(selected_ids)),
        "seconds": time.monotonic() - started,
    }
    (output / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: payload[key] for key in (
        "mode", "passed", "discovered", "executed", "status_counts", "source_unchanged")}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
