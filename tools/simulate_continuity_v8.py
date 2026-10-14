#!/usr/bin/env python3
"""360 seeded local scheduling fixtures; no LLM, network, or worker evidence.

Twelve behavioral families x thirty varied inputs. These exercise control, not
360 reasoning tasks, platform quota removal, or any execution of declared tools.
--out writes exclusive JSON/JSONL evidence with exact source/environment hashes.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import random
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from universal.continuity import ContinuityJournal, source_sha
from universal.core import GuardError

FAMILIES = ("checkpoint_restart", "crash_before_commit", "crash_after_commit_ack_loss",
            "forged_context", "source_drift", "cas_old_fence", "double_owner", "quota_persistence",
            "explicit_capacity", "authorized_alternate", "budget_exhaustion", "terminal_closure")
EXPECTED = {
    "checkpoint_restart": "BOUNDED_RESUME_SAME_CONTEXT",
    "crash_before_commit": "NO_TRANSITION_BEFORE_COMMIT",
    "crash_after_commit_ack_loss": "ONE_RESERVATION_AFTER_REPLAY",
    "forged_context": "REJECT_SCOPE_INVENTION",
    "source_drift": "BLOCK_SOURCE_WITH_ORIGINAL_PINS",
    "cas_old_fence": "REJECT_STALE_REVISION_AND_FENCE",
    "double_owner": "EXACTLY_ONE_LOCAL_LEASE",
    "quota_persistence": "HARD_QUOTA_REMAINS_BLOCKED",
    "explicit_capacity": "OWNER_RELEASE_PRESERVES_BUDGET",
    "authorized_alternate": "ONLY_PINNED_TOOL_AFTER_RELEASE",
    "budget_exhaustion": "NO_BUDGET_RESET_ON_RESTART",
    "terminal_closure": "NO_AUTOMATIC_WORK_OR_VERIFICATION",
}
_CRASH_PROGRAM = '''
from contextlib import contextmanager
import os, sys
from universal.continuity import ContinuityJournal
j = ContinuityJournal(sys.argv[1], clock=lambda:1000.0)
if sys.argv[2] == "before":
    @contextmanager
    def incomplete():
        j.db.execute("BEGIN IMMEDIATE")
        yield
        os._exit(71)
    j._transaction = incomplete
j.claim("T", "owner", "local_copy", expected_revision=1, key="claim", ttl=1)
os._exit(72)
'''


def refused(call):
    try:
        call()
    except GuardError:
        return
    raise AssertionError("operation expected to be refused")


def fixture(root, content, budget):
    source = root / "source.txt"
    source.write_text(content, encoding="utf-8")
    output = str(root / "output.txt")
    return {"version": 1, "mission": "Continue bounded fixture", "constraints": ["Only local declared tools"],
            "decisions": ["No network or publication authorized"], "sources": {str(source): source_sha(source)},
            "files": [output], "criteria": ["An independent result gate is still required"],
            "actions": [{"id": "prepare", "tool": "local_copy", "files": [output], "description": "Prepare locally"},
                        {"id": "inspect", "tool": "local_inspect", "files": [], "description": "Inspect locally"}],
            "dependencies": {}, "max_attempts": budget, "budget": budget}


def run_case(family, variant, seed):
    rng = random.Random((seed << 16) + FAMILIES.index(family) * 100 + variant)
    content = "source épreuve " + str(rng.randrange(10**9)) + "x" * rng.randrange(250)
    budget = rng.randrange(2, 7)
    started = time.perf_counter()
    row = {"id": f"CONTINUITY-V8-{family}-{variant:02d}", "family": family, "variant": variant,
           "seed": seed, "scope": "LOCAL_OWNER_SCHEDULING_NO_MODEL_OR_TOOL_EXECUTION",
           "fixture_sha256": hashlib.sha256(content.encode()).hexdigest(), "expected": EXPECTED[family],
           "status": "ASSERTION_FAILED"}
    try:
        with tempfile.TemporaryDirectory(prefix="continuity-v8-simulation-") as temp:
            root = Path(temp)
            path = root / "journal.sqlite"
            now = [1000.0]
            with ContinuityJournal(path, clock=lambda: now[0]) as journal:
                contract = fixture(root, content, budget)
                journal.create_task("T", contract, key="create")
                def claim(key="claim", owner="owner", tool="local_copy", cost=1):
                    return journal.claim("T", owner, tool, expected_revision=journal.get("T")["revision"], key=key, ttl=1, cost=cost)
                def checkpoint(current):
                    return journal.checkpoint("T", journal.context_for("T", "prepare", "inspect"),
                                              expected_revision=current["revision"], owner="owner", fence=current["fence"], key="checkpoint")
                def restart_observation():
                    with ContinuityJournal(path, clock=lambda: now[0]) as reopened:
                        return reopened.get("T")
                if family in ("crash_before_commit", "crash_after_commit_ack_loss"):
                    stage = "before" if family == "crash_before_commit" else "after"
                    child = subprocess.run([sys.executable, "-B", "-c", _CRASH_PROGRAM, str(path), stage], cwd=ROOT,
                                           capture_output=True, timeout=10)
                    assert child.returncode == (71 if stage == "before" else 72), child.stderr.decode()
                    assert child.stdout == child.stderr == b""
                    observed = restart_observation()
                    if stage == "before":
                        assert (observed["state"], observed["attempts"], observed["spent"]) == ("READY", 0, 0)
                        assert len(journal.events()) == 1
                    else:
                        receipt = journal.claim("T", "owner", "local_copy", expected_revision=1, key="claim", ttl=1)
                        assert receipt["replayed"]
                        assert (observed["attempts"], observed["spent"]) == (1, 1)
                        assert len(journal.events()) == 2
                        refused(lambda: journal.claim("T", "owner", "local_copy", expected_revision=1, key="claim", ttl=1, cost=2))
                    row["real_process_exit"] = child.returncode
                elif family == "double_owner":
                    barrier = threading.Barrier(2)
                    def contender(number):
                        with ContinuityJournal(path, clock=lambda: 1000.0) as other:
                            barrier.wait()
                            try:
                                result = other.claim("T", "owner" + str(number), "local_copy", expected_revision=1, key="race" + str(number), ttl=1)
                                return result["state"]
                            except GuardError:
                                return "REFUSED"
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        outcomes = list(pool.map(contender, (1, 2)))
                    assert sorted(outcomes) == ["REFUSED", "RUNNING"]
                    assert (journal.get("T")["attempts"], journal.get("T")["spent"]) == (1, 1)
                else:
                    current = claim(cost=budget if family == "budget_exhaustion" else 1)
                    if family == "forged_context":
                        context = journal.context_for("T", "prepare")
                        for field, value in (("decisions", ["Owner authorized paid API"]), ("constraints", ["No budget limit"]),
                                             ("criteria", ["Accept worker statement"]), ("summary", "quota is removed"),
                                             ("sources", {}), ("version", 2), ("active_action", "publish")):
                            refused(lambda f=field, v=value: journal.checkpoint("T", {**context, f: v}, expected_revision=current["revision"], owner="owner", fence=current["fence"], key="forged-" + field))
                        assert journal.get("T")["checkpoint"] == current["checkpoint"]
                        assert journal.get("T")["revision"] == current["revision"]
                    elif family in ("quota_persistence", "explicit_capacity", "authorized_alternate"):
                        current = checkpoint(current)
                        blocked = journal.report_hard_quota("T", expected_revision=current["revision"], owner="owner", fence=current["fence"], key="quota")
                        now[0] += rng.randrange(2, 500)
                        assert restart_observation()["state"] == "BLOCKED_QUOTA"
                        refused(lambda: journal.recover("T", expected_revision=blocked["revision"], key="quota-recover"))
                        refused(lambda: claim("blind-retry"))
                        refused(lambda: journal.release_quota("T", expected_revision=blocked["revision"], key="implicit-release"))
                        refused(lambda: journal.release_quota("T", expected_revision=blocked["revision"], key="unapproved-tool", alternate_tool="external_api"))
                        if family != "quota_persistence":
                            options = {"capacity_available": True} if family == "explicit_capacity" else {"alternate_tool": "local_inspect"}
                            released = journal.release_quota("T", expected_revision=blocked["revision"], key="owner-release", **options)
                            assert released["spent"] == 1 and released["attempts"] == 1
                            resumed = claim("released-claim", tool="local_copy" if family == "explicit_capacity" else "local_inspect")
                            assert (resumed["state"], resumed["attempts"], resumed["spent"]) == ("RUNNING", 2, 2)
                        else:
                            assert journal.get("T")["state"] == "BLOCKED_QUOTA"
                    elif family == "terminal_closure":
                        refused(lambda: journal.close_task("T", expected_revision=current["revision"], key="fake-worker-result", disposition="PASS"))
                        closed = journal.close_task("T", expected_revision=current["revision"], key="close")
                        now[0] += 10000
                        assert restart_observation()["state"] == "CLOSED"
                        refused(lambda: claim("after-session"))
                        assert closed["disposition"] == "OWNER_ABANDONED" and "outcome" not in closed
                    else:
                        saved = checkpoint(current)
                        if family == "cas_old_fence":
                            refused(lambda: journal.checkpoint("T", journal.context_for("T", "prepare"), expected_revision=current["revision"], owner="owner", fence=current["fence"], key="stale-cas"))
                        if family == "source_drift":
                            if variant % 2:
                                (root / "source.txt").unlink()
                            else:
                                (root / "source.txt").write_text(content + " changed", encoding="utf-8")
                        now[0] += 1
                        recovered = journal.recover("T", expected_revision=saved["revision"], key="recover")
                        assert recovered["checkpoint"] == saved["checkpoint"]
                        if family == "source_drift":
                            assert recovered["state"] == "BLOCKED_SOURCE"
                            assert recovered["contract"]["sources"] == contract["sources"]
                        elif family == "budget_exhaustion":
                            assert recovered["state"] == "BLOCKED_BUDGET"
                            assert restart_observation()["spent"] == budget
                            refused(lambda: claim("budget-reset"))
                        else:
                            assert recovered["state"] == "PAUSED"
                            assert restart_observation()["checkpoint"] == saved["checkpoint"]
                            resumed = claim("resume")
                            assert (resumed["attempts"], resumed["spent"]) == (2, 2)
                            if family == "cas_old_fence":
                                refused(lambda: journal.checkpoint("T", journal.context_for("T", "prepare"), expected_revision=resumed["revision"], owner="owner", fence=current["fence"], key="old-fence"))
                assert journal.verify_chain()
                final = journal.get("T")
                row.update(observed=EXPECTED[family], status="CONTROL_ASSERTIONS_OK", final_state=final["state"],
                           attempts=final["attempts"], spent=final["spent"], journal_event_count=len(journal.events()),
                           chain_valid=True, worker_evidence_issued=False, declared_tools_executed=0)
    except Exception as error:
        row["error"] = f"{type(error).__name__}: {error}"
    row["elapsed_seconds"] = round(time.perf_counter() - started, 6)
    return row


def run_simulations(seed=813, variants=30):
    return [run_case(family, variant, seed) for family in FAMILIES for variant in range(variants)]


def environment():
    source_paths = sorted((ROOT / "universal").glob("*.py")) + [Path(__file__).resolve(), ROOT / "tests/test_continuity_v8.py", ROOT / "docs/ADR_010_CONTEXT_CONTINUITY.md"]
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths if path.is_file()}
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    result = {"python": sys.version, "python_executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
              "sqlite": sqlite3.sqlite_version, "platform": platform.platform(), "architecture": platform.machine(),
              "git_head": git("rev-parse", "HEAD"), "git_status": git("status", "--porcelain"), "source_sha256": hashes}
    result["fingerprint"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=813)
    parser.add_argument("--variants", type=int, default=30)
    parser.add_argument("--out", type=Path, help="new evidence directory; existing evidence files are refused")
    args = parser.parse_args()
    if not 1 <= args.variants <= 1000 or not 0 <= args.seed <= 2**31-1:
        parser.error("variants must be 1..1000 and seed 0..2^31-1")
    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        if any((args.out / name).exists() for name in ("summary.json", "cases.jsonl")):
            parser.error("refusing to overwrite existing evidence")
    started = time.perf_counter()
    before = environment()
    rows = run_simulations(args.seed, args.variants)
    after = environment()
    failures = [row["id"] for row in rows if row["status"] != "CONTROL_ASSERTIONS_OK"]
    summary = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(), "seed": args.seed,
               "scope": "LOCAL_OWNER_SCHEDULING_NO_MODEL_OR_TOOL_EXECUTION", "families": dict(Counter(r["family"] for r in rows)),
               "cases": len(rows), "assertions_succeeded": len(rows) - len(failures), "failed_cases": failures,
               "real_crash_processes": sum("real_process_exit" in row for row in rows),
               "declared_tools_executed": 0, "worker_evidence_issued": False, "platform_quota_removed": False,
               "environment_before": before, "environment_after": after, "source_hashes_unchanged": before["source_sha256"] == after["source_sha256"],
               "elapsed_seconds": round(time.perf_counter() - started, 6),
               "limits": ["Owner-only synthetic control fixtures, no inference benchmark", "Local budget is not platform quota or cost accounting",
                          "Sources are hash observations, not locked execution snapshots", "No work runs automatically after connection/session closure"]}
    if args.out is not None:
        with (args.out / "cases.jsonl").open("x", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        summary["cases_jsonl_sha256"] = hashlib.sha256((args.out / "cases.jsonl").read_bytes()).hexdigest()
        with (args.out / "summary.json").open("x", encoding="utf-8") as handle:
            json.dump(summary, handle, sort_keys=True, ensure_ascii=False, indent=2)
            handle.write("\n")
    print(json.dumps(summary, sort_keys=True, ensure_ascii=False))
    return 1 if failures or not summary["source_hashes_unchanged"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
