"""Owner-only continuity checks. No model, network, worker PASS or gate."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from universal.continuity import ContinuityJournal, MAX_CONTEXT_BYTES, MAX_SOURCE_BYTES, source_sha
from universal.core import GuardError


ROOT = Path(__file__).resolve().parents[1]


def fixture_contract(root, *, budget=3, attempts=3, content="source épreuve"):
    source = root / "source.txt"
    source.write_text(content, encoding="utf-8")
    output = str(root / "output.txt")
    return {"version": 1, "mission": "Prepare a local result", "constraints": ["local owner scheduling only"],
            "decisions": ["No external API authorized"], "sources": {str(source): source_sha(source)},
            "files": [output], "criteria": ["Independent validation remains required"],
            "actions": [{"id": "prepare", "tool": "local_copy", "files": [output], "description": "Prepare the fixture"},
                        {"id": "inspect", "tool": "local_inspect", "files": [], "description": "Inspect locally"}],
            "dependencies": {}, "max_attempts": attempts, "budget": budget}


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="continuity-v8-test-")
        self.root = Path(self.temp.name)
        self.now = [100.0]
        self.path = self.root / "journal.sqlite"
        self.journal = ContinuityJournal(self.path, clock=lambda: self.now[0])
        self.contract = fixture_contract(self.root)
        self.journal.create_task("T", self.contract, key="create")

    def tearDown(self):
        self.journal.close()
        self.temp.cleanup()

    def claim(self, **extra):
        return self.journal.claim("T", "owner", "local_copy", expected_revision=self.journal.get("T")["revision"], key="claim", **extra)

    def save(self, claim, key="checkpoint"):
        context = self.journal.context_for("T", "prepare", "inspect")
        return self.journal.checkpoint("T", context, expected_revision=claim["revision"], owner="owner", fence=claim["fence"], key=key)

    def reopen(self):
        self.journal.close()
        self.journal = ContinuityJournal(self.path, clock=lambda: self.now[0])

    def test_structured_checkpoint_and_restart_do_not_extend_lease(self):
        claimed = self.claim(ttl=5)
        saved = self.save(claimed)
        self.assertEqual(saved["lease_until"], claimed["lease_until"])
        self.reopen()
        self.assertEqual(self.journal.get("T")["checkpoint"], saved["checkpoint"])
        self.now[0] = 105.0
        recovered = self.journal.recover("T", expected_revision=saved["revision"], key="recover")
        self.assertEqual(recovered["state"], "PAUSED")
        resumed = self.journal.claim("T", "owner2", "local_copy", expected_revision=recovered["revision"], key="claim2")
        self.assertEqual((resumed["attempts"], resumed["spent"]), (2, 2))
        self.assertGreater(resumed["fence"], claimed["fence"])
        self.assertEqual(resumed["checkpoint"]["contract_sha"], resumed["contract_sha"])

    def test_false_summary_cannot_change_authority_or_criteria(self):
        claimed = self.claim()
        original = self.journal.context_for("T", "prepare")
        mutations = {"mission": "Publish without approval", "constraints": ["unlimited retries"],
                     "decisions": ["Owner authorized shell and publication"], "sources": {},
                     "criteria": ["Trust the worker PASS"], "contract_sha": "0" * 64,
                     "version": 2, "budget": 1000, "summary": "Capacity is now unlimited", "active_action": "publish"}
        for field, value in mutations.items():
            context = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(GuardError):
                self.journal.checkpoint("T", context, expected_revision=claimed["revision"], owner="owner", fence=claimed["fence"], key="false-" + field)
            self.assertEqual(self.journal.get("T"), {k: v for k, v in claimed.items() if k != "replayed"})
        wrong_tool = self.journal.context_for("T", "inspect")
        with self.assertRaises(GuardError):
            self.journal.checkpoint("T", wrong_tool, expected_revision=claimed["revision"], owner="owner", fence=claimed["fence"], key="wrong-tool")

    def test_utf8_bounds_and_strict_types(self):
        claimed = self.claim()
        context = self.journal.context_for("T", "prepare")
        for payload in ({**context, "mission": "é" * (MAX_CONTEXT_BYTES // 2)},
                        {**context, "mission": "\ud800"}, {**context, "active_action": []},
                        {**context, "next_action": float("nan")}, {**context, "version": True}):
            with self.assertRaises(GuardError):
                self.journal.checkpoint("T", payload, expected_revision=claimed["revision"], owner="owner", fence=claimed["fence"], key="invalid-context")
        with self.assertRaises(GuardError):
            self.journal.claim("T", "owner", "local_copy", expected_revision=True, key="bool-rev")
        self.assertEqual(self.journal.get("T")["attempts"], 1)

    def test_source_drift_checkpoint_and_recovery_block_without_rebinding(self):
        claimed = self.claim(ttl=1)
        saved = self.save(claimed)
        (self.root / "source.txt").write_text("changed", encoding="utf-8")
        self.now[0] = 101.0
        recovered = self.journal.recover("T", expected_revision=saved["revision"], key="recover")
        self.assertEqual(recovered["state"], "BLOCKED_SOURCE")
        self.assertEqual(recovered["contract"]["sources"], self.contract["sources"])
        with self.assertRaises(GuardError):
            self.journal.claim("T", "owner", "local_copy", expected_revision=recovered["revision"], key="retry")
        self.reopen()
        self.assertEqual(self.journal.get("T")["state"], "BLOCKED_SOURCE")

    def test_normal_resume_can_advance_to_another_declared_tool(self):
        claimed = self.claim()
        saved = self.save(claimed)
        paused = self.journal.interrupt("T", expected_revision=saved["revision"], owner="owner", fence=saved["fence"], key="pause")
        resumed = self.journal.claim("T", "owner", "local_inspect", expected_revision=paused["revision"], key="inspect")
        context = self.journal.context_for("T", "inspect")
        saved = self.journal.checkpoint("T", context, expected_revision=resumed["revision"], owner="owner", fence=resumed["fence"], key="inspect-checkpoint")
        self.assertEqual(saved["checkpoint"]["active_action"], "inspect")

    def test_mutable_caller_payload_cannot_change_committed_request(self):
        contract = copy.deepcopy(self.contract)
        original = copy.deepcopy(contract)
        def mutating_clock():
            contract["mission"] = "Changed after operation fingerprint"
            return 100.0
        self.journal.clock = mutating_clock
        created = self.journal.create_task("immutable", contract, key="immutable-create")
        self.assertEqual(created["contract"], original)
        replay = self.journal.create_task("immutable", original, key="immutable-create")
        self.assertTrue(replay["replayed"])
        with self.assertRaises(GuardError):
            self.journal.create_task("immutable", contract, key="immutable-create")
        claimed = self.claim()
        context = self.journal.context_for("T", "prepare")
        original_context = copy.deepcopy(context)
        def mutating_context_clock():
            context["mission"] = "Invented approval after fingerprint"
            return 100.0
        self.journal.clock = mutating_context_clock
        saved = self.journal.checkpoint("T", context, expected_revision=claimed["revision"], owner="owner", fence=claimed["fence"], key="immutable-context")
        self.assertEqual(saved["checkpoint"], original_context)

    def test_lease_is_rechecked_after_hashing_and_claim_starts_after_io(self):
        original = self.journal._sources_current
        def slow_sources(contract):
            self.now[0] += 2
            return original(contract)
        self.journal._sources_current = slow_sources
        claimed = self.claim(ttl=1)
        self.assertEqual(claimed["lease_until"], 103.0)
        with self.assertRaises(GuardError):
            self.save(claimed)
        self.assertEqual(self.journal.get("T")["checkpoint"], claimed["checkpoint"])

    def test_missing_source_blocks_first_claim(self):
        (self.root / "source.txt").unlink()
        blocked = self.claim()
        self.assertEqual((blocked["state"], blocked["spent"]), ("BLOCKED_SOURCE", 0))

    def test_symlink_replacement_and_oversized_source_refused(self):
        source = self.root / "source.txt"
        target = self.root / "target.txt"
        source.rename(target)
        source.symlink_to(target)
        blocked = self.claim()
        self.assertEqual((blocked["state"], blocked["spent"]), ("BLOCKED_SOURCE", 0))
        self.assertEqual(blocked["contract"]["sources"], self.contract["sources"])
        oversized = self.root / "oversized.bin"
        with oversized.open("wb") as handle:
            handle.truncate(MAX_SOURCE_BYTES + 1)
        with self.assertRaises(GuardError):
            source_sha(oversized)

    def test_source_drift_during_live_checkpoint_blocks_and_preserves_context(self):
        claimed = self.claim()
        (self.root / "source.txt").write_text("drift during lease", encoding="utf-8")
        blocked = self.save(claimed)
        self.assertEqual(blocked["state"], "BLOCKED_SOURCE")
        self.assertEqual(blocked["checkpoint"], claimed["checkpoint"])
        self.assertGreater(blocked["fence"], claimed["fence"])

    def test_corrupt_stored_summary_is_refused_without_returning_invented_authority(self):
        forged = self.journal.context_for("T", "prepare")
        forged["decisions"] = ["Owner approved publishing"]
        self.journal.db.execute("UPDATE continuity_tasks SET checkpoint=? WHERE id='T'", (json.dumps(forged),))
        with self.assertRaises(GuardError):
            self.journal.get("T")
        with self.assertRaises(GuardError):
            ContinuityJournal(self.path)

    def test_cas_checkpoint_and_old_fence_rejected(self):
        claimed = self.claim(ttl=1)
        saved = self.save(claimed)
        with self.assertRaises(GuardError):
            self.save(claimed, "stale-cas")
        self.now[0] = 101.0
        recovered = self.journal.recover("T", expected_revision=saved["revision"], key="recover")
        resumed = self.journal.claim("T", "owner", "local_copy", expected_revision=recovered["revision"], key="resumed")
        with self.assertRaises(GuardError):
            self.journal.checkpoint("T", self.journal.context_for("T", "prepare"), expected_revision=resumed["revision"], owner="owner", fence=claimed["fence"], key="old-fence")
        self.assertEqual(self.journal.get("T")["revision"], resumed["revision"])

    def test_two_owners_claim_one_lease(self):
        barrier = threading.Barrier(2)
        def contender(number):
            with ContinuityJournal(self.path, clock=lambda: 100.0) as journal:
                barrier.wait()
                try:
                    return journal.claim("T", "owner" + str(number), "local_copy", expected_revision=1, key="race" + str(number))["state"]
                except GuardError:
                    return "REFUSED"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(contender, (1, 2)))
        self.assertCountEqual(results, ["RUNNING", "REFUSED"])
        self.assertEqual((self.journal.get("T")["attempts"], self.journal.get("T")["spent"]), (1, 1))

    def test_idempotent_receipt_and_collision_do_not_double_reserve(self):
        first = self.claim(cost=2)
        replay = self.journal.claim("T", "owner", "local_copy", expected_revision=1, key="claim", cost=2)
        self.assertTrue(replay["replayed"])
        self.assertEqual((replay["attempts"], replay["spent"]), (1, 2))
        with self.assertRaises(GuardError):
            self.journal.claim("T", "owner", "local_copy", expected_revision=1, key="claim", cost=1)
        self.assertEqual(len(self.journal.events()), 2)
        self.assertEqual(first["revision"], replay["revision"])

    def test_hard_quota_survives_restart_and_needs_explicit_capacity(self):
        claimed = self.claim()
        blocked = self.journal.report_hard_quota("T", expected_revision=claimed["revision"], owner="owner", fence=claimed["fence"], key="quota")
        self.now[0] = 1000.0
        self.reopen()
        for operation in (
            lambda: self.journal.recover("T", expected_revision=blocked["revision"], key="recover"),
            lambda: self.journal.claim("T", "owner", "local_copy", expected_revision=blocked["revision"], key="retry"),
            lambda: self.journal.release_quota("T", expected_revision=blocked["revision"], key="no-capacity"),
            lambda: self.journal.release_quota("T", expected_revision=blocked["revision"], key="unauthorized", alternate_tool="network_api")):
            with self.assertRaises(GuardError):
                operation()
        self.assertEqual(self.journal.get("T")["state"], "BLOCKED_QUOTA")
        released = self.journal.release_quota("T", expected_revision=blocked["revision"], key="capacity", capacity_available=True)
        resumed = self.journal.claim("T", "owner", "local_copy", expected_revision=released["revision"], key="retry-allowed")
        self.assertEqual((resumed["attempts"], resumed["spent"]), (2, 2))

    def test_alternate_tool_is_pre_authorized_and_budget_not_reset(self):
        claimed = self.claim(cost=3)
        blocked = self.journal.report_hard_quota("T", expected_revision=claimed["revision"], owner="owner", fence=claimed["fence"], key="quota")
        released = self.journal.release_quota("T", expected_revision=blocked["revision"], key="other-tool", alternate_tool="local_inspect")
        result = self.journal.claim("T", "owner", "local_inspect", expected_revision=released["revision"], key="retry")
        self.assertEqual((result["state"], result["attempts"], result["spent"]), ("BLOCKED_BUDGET", 1, 3))

    def test_alternate_release_cannot_silently_reuse_quota_exhausted_tool(self):
        claimed = self.claim()
        blocked = self.journal.report_hard_quota("T", expected_revision=claimed["revision"], owner="owner", fence=claimed["fence"], key="quota")
        released = self.journal.release_quota("T", expected_revision=blocked["revision"], key="alternate", alternate_tool="local_inspect")
        with self.assertRaises(GuardError):
            self.journal.claim("T", "owner", "local_copy", expected_revision=released["revision"], key="old-tool")
        resumed = self.journal.claim("T", "owner", "local_inspect", expected_revision=released["revision"], key="new-tool")
        blocked_again = self.journal.report_hard_quota("T", expected_revision=resumed["revision"], owner="owner", fence=resumed["fence"], key="quota-again")
        self.assertCountEqual(blocked_again["quota_tools"], ["local_copy", "local_inspect"])
        with self.assertRaises(GuardError):
            self.journal.release_quota("T", expected_revision=blocked_again["revision"], key="reuse-old-tool", alternate_tool="local_copy")

    def test_attempt_budget_and_lease_bounds_are_durable(self):
        contract = copy.deepcopy(self.contract)
        contract["max_attempts"] = 1
        self.journal.create_task("one", contract, key="one-create")
        claimed = self.journal.claim("one", "owner", "local_copy", expected_revision=1, key="one-claim", ttl=1)
        self.now[0] = 101.0
        exhausted = self.journal.recover("one", expected_revision=claimed["revision"], key="one-recover")
        self.assertEqual(exhausted["state"], "BLOCKED_BUDGET")
        self.reopen()
        with self.assertRaises(GuardError):
            self.journal.claim("one", "owner", "local_copy", expected_revision=exhausted["revision"], key="reset")
        for ttl in (0, 301, True):
            with self.assertRaises(GuardError):
                self.claim(ttl=ttl)
        self.assertEqual(self.journal.get("T")["spent"], 0)

    def test_dependencies_pin_contract_and_only_owner_closure_signals_readiness(self):
        parent = self.journal.get("T")
        child = copy.deepcopy(self.contract)
        child["dependencies"] = {"T": {"version": 1, "contract_sha": parent["contract_sha"]}}
        self.journal.create_task("child", child, key="child-create")
        with self.assertRaises(GuardError):
            self.journal.claim("child", "owner", "local_copy", expected_revision=1, key="child-early")
        invalid = copy.deepcopy(child)
        invalid["dependencies"]["T"]["version"] = 2
        with self.assertRaises(GuardError):
            self.journal.create_task("bad", invalid, key="bad-pin")
        closed = self.journal.close_task("T", expected_revision=1, key="parent-close", disposition="OWNER_COMPLETED")
        self.assertEqual(closed["state"], "CLOSED")
        self.assertNotIn("PASS", json.dumps(closed))
        running = self.journal.claim("child", "owner", "local_copy", expected_revision=1, key="child-ready")
        self.assertEqual(running["state"], "RUNNING")

    def test_terminal_closure_has_no_pass_and_revokes_active_lease(self):
        claimed = self.claim()
        with self.assertRaises(GuardError):
            self.journal.close_task("T", expected_revision=claimed["revision"], key="worker-pass", disposition="PASS")
        closed = self.journal.close_task("T", expected_revision=claimed["revision"], key="close")
        self.reopen()
        with self.assertRaises(GuardError):
            self.journal.claim("T", "owner", "local_copy", expected_revision=closed["revision"], key="after-session")
        self.assertEqual(closed["disposition"], "OWNER_ABANDONED")
        self.assertNotIn("outcome", closed)
        self.assertGreater(closed["fence"], claimed["fence"])

    def test_foreign_store_relocation_and_chain_corruption_refused(self):
        foreign = self.root / "foreign.sqlite"
        with sqlite3.connect(foreign) as db:
            db.execute("CREATE TABLE foreign_data(value TEXT)")
        before_sha = hashlib.sha256(foreign.read_bytes()).hexdigest()
        with self.assertRaises(GuardError):
            ContinuityJournal(foreign)
        self.assertEqual(hashlib.sha256(foreign.read_bytes()).hexdigest(), before_sha)
        with sqlite3.connect(foreign) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        copy_path = self.root / "copy.sqlite"
        with sqlite3.connect(copy_path) as backup:
            self.journal.db.backup(backup)
        with self.assertRaises(GuardError):
            ContinuityJournal(copy_path)
        self.journal.db.execute("DROP TRIGGER continuity_events_no_update")
        self.journal.db.execute("UPDATE continuity_events SET body='{}' WHERE id=1")
        self.assertFalse(self.journal.verify_chain())
        with self.assertRaises(GuardError):
            ContinuityJournal(self.path)

    def test_clock_regression_is_refused_without_transition(self):
        before = self.journal.get("T")
        self.now[0] = 99.0
        with self.assertRaises(GuardError):
            self.claim()
        self.assertEqual(self.journal.get("T"), before)

    def test_real_process_crashes_before_commit_and_after_commit_before_ack(self):
        program = '''
from contextlib import contextmanager
import os, sys
from universal.continuity import ContinuityJournal
j = ContinuityJournal(sys.argv[1], clock=lambda:100.0)
if sys.argv[2] == "before":
    @contextmanager
    def crash_transaction():
        j.db.execute("BEGIN IMMEDIATE")
        yield
        os._exit(71)
    j._transaction = crash_transaction
j.claim("T", "owner", "local_copy", expected_revision=1, key="crash-claim", ttl=1)
os._exit(72)
'''
        before = subprocess.run([sys.executable, "-B", "-c", program, str(self.path), "before"], cwd=ROOT, capture_output=True, timeout=10)
        self.assertEqual((before.returncode, before.stdout, before.stderr), (71, b"", b""))
        self.reopen()
        self.assertEqual((self.journal.get("T")["state"], self.journal.get("T")["spent"]), ("READY", 0))
        after = subprocess.run([sys.executable, "-B", "-c", program, str(self.path), "after"], cwd=ROOT, capture_output=True, timeout=10)
        self.assertEqual((after.returncode, after.stdout, after.stderr), (72, b"", b""))
        self.reopen()
        replay = self.journal.claim("T", "owner", "local_copy", expected_revision=1, key="crash-claim", ttl=1)
        self.assertTrue(replay["replayed"])
        self.assertEqual((replay["spent"], replay["attempts"]), (1, 1))
        self.now[0] = 101.0
        recovered = self.journal.recover("T", expected_revision=replay["revision"], key="crash-recover")
        self.assertEqual(recovered["state"], "PAUSED")
        self.assertTrue(self.journal.verify_chain())


if __name__ == "__main__":
    unittest.main()
