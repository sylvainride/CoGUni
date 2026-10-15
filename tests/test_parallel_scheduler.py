"""Owner facade tests on temporary synthetic journals; no live provider claims.

Callbacks are explicit synthetic fixtures, not production authentication or proof
verification. Process races exercise the real existing SQLite journal boundary.
"""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from universal.continuity import ContinuityJournal
from universal.core import GuardError
from universal.parallel_policy import Access, Work
from universal.parallel_scheduler import OwnerScheduler

ROOT = Path(__file__).resolve().parents[1]
CODE = "a" * 40
REQUEST = "b" * 64
TARGET = "c" * 40


def synthetic_work(task="A", *, target=None, depends_on=(), **changes):
    branch = "work/mvp-mission-transport-policy-" + task
    resource = Access("github", 1418009675, "synthetic-P", "refs/heads/" + branch,
                      "/artifact", "W", TARGET, target or "target-" + task)
    values = dict(task_id=task, depends_on=tuple(depends_on), accesses=(resource,), authorized=True)
    values.update(changes)
    return Work(**values)


def synthetic_provider(task="A", **changes):
    values = dict(repository_id=1418009675, actor_id=265171248, run_id=10001,
                  attempt=1, commit="d" * 40,
                  branch="work/mvp-mission-transport-policy-" + task,
                  code_ref=CODE, request_sha256=REQUEST, status="in_progress", conclusion=None)
    values.update(changes)
    return values


RACE_CHILD = r"""
import json, pathlib, sys, time
from universal.continuity import ContinuityJournal
from universal.parallel_scheduler import OwnerScheduler
db, task, owner, gate, mode, source, backlog = sys.argv[1:]
journal = ContinuityJournal(db, clock=lambda: 100.0)
try:
    scheduler = OwnerScheduler(journal, enabled=True, check_current=lambda work, meta: True,
                               check_applied=lambda *args: False, max_backlog=int(backlog))
    pathlib.Path(gate + '-' + owner).write_text('ready')
    until = time.monotonic() + 10
    while not pathlib.Path(gate).exists():
        if time.monotonic() > until:
            raise RuntimeError('synthetic race barrier timed out')
        time.sleep(.005)
    try:
        if mode == 'submit':
            from tests.test_parallel_scheduler import synthetic_work, CODE, REQUEST
            result = scheduler.submit(synthetic_work(task), source_path=source, code_ref=CODE,
                                      request_sha256=REQUEST, branch='work/mvp-mission-transport-policy-' + task,
                                      expires_unix=1000, key='submit-' + task)
        else:
            result = scheduler.reserve(task, expected_revision=1, owner=owner, key='reserve-' + owner)
        print(json.dumps({'reserved': True, 'task': task, 'fence': result['fence']}))
    except Exception as exc:
        print(json.dumps({'reserved': False, 'task': task, 'error': type(exc).__name__}))
finally:
    journal.close()
"""


class ParallelSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="parallel-scheduler-test-")
        self.root = Path(self.temp.name)
        self.source = self.root / "synthetic-source.txt"
        self.source.write_text("public synthetic immutable fixture\n")
        self.now = [100.0]
        self.permissions_current = True
        self.applied_checks = []
        self.journals = []
        self.journal, self.scheduler = self.fresh()

    def tearDown(self):
        for journal in self.journals:
            try:
                journal.close()
            except Exception:
                pass
        self.temp.cleanup()

    def owner_current_fixture(self, work, metadata):
        return (self.permissions_current and metadata["code_ref"] == CODE
                and metadata["branch"].endswith(work.task_id))

    def owner_applied_fixture(self, work, metadata, provider, evidence):
        self.applied_checks.append((work.task_id, provider["run_id"], evidence))
        return (evidence == {"owner_readback": work.task_id, "target_sha": TARGET}
                and metadata["request_sha256"] == provider["request_sha256"])

    def fresh(self, **configuration):
        path = self.root / ("owner-%d.sqlite" % len(self.journals))
        journal = ContinuityJournal(path, clock=lambda: self.now[0])
        self.journals.append(journal)
        scheduler = OwnerScheduler(journal, enabled=True,
                                   check_current=self.owner_current_fixture,
                                   check_applied=self.owner_applied_fixture, **configuration)
        return journal, scheduler

    def submit(self, task="A", *, scheduler=None, key=None, work=None, **changes):
        scheduler = scheduler or self.scheduler
        args = dict(source_path=self.source, code_ref=CODE, request_sha256=REQUEST,
                    branch="work/mvp-mission-transport-policy-" + task,
                    expires_unix=1000, key=key or "submit-" + task)
        args.update(changes)
        return scheduler.submit(work or synthetic_work(task), **args)

    def reserve(self, task="A", *, scheduler=None, owner="owner-1", key=None):
        scheduler = scheduler or self.scheduler
        state = scheduler.status(task)
        return scheduler.reserve(task, expected_revision=state["revision"], owner=owner,
                                 key=key or "reserve-" + task)

    def observe(self, task="A", provider=None, *, scheduler=None, key=None):
        scheduler = scheduler or self.scheduler
        state = scheduler.status(task)
        return scheduler.observe(task, provider or synthetic_provider(task),
                                 expected_revision=state["revision"], fence=state["fence"],
                                 owner=state["owner"], key=key or "observe-" + task)

    def accept(self, task="A", evidence=None, *, scheduler=None, key=None):
        scheduler = scheduler or self.scheduler
        state = scheduler.status(task)
        return scheduler.accept_applied(task, evidence if evidence is not None else
                                        {"owner_readback": task, "target_sha": TARGET},
                                        expected_revision=state["revision"], fence=state["fence"],
                                        owner=state["owner"], key=key or "accept-" + task)

    def test_a_b_reserved_independently_and_no_dispatch_or_grant(self):
        self.submit("A")
        self.submit("B")
        ready = self.scheduler.ready()
        self.assertEqual(ready["selected"], ("A", "B"))
        self.assertFalse(ready["execution_authorized"])
        self.assertFalse(ready["dispatch_performed"])
        a = self.reserve("A")
        b = self.reserve("B")
        self.assertEqual((a["state"], b["state"]), ("IN_FLIGHT", "IN_FLIGHT"))
        self.assertFalse(a["effect_retry_authorized"])
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 6)
        self.assertTrue(self.journal.verify_chain())
        self.assertEqual({r[0] for r in self.journal.db.execute("SELECT name FROM sqlite_master WHERE type='table'")},
                         {"continuity_meta", "continuity_tasks", "continuity_receipts", "continuity_events"})

    def test_disabled_or_missing_owner_checker_cannot_reserve(self):
        self.submit()
        for enabled, checker in ((False, self.owner_current_fixture), (True, None), (True, lambda *_: 1)):
            scheduler = OwnerScheduler(self.journal, enabled=enabled, check_current=checker)
            with self.subTest(enabled=enabled, checker=checker), self.assertRaises(GuardError):
                self.reserve(scheduler=scheduler)
        self.assertEqual(self.scheduler.status("A")["state"], "READY")
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 8)

    def test_permissions_source_and_expiration_rechecked_before_reservation(self):
        self.submit()
        before = self.scheduler.status("A")
        self.permissions_current = False
        with self.assertRaises(GuardError):
            self.reserve()
        self.permissions_current = True
        self.now[0] = 1000.0
        with self.assertRaises(GuardError):
            self.reserve()
        self.assertEqual(self.scheduler.status("A"), before)
        self.source.write_text("changed after owner submit\n")
        with self.assertRaises(GuardError):
            self.scheduler.ready()

    def test_d_waits_for_a_provider_success_owner_gate_and_target_readback(self):
        self.submit("A")
        self.submit("D", work=synthetic_work("D", depends_on=("A",)))
        self.assertNotIn("D", self.scheduler.ready()["selected"])
        self.reserve("A")
        with self.assertRaises(GuardError):
            self.accept("A")
        self.observe("A", synthetic_provider(status="completed", conclusion="success"))
        self.assertNotIn("D", self.scheduler.ready()["selected"])
        for evidence in ({"worker_pass": True}, {"owner_readback": "A", "target_sha": "e" * 40}):
            with self.subTest(evidence=evidence), self.assertRaises(GuardError):
                self.accept(evidence=evidence)
        self.assertNotIn("D", self.scheduler.ready()["selected"])
        accepted = self.accept("A")
        self.assertEqual(accepted["state"], "ACCEPTED_APPLIED")
        self.assertEqual(self.scheduler.ready()["selected"], ("D",))
        self.assertEqual(self.reserve("D")["state"], "IN_FLIGHT")

    def test_observations_return_out_of_order_without_project_confusion(self):
        for task in ("A", "B"):
            self.submit(task)
            self.reserve(task)
        self.observe("B", synthetic_provider("B", run_id=20002, status="completed", conclusion="success"))
        self.accept("B")
        self.assertEqual(self.scheduler.status("A")["state"], "IN_FLIGHT")
        self.assertEqual(self.scheduler.status("B")["provider"]["run_id"], 20002)
        self.observe("A", synthetic_provider(status="completed", conclusion="success"))
        self.accept("A")
        self.assertEqual({task: self.scheduler.status(task)["state"] for task in ("A", "B")},
                         {"A": "ACCEPTED_APPLIED", "B": "ACCEPTED_APPLIED"})

    def test_provider_branch_actor_repo_and_bound_run_attempt_commit_spoofs_refused(self):
        self.submit()
        self.reserve()
        before = self.scheduler.status("A")
        invalid = [{"repository_id": 99}, {"repository_id": True}, {"actor_id": 99},
                   {"branch": "work/mvp-mission-transport-policy-other"},
                   {"code_ref": "e" * 40}, {"request_sha256": "f" * 64},
                   {"run_id": True}, {"attempt": 0}, {"commit": "A" * 40}]
        for index, changes in enumerate(invalid):
            with self.subTest(changes=changes), self.assertRaises(GuardError):
                self.observe(provider=synthetic_provider(**changes), key="bad-initial-%d" % index)
            self.assertEqual(self.scheduler.status("A"), before)
        self.observe()
        for index, changes in enumerate(({"run_id": 20002}, {"attempt": 2}, {"commit": "e" * 40})):
            with self.subTest(changes=changes), self.assertRaises(GuardError):
                self.observe(provider=synthetic_provider(**changes), key="bad-bound-%d" % index)
        self.assertEqual(self.scheduler.status("A")["provider"], synthetic_provider())

    def test_terminal_failure_and_silent_active_never_release_or_retry(self):
        self.submit()
        self.submit("B", work=synthetic_work("B", target="target-A"))
        self.reserve()
        for index in range(3):
            state = self.observe(key="silent-%d" % index)
            self.assertEqual(state["state"], "IN_FLIGHT")
            self.assertFalse(state["effect_retry_authorized"])
        failed = self.observe(provider=synthetic_provider(status="completed", conclusion="failure"), key="terminal-failure")
        self.assertEqual(failed["state"], "SUSPECT")
        self.assertNotIn("B", self.scheduler.ready()["selected"])
        with self.assertRaises(GuardError):
            self.observe(key="late-running")
        with self.assertRaises(GuardError):
            self.accept()

    def test_lost_reservation_ack_replays_without_second_run_budget(self):
        self.submit()
        reserved = self.reserve()
        after = self.scheduler.ready()
        replay = self.scheduler.reserve("A", expected_revision=1, owner="owner-1", key="reserve-A")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["fence"], reserved["fence"])
        self.assertEqual(self.scheduler.ready(), after)
        with self.assertRaises(GuardError):
            self.scheduler.reserve("A", expected_revision=1, owner="other-owner", key="reserve-A")
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 1)

    def test_lost_apply_ack_unknown_holds_across_reopen_without_redispatch(self):
        self.submit()
        self.submit("B", work=synthetic_work("B", target="target-A"))
        active = self.reserve()
        unknown = self.scheduler.mark_unknown("A", expected_revision=active["revision"],
                                               fence=active["fence"], owner=active["owner"], key="lost-apply-ack")
        self.assertEqual(unknown["state"], "UNKNOWN_EFFECT")
        path = self.journal.path
        identity = self.journal.identity
        self.journal.close()
        self.journal = ContinuityJournal(path, clock=lambda: self.now[0])
        self.journals.append(self.journal)
        self.scheduler = OwnerScheduler(self.journal, enabled=True, check_current=self.owner_current_fixture,
                                        check_applied=self.owner_applied_fixture)
        self.assertEqual(self.journal.identity, identity)
        self.assertEqual(self.scheduler.reconcile("A"), unknown)
        self.assertEqual(self.scheduler.ready()["selected"], ())
        self.assertFalse(self.scheduler.reconcile("A")["effect_retry_authorized"])
        with self.assertRaises(GuardError):
            self.reserve()
        with self.assertRaises(GuardError):
            self.scheduler.cancel_queued("A", expected_revision=unknown["revision"], key="unsafe-cancel")
        self.assertTrue(self.journal.verify_chain())

    def test_budget_reopen_cannot_reset_spent_reservation_or_raise_config(self):
        self.submit("A", work=synthetic_work("A", run_cost=8))
        self.submit("B")
        self.reserve()
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 0)
        self.observe(provider=synthetic_provider(status="completed", conclusion="success"))
        self.accept()
        with self.assertRaises(GuardError):
            OwnerScheduler(self.journal, enabled=True, run_budget=9, check_current=self.owner_current_fixture)
        same = OwnerScheduler(self.journal, enabled=True, check_current=self.owner_current_fixture,
                              check_applied=self.owner_applied_fixture)
        self.assertEqual(same.ready()["remaining_runs"], 0)
        self.assertNotIn("B", same.ready()["selected"])
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 1)

    def test_submit_idempotence_mismatch_and_dependency_missing(self):
        first = self.submit()
        self.assertEqual(self.submit(), first)
        with self.assertRaises(GuardError):
            self.submit(request_sha256="e" * 64)
        with self.assertRaises((GuardError, ValueError)):
            self.submit("D", work=synthetic_work("D", depends_on=("missing",)))
        self.assertEqual(len(self.scheduler.handoff()["tasks"]), 1)

    def test_poll_budget_replays_do_not_spend_and_handoff_is_inert(self):
        journal, scheduler = self.fresh(poll_budget=2)
        self.submit(scheduler=scheduler)
        active = self.reserve(scheduler=scheduler)
        provider = synthetic_provider()
        first = scheduler.observe("A", provider, expected_revision=active["revision"],
                                  fence=active["fence"], owner=active["owner"], key="poll-one")
        scheduler.observe("A", provider, expected_revision=active["revision"],
                          fence=active["fence"], owner=active["owner"], key="poll-one")
        self.assertEqual(scheduler.ready()["polls_left"], 1)
        self.observe(scheduler=scheduler, key="poll-two")
        self.assertEqual(scheduler.ready()["polls_left"], 0)
        with self.assertRaises(GuardError):
            self.observe(scheduler=scheduler, key="poll-three")
        before = scheduler.status("A")
        handoff = scheduler.handoff()
        self.assertFalse(handoff["persistent_service"])
        self.assertFalse(handoff["chat_wakeup_available"])
        self.assertIn("Écris reprise", handoff["message"])
        self.assertEqual(scheduler.status("A"), before)
        self.assertTrue(journal.verify_chain())

    def test_only_unreserved_work_can_be_cancelled(self):
        self.submit()
        state = self.scheduler.status("A")
        cancelled = self.scheduler.cancel_queued("A", expected_revision=state["revision"], key="cancel-A")
        self.assertEqual(cancelled["state"], "CANCELLED")
        self.assertEqual(self.scheduler.ready()["selected"], ())
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 8)
        with self.assertRaises(GuardError):
            self.reserve()

    def test_backlog_full_replay_remains_idempotent(self):
        _, scheduler = self.fresh(max_backlog=1)
        submitted = self.submit(scheduler=scheduler)
        self.assertEqual(self.submit(scheduler=scheduler), submitted)
        with self.assertRaises((GuardError, ValueError)):
            self.submit("B", scheduler=scheduler)
        self.assertEqual(scheduler.handoff()["tasks"], [submitted])

    def test_implementation_pin_drift_blocks_ready_and_reserve(self):
        self.submit()
        real_checker = self.journal._sources_current
        def drifted_policy_fixture(contract):
            if any(name.endswith("parallel_policy.py") for name in contract["sources"]):
                return False
            return real_checker(contract)
        with patch.object(self.journal, "_sources_current", side_effect=drifted_policy_fixture):
            with self.assertRaises(GuardError):
                self.scheduler.ready()
            with self.assertRaises(GuardError):
                self.scheduler.reserve("A", expected_revision=1, owner="owner-1", key="drifted-reserve")
        self.assertEqual(self.scheduler.status("A")["state"], "READY")
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 0)

    def test_source_symlink_noncanonical_and_version_inputs_refused(self):
        link = self.root / "alias.txt"
        link.symlink_to(self.source)
        for changes in ({"source_path": link}, {"source_path": "relative.txt"},
                        {"source_path": str(self.root / "missing" / ".." / self.source.name)},
                        {"code_ref": "A" * 40}, {"request_sha256": "b" * 63},
                        {"branch": "unapproved/mission"}, {"expires_unix": True},
                        {"expires_unix": 100}, {"expires_unix": 86501}):
            with self.subTest(changes=changes), self.assertRaises((GuardError, ValueError)):
                self.submit(**changes)
        self.assertEqual(self.scheduler.handoff()["tasks"], [])

    def test_initial_lease_is_bounded_by_declared_duration(self):
        self.submit(work=synthetic_work(duration_seconds=1))
        active = self.reserve()
        self.assertLessEqual(active["lease_until"], self.now[0] + 1)
        self.now[0] = 101.0
        with self.assertRaises(GuardError):
            self.observe()

    def test_expired_lease_recovery_fences_old_owner_and_preserves_run_budget(self):
        self.submit(work=synthetic_work(duration_seconds=900))
        active = self.reserve()
        bound = self.observe()
        self.now[0] = active["lease_until"]
        with self.assertRaises(GuardError):
            self.observe(key="expired-observe")
        with self.assertRaises(GuardError):
            self.accept()
        with self.assertRaises(GuardError):
            self.scheduler.mark_unknown("A", expected_revision=bound["revision"], fence=bound["fence"],
                                        owner=bound["owner"], key="expired-unknown")
        recovered = self.scheduler.recover("A", expected_revision=bound["revision"],
                                           owner="owner-after-restart", key="recover-A")
        self.assertGreater(recovered["fence"], bound["fence"])
        self.assertEqual(recovered["provider"], bound["provider"])
        self.assertEqual(recovered["state"], "IN_FLIGHT")
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 7)
        with self.assertRaises(GuardError):
            self.scheduler.observe("A", synthetic_provider(), expected_revision=recovered["revision"],
                                   fence=bound["fence"], owner=bound["owner"], key="old-controller-observe")
        fresh = self.scheduler.observe("A", synthetic_provider(status="completed", conclusion="success"),
                                       expected_revision=recovered["revision"], fence=recovered["fence"],
                                       owner=recovered["owner"], key="new-controller-observe")
        unknown = self.scheduler.mark_unknown("A", expected_revision=fresh["revision"], fence=fresh["fence"],
                                               owner=fresh["owner"], key="effect-ack-lost-after-restart")
        accepted = self.scheduler.reconcile("A", {"owner_readback": "A", "target_sha": TARGET},
                                            expected_revision=unknown["revision"], fence=unknown["fence"],
                                            owner=unknown["owner"], key="reconcile-original-effect")
        self.assertEqual(accepted["state"], "ACCEPTED_APPLIED")
        self.assertFalse(accepted["effect_retry_authorized"])
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 1)

    def test_renewal_requires_bound_provider_and_stops_at_original_deadline(self):
        self.submit(work=synthetic_work(duration_seconds=900))
        active = self.reserve()
        with self.assertRaises(GuardError):
            self.scheduler.renew("A", expected_revision=active["revision"], fence=active["fence"],
                                 owner=active["owner"], key="renew-without-provider")
        state = self.observe()
        for now in (399.0, 698.0, 997.0):
            self.now[0] = now
            state = self.scheduler.renew("A", expected_revision=state["revision"], fence=state["fence"],
                                         owner=state["owner"], key="renew-%d" % now)
            self.assertLessEqual(state["lease_until"], 1000.0)
        self.assertEqual(state["lease_until"], 1000.0)
        self.now[0] = 1000.0
        with self.assertRaises(GuardError):
            self.scheduler.renew("A", expected_revision=state["revision"], fence=state["fence"],
                                 owner=state["owner"], key="renew-after-deadline")
        with self.assertRaises(GuardError):
            self.scheduler.recover("A", expected_revision=state["revision"], owner="owner-2",
                                   key="recover-after-deadline")
        self.assertEqual(self.scheduler.ready()["held"], ("A",))

    def test_slow_independent_readback_cannot_accept_after_lease_expiry(self):
        self.submit()
        self.reserve()
        state = self.observe(provider=synthetic_provider(status="completed", conclusion="success"))
        def slow_owner_readback_fixture(*_):
            self.now[0] = state["lease_until"]
            return True
        self.scheduler.check_applied = slow_owner_readback_fixture
        with self.assertRaises(GuardError):
            self.accept()
        self.assertEqual(self.scheduler.status("A"), state)
        self.assertEqual(self.scheduler.ready()["held"], ("A",))

    def test_slow_acl_check_cannot_renew_an_expired_lease(self):
        self.submit(work=synthetic_work(duration_seconds=900))
        self.reserve()
        state = self.observe()
        self.now[0] = state["lease_until"] - 1
        def slow_current_fixture(*_):
            self.now[0] = state["lease_until"]
            return True
        self.scheduler.check_current = slow_current_fixture
        with self.assertRaises(GuardError):
            self.scheduler.renew("A", expected_revision=state["revision"], fence=state["fence"],
                                 owner=state["owner"], key="slow-expired-renewal")
        self.assertEqual(self.scheduler.status("A"), state)

    def _race(self, task_ids, *, scheduler=None, submission=False):
        scheduler = scheduler or self.scheduler
        gate = self.root / "go"
        processes = []
        for index, task in enumerate(task_ids):
            owner = "process-%d" % index
            processes.append(subprocess.Popen([sys.executable, "-c", RACE_CHILD,
                                                str(scheduler.journal.path), task, owner, str(gate),
                                                "submit" if submission else "reserve", str(self.source),
                                                str(scheduler.config["max_backlog"])],
                                               cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE))
        try:
            stop = time.monotonic() + 10
            while not all(Path(str(gate) + "-process-%d" % index).exists() for index in range(len(processes))):
                if any(process.poll() is not None for process in processes) or time.monotonic() > stop:
                    self.fail("synthetic owner race did not reach its start barrier")
                time.sleep(.005)
            gate.write_text("start\n")
            outputs = [process.communicate(timeout=10) for process in processes]
            for process, (_, stderr) in zip(processes, outputs):
                self.assertEqual(process.returncode, 0, stderr)
            return [json.loads(stdout) for stdout, _ in outputs]
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_two_processes_same_task_reserve_exactly_one_attempt(self):
        self.submit()
        results = self._race(("A", "A"))
        self.assertEqual(sum(result["reserved"] for result in results), 1)
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 1)
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 7)
        self.assertTrue(self.journal.verify_chain())

    def test_two_processes_same_write_target_reserve_only_one_task(self):
        self.submit("A")
        self.submit("B", work=synthetic_work("B", target="target-A"))
        results = self._race(("A", "B"))
        self.assertEqual(sum(result["reserved"] for result in results), 1)
        self.assertEqual(sum(self.journal.get("ps-job-" + task)["attempts"] for task in ("A", "B")), 1)
        self.assertTrue(self.journal.verify_chain())

    def test_two_processes_independent_targets_reserve_both(self):
        self.submit("A")
        self.submit("B")
        results = self._race(("A", "B"))
        self.assertEqual(sum(result["reserved"] for result in results), 2)
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 6)
        self.assertEqual(self.scheduler.ready()["selected"], ())
        self.assertTrue(self.journal.verify_chain())

    def test_two_processes_cold_backlog_one_cannot_overbook_and_replay_while_full(self):
        journal, scheduler = self.fresh(max_backlog=1)
        results = self._race(("A", "B"), scheduler=scheduler, submission=True)
        self.assertEqual(sum(result["reserved"] for result in results), 1)
        admitted = next(result["task"] for result in results if result["reserved"])
        original = scheduler.status(admitted)
        self.assertEqual(self.submit(admitted, scheduler=scheduler), original)
        self.assertEqual(scheduler.handoff()["tasks"], [original])
        self.assertEqual(scheduler.ready()["remaining_runs"], 8)
        self.assertTrue(journal.verify_chain())


if __name__ == "__main__":
    unittest.main()
