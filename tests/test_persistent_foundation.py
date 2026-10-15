"""Deterministic owner-only P4 tests. All provider reads are synthetic fixtures.

No network, cron, credentials, live GitHub mutation or deployed scheduler.
"""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from universal.continuity import ContinuityJournal
from universal.core import GuardError
from universal.parallel_policy import Access, Work
from universal.parallel_scheduler import OwnerScheduler
from universal.persistent_provider_observation import ProviderObservation, UnavailableReadback
from universal.persistent_resume import export_resume, validate_resume
from universal.persistent_supervisor import HealthReadback, PassiveSupervisor

CODE = "a" * 40
REQUEST = "b" * 64
TARGET = "c" * 40
ROOT = Path(__file__).resolve().parents[1]


class PersistentFoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="p4-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "public-synthetic.txt"
        self.source.write_text("immutable synthetic source\n")
        self.now = [100.0]
        self.db_path = self.root / "original.sqlite"
        self.journal = ContinuityJournal(self.db_path, clock=lambda: self.now[0])
        self.addCleanup(self._close)
        self.scheduler = self.open_scheduler()
        self.supervisor = PassiveSupervisor(self.scheduler)

    def _close(self):
        if self.journal is not None:
            self.journal.close()
            self.journal = None

    def open_scheduler(self, **updates):
        options = dict(enabled=True, run_budget=2, poll_budget=3,
                       check_current=lambda *_: True, check_applied=lambda *_: False)
        options.update(updates)
        return OwnerScheduler(self.journal, **options)

    def reopen(self):
        self._close()
        self.journal = ContinuityJournal(self.db_path, clock=lambda: self.now[0])
        self.scheduler = self.open_scheduler()
        self.supervisor = PassiveSupervisor(self.scheduler)

    def work(self, task="A", *, physical=None, depends_on=()):
        ref = "work/mvp-mission-transport-p4-" + task
        resource = Access("github", 1418009675, "synthetic-project", "refs/heads/" + ref,
                          "/artifact", "W", TARGET, physical or "physical-" + task)
        return Work(task_id=task, depends_on=tuple(depends_on), accesses=(resource,),
                    authorized=True)

    def submit(self, task="A", **kw):
        args = dict(source_path=self.source, code_ref=CODE, request_sha256=REQUEST,
                    branch="work/mvp-mission-transport-p4-" + task,
                    expires_unix=1000, key="submit-" + task)
        return self.scheduler.submit(self.work(task, **kw), **args)

    def reserve(self, task="A"):
        status = self.scheduler.status(task)
        return self.scheduler.reserve(task, expected_revision=status["revision"],
                                      owner="owner-1", key="reserve-" + task)

    def provider(self, observation_id="read-1", task="A", **changes):
        args = dict(observation_id=observation_id, repository_id=1418009675,
                    actor_id=265171248, run_id=10001, attempt=1, commit="d" * 40,
                    branch="work/mvp-mission-transport-p4-" + task,
                    code_ref=CODE, request_sha256=REQUEST,
                    status="in_progress", conclusion=None,
                    observed_unix=int(self.now[0]))
        args.update(changes)
        return ProviderObservation(**args)

    def read(self, provider, *, health=True):
        def owner_reader(task, status):
            heartbeat = HealthReadback(provider.run_id, status["fence"], int(self.now[0])) if health else None
            return provider, heartbeat
        return owner_reader

    def tick(self, provider, *, health=True):
        return self.supervisor.tick(("A",), provider_reader=self.read(provider, health=health),
                                    now_unix=int(self.now[0]))[0]

    def test_typed_observation_is_immutable_and_not_a_credential(self):
        o = self.provider()
        with self.assertRaises(FrozenInstanceError):
            o.actor_id = 1
        self.assertNotIn("trusted", o.scheduler_record())
        self.assertNotIn("observation_id", o.scheduler_record())
        self.assertEqual(len(o.scheduler_record()), 10)

    def test_spoof_types_oversize_unicode_and_terminal_contradictions_refused(self):
        for changes in (
            {"repository_id": True}, {"repository_id": 0}, {"actor_id": False},
            {"run_id": "10001"}, {"run_id": -1}, {"attempt": 0}, {"attempt": 101},
            {"observation_id": "x" * 65}, {"observation_id": "\ud800"},
            {"commit": "A" * 40}, {"code_ref": "a" * 39},
            {"request_sha256": "b" * 63}, {"branch": "main"},
            {"observed_unix": True}, {"status": "worker_PASS"},
            {"status": "in_progress", "conclusion": "success"},
            {"status": "completed", "conclusion": None},
            {"status": "completed", "conclusion": "PASS"},
        ):
            with self.subTest(changes=changes), self.assertRaises(GuardError):
                self.provider(**changes)

    def test_foreign_owner_repo_ref_and_observation_clock_refused_without_mutation(self):
        self.submit()
        self.reserve()
        before = self.scheduler.status("A")
        for changes in (
            {"repository_id": 55}, {"actor_id": 56}, {"code_ref": "e" * 40},
            {"request_sha256": "e" * 64},
            {"branch": "work/mvp-mission-transport-other"},
            {"observed_unix": 200}, {"observed_unix": 0},
        ):
            with self.subTest(changes=changes), self.assertRaises(GuardError):
                self.tick(self.provider(**changes))
            self.assertEqual(self.scheduler.status("A"), before)
        self.assertEqual(self.scheduler.ready()["polls_left"], 3)

    def test_silent_running_keeps_original_reservation_and_never_cancels(self):
        self.submit()
        before = self.reserve()
        verdict = self.tick(self.provider())
        self.assertEqual((verdict.action, verdict.liveness), ("RECORDED", "SILENT_RUNNING"))
        self.assertFalse(verdict.execution_authorized)
        self.assertFalse(verdict.may_cancel)
        self.assertFalse(verdict.may_retry_write)
        self.assertEqual(self.scheduler.status("A")["state"], "IN_FLIGHT")
        self.assertEqual(self.scheduler.status("A")["fence"], before["fence"])
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 1)

    def test_missing_independent_heartbeat_is_suspect_not_failure(self):
        self.submit()
        self.reserve()
        verdict = self.tick(self.provider(), health=False)
        self.assertEqual(verdict.liveness, "SUSPECT_RECOVERY")
        self.assertEqual(self.scheduler.status("A")["state"], "IN_FLIGHT")

    def test_unknown_effect_never_invokes_reader_or_releases_collision(self):
        self.submit()
        self.submit("B", physical="physical-A")
        state = self.reserve()
        unknown = self.scheduler.mark_unknown("A", expected_revision=state["revision"],
                                               fence=state["fence"], owner=state["owner"],
                                               key="lost-effect-ack")
        def forbidden_reader(*_):
            self.fail("UNKNOWN_EFFECT must not poll or dispatch a new provider job")
        verdict = self.supervisor.tick(("A",), provider_reader=forbidden_reader,
                                       now_unix=100)[0]
        self.assertEqual((verdict.action, verdict.liveness), ("RECONCILE", "UNKNOWN_EFFECT"))
        self.assertNotIn("B", self.scheduler.ready()["selected"])
        handle = export_resume(self.scheduler, ("A",))
        self.reopen()
        self.assertEqual(validate_resume(self.scheduler, handle).states, ("UNKNOWN_EFFECT",))
        self.assertEqual(self.scheduler.status("A"), unknown)
        self.assertFalse(self.scheduler.status("A")["effect_retry_authorized"])

    def test_provider_success_is_not_applied_and_dependency_stays_held(self):
        self.submit("A")
        self.submit("B", depends_on=("A",))
        self.reserve()
        verdict = self.tick(self.provider(status="completed", conclusion="success"))
        self.assertEqual(verdict.liveness, "UNKNOWN")  # no owner manifest attestation
        self.assertEqual(self.scheduler.status("A")["state"], "IN_FLIGHT")
        self.assertNotIn("B", self.scheduler.ready()["selected"])
        with self.assertRaises(GuardError):
            state = self.scheduler.status("A")
            self.scheduler.accept_applied("A", {"worker_pass": True},
                                          expected_revision=state["revision"],
                                          fence=state["fence"], owner=state["owner"],
                                          key="forged-accept")

    def test_lost_observation_ack_replays_without_second_poll(self):
        self.submit()
        self.reserve()
        first = self.tick(self.provider("stable-read"))
        self.assertEqual(self.scheduler.ready()["polls_left"], 2)
        repeated = self.tick(self.provider("stable-read"))
        self.assertEqual(repeated.action, "REPLAY")
        self.assertEqual(repeated.revision, first.revision)
        self.assertEqual(self.scheduler.ready()["polls_left"], 2)
        self.assertTrue(self.journal.verify_chain())

    def test_original_poll_budget_does_not_reset_on_restart(self):
        self.submit()
        self.reserve()
        for seq in range(3):
            self.tick(self.provider("read-%d" % seq))
        self.assertEqual(self.scheduler.ready()["polls_left"], 0)
        self.reopen()
        before = self.scheduler.status("A")
        verdict = self.tick(self.provider("new-read"))
        self.assertEqual(verdict.action, "HANDOFF")
        self.assertEqual(before, self.scheduler.status("A"))
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 1)
        with self.assertRaises(GuardError):
            self.open_scheduler(run_budget=3)

    def test_run_and_attempt_substitution_refused(self):
        self.submit()
        self.reserve()
        self.tick(self.provider())
        for changes in ({"run_id": 20002}, {"attempt": 2}, {"commit": "e" * 40}):
            with self.subTest(changes=changes), self.assertRaises(GuardError):
                self.tick(self.provider("next-read", **changes))
        self.assertEqual(self.scheduler.ready()["polls_left"], 2)

    def test_colliding_observation_ids_fail_closed(self):
        self.submit()
        self.reserve()
        self.tick(self.provider("reused-key"))
        with self.assertRaises(GuardError):
            self.tick(self.provider("reused-key", status="completed", conclusion="success"))
        self.assertEqual(self.scheduler.ready()["polls_left"], 2)

    def test_resume_reopen_same_store_and_reject_stale_revision_fence(self):
        self.submit()
        before = self.reserve()
        wire = export_resume(self.scheduler, ("A",))
        identity = self.journal.identity
        self.reopen()
        self.assertEqual(self.journal.identity, identity)
        h = validate_resume(self.scheduler, wire)
        self.assertEqual(h.task_ids, ("A",))
        self.assertFalse(h.execution_authorized)
        self.tick(self.provider())
        with self.assertRaises(GuardError):
            validate_resume(self.scheduler, wire)
        self.assertGreater(self.scheduler.status("A")["revision"], before["revision"])

    def test_forged_resume_and_foreign_store_refused(self):
        self.submit()
        wire = export_resume(self.scheduler, ("A",))
        for forged in (wire + " ", wire.replace('"authority":"NONE"', '"authority":"OWNER"'),
                       wire.replace('"fence":0', '"fence":1'),
                       wire.replace(self.journal.identity, "f" * 64), "\ud800"):
            with self.subTest(forged=forged[:48]), self.assertRaises(GuardError):
                validate_resume(self.scheduler, forged)
        other_path = self.root / "copy.sqlite"
        self._close()
        shutil.copyfile(self.db_path, other_path)
        with self.assertRaises(GuardError):
            ContinuityJournal(other_path, clock=lambda: self.now[0])
        self.reopen()
        self.assertEqual(validate_resume(self.scheduler, wire).task_ids, ("A",))

    def test_source_drift_blocks_even_passive_read_and_resume(self):
        self.submit()
        self.reserve()
        wire = export_resume(self.scheduler, ("A",))
        self.source.write_text("changed after admission\n")
        with self.assertRaises(GuardError):
            self.tick(self.provider())
        with self.assertRaises(GuardError):
            validate_resume(self.scheduler, wire)

    def test_expired_lease_is_not_recovered_by_tick(self):
        self.submit()
        self.reserve()
        state = self.scheduler.status("A")
        self.now[0] = state["lease_until"]
        verdict = self.tick(self.provider())
        self.assertEqual(verdict.action, "HANDOFF")
        self.assertEqual(self.scheduler.status("A"), state)

    def test_batch_limit_and_reader_budget_fail_closed(self):
        self.submit()
        self.reserve()
        provider = self.provider()
        with self.assertRaises(GuardError):
            self.supervisor.tick(("A", "A"), provider_reader=self.read(provider), now_unix=100)
        for kwargs in ({"max_observations": 0}, {"max_duration_ms": 0},
                       {"max_observations": True}, {"max_duration_ms": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(GuardError):
                self.supervisor.tick(("A",), provider_reader=self.read(provider),
                                     now_unix=100, **kwargs)
        with self.assertRaises(GuardError):
            self.supervisor.observe_once("A", provider_reader=self.read(provider),
                                         now_unix=100, deadline_monotonic=time.monotonic()-1)
        self.assertEqual(self.scheduler.ready()["polls_left"], 3)

    def test_two_processes_read_same_original_owner_resume(self):
        self.submit()
        self.reserve()
        wire = export_resume(self.scheduler, ("A",))
        child = r"""
import sys
from universal.continuity import ContinuityJournal
from universal.parallel_scheduler import OwnerScheduler
from universal.persistent_resume import validate_resume
with ContinuityJournal(sys.argv[1], clock=lambda: 100.0) as j:
    s = OwnerScheduler(j, enabled=True, run_budget=2, poll_budget=3,
                       check_current=lambda *_: True, check_applied=lambda *_: False)
    hint = validate_resume(s, sys.argv[2])
    print(hint.action + ':' + hint.task_ids[0])
"""
        for _ in range(2):
            p = subprocess.run([sys.executable, "-B", "-c", child, str(self.db_path), wire],
                               cwd=ROOT, capture_output=True, text=True, timeout=15)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), "OBSERVE_ONLY:A")
        self.assertEqual(self.scheduler.ready()["remaining_runs"], 1)
        self.assertTrue(self.journal.verify_chain())


    def test_provider_read_unavailable_403_404_429_never_authorizes_effect(self):
        self.submit()
        self.reserve()
        before = self.scheduler.status("A")
        for reason in ("RATE_LIMIT", "ACCESS_DENIED", "NOT_FOUND", "UNAVAILABLE"):
            def unavailable(*_):
                return UnavailableReadback(reason, observed_unix=int(self.now[0]))
            verdict = self.supervisor.observe_once(
                "A", provider_reader=unavailable, now_unix=int(self.now[0]))
            self.assertEqual((verdict.action, verdict.liveness), ("HANDOFF", "UNKNOWN"))
            self.assertFalse(verdict.execution_authorized)
            self.assertFalse(verdict.may_cancel)
            self.assertFalse(verdict.may_retry_write)
            self.assertEqual(self.scheduler.status("A"), before)
        self.assertEqual(self.scheduler.ready()["polls_left"], 3)
        self.assertEqual(self.journal.get("ps-job-A")["attempts"], 1)
        for changes in (("WRONG", 100), ("RATE_LIMIT", 0), ("RATE_LIMIT", True),
                        (False, 100)):
            with self.subTest(changes=changes), self.assertRaises(GuardError):
                UnavailableReadback(*changes)
        for bad_time in (101, 1):
            with self.subTest(observed_unix=bad_time), self.assertRaises(GuardError):
                self.supervisor.observe_once("A", provider_reader=lambda *_: UnavailableReadback(
                    "RATE_LIMIT", bad_time), now_unix=100 if bad_time == 101 else 4000)

    def test_worker_supplied_success_json_cannot_be_provider_reader(self):
        self.submit()
        self.reserve()
        before = self.scheduler.status("A")
        with self.assertRaises(GuardError):
            self.supervisor.observe_once(
                "A", provider_reader=lambda *_: {"worker_pass": True,
                                                   "provider_trusted": True},
                now_unix=100)
        self.assertEqual(before, self.scheduler.status("A"))
        self.assertEqual(self.scheduler.ready()["polls_left"], 3)

    def test_silent_queued_job_preserves_original_owner_reservation(self):
        self.submit()
        self.reserve()
        verdict = self.tick(self.provider(status="queued"))
        self.assertEqual(verdict.liveness, "SILENT_RUNNING")
        self.assertFalse(verdict.may_cancel)
        self.assertFalse(verdict.may_retry_write)
        self.assertEqual(self.scheduler.status("A")["state"], "IN_FLIGHT")

    def test_out_of_order_independent_runs_preserve_task_identity(self):
        self.submit("A")
        self.submit("B")
        self.reserve("A")
        self.reserve("B")
        samples = {
            "A": self.provider("read-a", "A", run_id=10001),
            "B": self.provider("read-b", "B", run_id=20002),
        }
        def reader(task_id, status):
            provider = samples[task_id]
            return provider, HealthReadback(provider.run_id, status["fence"], 100)
        results = self.supervisor.tick(("B", "A"), provider_reader=reader,
                                       now_unix=100, max_observations=2)
        self.assertEqual(tuple(r.task_id for r in results), ("B", "A"))
        self.assertTrue(all(r.liveness == "SILENT_RUNNING" for r in results))
        self.assertEqual(self.scheduler.status("A")["provider"]["run_id"], 10001)
        self.assertEqual(self.scheduler.status("B")["provider"]["run_id"], 20002)
        self.assertEqual(self.scheduler.ready()["polls_left"], 1)

    def test_batch_budget_reads_only_first_eligible_task(self):
        self.submit("A")
        self.submit("B")
        self.reserve("A")
        self.reserve("B")
        calls = []
        def reader(task_id, status):
            calls.append(task_id)
            provider = self.provider("read-" + task_id, task_id)
            return provider, None
        verdicts = self.supervisor.tick(("B", "A"), provider_reader=reader,
                                        now_unix=100, max_observations=1)
        self.assertEqual(tuple(v.task_id for v in verdicts), ("B",))
        self.assertEqual(calls, ["B"])
        self.assertIsNone(self.scheduler.status("A")["provider"])
        self.assertEqual(self.scheduler.ready()["polls_left"], 2)

    def test_false_heartbeat_run_fence_and_future_refused(self):
        self.submit()
        self.reserve()
        provider = self.provider()
        before = self.scheduler.status("A")
        for mismatch in (
            HealthReadback(77777, before["fence"], 100),
            HealthReadback(provider.run_id, before["fence"] + 1, 100),
            HealthReadback(provider.run_id, before["fence"], 101),
        ):
            with self.subTest(heartbeat=mismatch), self.assertRaises(GuardError):
                self.supervisor.observe_once(
                    "A", provider_reader=lambda *_: (provider, mismatch),
                    now_unix=100)
            self.assertEqual(self.scheduler.status("A"), before)
        self.assertEqual(self.scheduler.ready()["polls_left"], 3)

    def test_original_journal_replacement_cannot_import_resume(self):
        self.submit()
        wire = export_resume(self.scheduler, ("A",))
        old = self.journal.identity
        self._close()
        self.db_path.unlink()
        self.journal = ContinuityJournal(self.db_path, clock=lambda: self.now[0])
        self.scheduler = self.open_scheduler()
        self.assertNotEqual(old, self.journal.identity)
        with self.assertRaises(GuardError):
            validate_resume(self.scheduler, wire)
        self.assertEqual(self.scheduler.handoff()["tasks"], [])



if __name__ == "__main__":
    unittest.main()
