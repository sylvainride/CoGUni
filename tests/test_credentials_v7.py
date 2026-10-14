"""Actual SQLite credentials: owner rotation, local replay and process races.

Temporary databases only; no network service, model or external side effect.
"""
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from universal.core import GuardError, Intent, Runtime, digest
from universal.credentials import assert_run_credentials_active, rotate_run_token


def _race_actor(path, barrier, queue, operation, claim):
    with Runtime(path, clock=lambda: 1000.0) as runtime:
        barrier.wait(timeout=10)
        try:
            if operation == "rotate":
                rotation = rotate_run_token(runtime, claim["run_id"], claim["token"], expected_fence=claim["fence"])
                queue.put((operation, "ROTATED", rotation.token))
            elif operation == "revoke":
                runtime.revoke(claim["run_id"])
                queue.put((operation, "REVOKED", None))
            elif operation == "write":
                intent = Intent(claim["run_id"], "artifact.write", "output", 1, "write-race", claim["fence"], {"content": "HELLO"})
                runtime.execute(intent, claim["token"])
                queue.put((operation, "COMMITTED", None))
            else:
                raise AssertionError("unknown fixture operation")
        except GuardError as error:
            queue.put((operation, "DENIED", error.reason))


def _crash_rotation(path, claim, after_commit):
    with Runtime(path, clock=lambda: 1000.0) as runtime:
        if not after_commit:
            original_event = runtime._event

            def crash_at_event(actor, action, target, outcome, metadata=None):
                if action == "credential.rotate":
                    os._exit(71)
                return original_event(actor, action, target, outcome, metadata)

            runtime._event = crash_at_event
        rotate_run_token(runtime, claim["run_id"], claim["token"], expected_fence=claim["fence"])
        os._exit(72)


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cup_credentials_v7_")
        self.path = Path(self.temp.name) / "runtime.sqlite"
        self.now = [1000.0]
        self.runtime = Runtime(self.path, clock=lambda: self.now[0])
        self.runtime.put_resource("source", "hello")
        self.runtime.put_resource("output", "")
        self.runtime.add_task("A", "source", "output", "uppercase", digest("HELLO"))
        self.claim = self.runtime.claim("controller-test", ttl=30)

    def tearDown(self):
        self.runtime.close()
        self.temp.cleanup()

    def rotate(self, token=None, fence=None):
        return rotate_run_token(self.runtime, self.claim["run_id"], self.claim["token"] if token is None else token,
                                expected_fence=self.claim["fence"] if fence is None else fence)

    def write(self, token, key="write-test"):
        return self.runtime.execute(Intent(self.claim["run_id"], "artifact.write", "output", 1, key,
                                           self.claim["fence"], {"content": "HELLO"}), token)

    def assert_active(self, token):
        return assert_run_credentials_active(self.runtime, self.claim["run_id"], token, expected_fence=self.claim["fence"])

    def stable_rights(self):
        grants = [dict(row) for row in self.runtime.db.execute("SELECT * FROM grants ORDER BY resource,tool")]
        leases = [dict(row) for row in self.runtime.db.execute("SELECT * FROM leases ORDER BY resource")]
        return grants, leases

    def event_count(self):
        return self.runtime.db.execute("SELECT count(*) FROM events WHERE action='credential.rotate'").fetchone()[0]

    def run_race(self, operations):
        context = multiprocessing.get_context("spawn")
        barrier, queue = context.Barrier(len(operations)), context.Queue()
        processes = [context.Process(target=_race_actor, args=(str(self.path), barrier, queue, operation, self.claim))
                     for operation in operations]
        try:
            for process in processes:
                process.start()
            results = [queue.get(timeout=20) for _ in processes]
            for process in processes:
                process.join(20)
                self.assertEqual(process.exitcode, 0)
            return results
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            queue.close()
            queue.join_thread()

    def run_crash(self, after_commit):
        context = multiprocessing.get_context("spawn")
        child = context.Process(target=_crash_rotation, args=(str(self.path), self.claim, after_commit))
        try:
            child.start()
            child.join(15)
            self.assertEqual(child.exitcode, 72 if after_commit else 71)
        finally:
            if child.is_alive():
                child.terminate()
                child.join(5)

    def test_rotation_changes_only_token_hash_and_preserves_rights(self):
        before = dict(self.runtime.db.execute("SELECT * FROM runs").fetchone())
        rights = self.stable_rights()
        rotation = self.rotate()
        after = dict(self.runtime.db.execute("SELECT * FROM runs").fetchone())
        self.assertNotEqual(rotation.token, self.claim["token"])
        self.assertEqual(after.pop("token_hash"), digest(rotation.token))
        before.pop("token_hash")
        self.assertEqual(after, before)
        self.assertEqual(self.stable_rights(), rights)
        self.assertEqual(rotation.fence, self.claim["fence"])
        self.assertEqual(rotation.expires, 1030)
        self.assertEqual(self.event_count(), 1)
        self.assertTrue(self.runtime.check_journal())

    def test_old_token_is_refused_and_replacement_can_write(self):
        rotation = self.rotate()
        with self.assertRaisesRegex(GuardError, "credential"):
            self.write(self.claim["token"])
        self.assertEqual(self.runtime.resource("output")["version"], 1)
        self.write(rotation.token)
        self.assertEqual(self.runtime.resource("output")["content"], "HELLO")
        self.assertEqual(self.runtime.resource("output")["version"], 2)

    def test_old_token_refused_before_committed_receipt_replay(self):
        receipt = self.write(self.claim["token"])
        rotation = self.rotate()
        with self.assertRaisesRegex(GuardError, "credential"):
            self.write(self.claim["token"])
        replay = self.write(rotation.token)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["version"], receipt["version"])
        self.assertEqual(self.runtime.resource("output")["version"], 2)
        self.assertEqual(self.runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)

    def test_revocation_before_rotation_never_resurrects_grants(self):
        self.runtime.revoke(self.claim["run_id"])
        rights = self.stable_rights()
        with self.assertRaisesRegex(GuardError, "revoked"):
            self.rotate()
        self.assertEqual(self.stable_rights(), rights)
        self.assertEqual(self.event_count(), 0)
        with self.assertRaises(GuardError):
            self.write(self.claim["token"])

    def test_revocation_after_rotation_refuses_replacement_and_old_token(self):
        rotation = self.rotate()
        self.runtime.revoke(self.claim["run_id"])
        for token in (self.claim["token"], rotation.token):
            with self.assertRaises(GuardError):
                self.write(token)
            with self.assertRaises(GuardError):
                self.assert_active(token)
        with self.assertRaises(GuardError):
            self.rotate(rotation.token)
        self.assertEqual(self.runtime.resource("output")["version"], 1)

    def test_expired_credentials_cannot_be_rotated_or_extended(self):
        rights = self.stable_rights()
        self.now[0] = 1030.0
        with self.assertRaisesRegex(GuardError, "expired"):
            self.rotate()
        self.assertEqual(self.stable_rights(), rights)
        self.assertEqual(self.event_count(), 0)

    def test_stale_fence_and_wrong_token_fail_without_rotation(self):
        for token, fence in (("wrong-token", self.claim["fence"]), (self.claim["token"], self.claim["fence"] + 1)):
            with self.assertRaises(GuardError):
                self.rotate(token, fence)
        self.assertEqual(self.event_count(), 0)
        self.assert_active(self.claim["token"])

    def test_invalid_arguments_fail_closed(self):
        for token in (None, "", "z" * 257, "\ud800", b"bytes"):
            with self.assertRaises(GuardError):
                rotate_run_token(self.runtime, self.claim["run_id"], token, expected_fence=self.claim["fence"])
        for fence in (True, 0, -1, "1", 1.0):
            with self.assertRaises(GuardError):
                rotate_run_token(self.runtime, self.claim["run_id"], self.claim["token"], expected_fence=fence)
        self.assertEqual(self.event_count(), 0)

    def test_repeated_rotation_requires_current_secret(self):
        first = self.rotate()
        with self.assertRaisesRegex(GuardError, "credential"):
            self.rotate()
        second = self.rotate(first.token)
        with self.assertRaises(GuardError):
            self.assert_active(first.token)
        self.assert_active(second.token)
        self.assertEqual(self.event_count(), 2)

    def test_generator_collision_does_not_replace_current_credential(self):
        with patch("universal.credentials.secrets.token_urlsafe", return_value=self.claim["token"]):
            with self.assertRaisesRegex(GuardError, "collision"):
                self.rotate()
        self.assert_active(self.claim["token"])
        self.assertEqual(self.event_count(), 0)

    def test_collision_with_other_run_is_refused(self):
        self.runtime.put_resource("output2", "")
        self.runtime.add_task("B", "source", "output2", "uppercase", digest("HELLO"))
        other = self.runtime.claim("other-controller")
        with patch("universal.credentials.secrets.token_urlsafe", return_value=other["token"]):
            with self.assertRaisesRegex(GuardError, "collision"):
                self.rotate()
        self.assert_active(self.claim["token"])
        self.assertEqual(self.event_count(), 0)

    def test_terminal_run_cannot_be_rotated(self):
        self.write(self.claim["token"])
        self.runtime.verify("A", "credentials-local")
        with self.assertRaisesRegex(GuardError, "not active"):
            self.rotate()
        self.assertEqual(self.event_count(), 0)

    def test_repr_and_audit_contain_no_credential_or_hash(self):
        rotation = self.rotate()
        self.assertNotIn(rotation.token, repr(rotation))
        journal = "\n".join(str(tuple(row)) for row in self.runtime.db.execute("SELECT * FROM events"))
        for secret in (self.claim["token"], rotation.token, digest(self.claim["token"]), digest(rotation.token)):
            self.assertNotIn(secret, journal)
        event = self.runtime.db.execute("SELECT metadata FROM events WHERE action='credential.rotate'").fetchone()
        self.assertEqual(event["metadata"], "{}")

    def test_backup_preserves_rotated_credential_not_original(self):
        rotation = self.rotate()
        backup = Path(self.temp.name) / "backup.sqlite"
        self.runtime.backup(backup)
        with Runtime(backup, clock=lambda: 1000.0) as restored:
            with self.assertRaises(GuardError):
                assert_run_credentials_active(restored, self.claim["run_id"], self.claim["token"], expected_fence=self.claim["fence"])
            assert_run_credentials_active(restored, self.claim["run_id"], rotation.token, expected_fence=self.claim["fence"])
            self.assertTrue(restored.check_journal())

    def test_recovery_creates_new_run_and_fence_without_reviving_rotated_run(self):
        rotation = self.rotate()
        self.now[0] = 1031
        self.assertEqual(self.runtime.recover(), 1)
        self.runtime.resume("A")
        replacement_run = self.runtime.claim("new-controller")
        self.assertNotEqual(replacement_run["run_id"], self.claim["run_id"])
        self.assertGreater(replacement_run["fence"], self.claim["fence"])
        for token in (self.claim["token"], rotation.token):
            with self.assertRaises(GuardError):
                self.write(token)
            with self.assertRaises(GuardError):
                self.rotate(token)
        result = self.runtime.execute(Intent(replacement_run["run_id"], "artifact.write", "output", 1, "new-run-write",
                                             replacement_run["fence"], {"content": "HELLO"}), replacement_run["token"])
        self.assertEqual(result["version"], 2)

    def test_process_rotation_and_old_token_write_are_serialized(self):
        results = self.run_race(["rotate", "write"])
        rotation = next(result for result in results if result[0] == "rotate")
        write = next(result for result in results if result[0] == "write")
        self.assertEqual(rotation[1], "ROTATED")
        self.assertIn(write[1], {"COMMITTED", "DENIED"})
        self.assertEqual(self.runtime.resource("output")["version"], 2 if write[1] == "COMMITTED" else 1)
        with self.assertRaises(GuardError):
            self.write(self.claim["token"], key="after-race")
        self.assert_active(rotation[2])
        self.assertEqual(self.event_count(), 1)
        self.assertTrue(self.runtime.check_journal())

    def test_process_rotation_and_revocation_never_resurrect_grants(self):
        results = self.run_race(["rotate", "revoke"])
        self.assertEqual(next(result[1] for result in results if result[0] == "revoke"), "REVOKED")
        rotation = next(result for result in results if result[0] == "rotate")
        self.assertIn(rotation[1], {"ROTATED", "DENIED"})
        self.assertEqual(self.runtime.db.execute("SELECT count(*) FROM grants WHERE revoked=0").fetchone()[0], 0)
        tokens = [self.claim["token"]] + ([rotation[2]] if rotation[1] == "ROTATED" else [])
        for token in tokens:
            with self.assertRaises(GuardError):
                self.write(token)
            with self.assertRaises(GuardError):
                self.rotate(token)
        self.assertEqual(self.runtime.resource("output")["version"], 1)
        self.assertTrue(self.runtime.check_journal())

    def test_two_process_rotations_using_same_old_token_have_one_winner(self):
        results = self.run_race(["rotate", "rotate"])
        self.assertEqual(sorted(result[1] for result in results), ["DENIED", "ROTATED"])
        winner = next(result[2] for result in results if result[1] == "ROTATED")
        self.assert_active(winner)
        with self.assertRaises(GuardError):
            self.assert_active(self.claim["token"])
        self.assertEqual(self.event_count(), 1)

    def test_process_crash_before_commit_rolls_back_rotation(self):
        self.run_crash(after_commit=False)
        self.assert_active(self.claim["token"])
        self.assertEqual(self.event_count(), 0)
        self.assertTrue(self.runtime.check_journal())

    def test_process_crash_after_commit_old_token_stays_invalid(self):
        self.run_crash(after_commit=True)
        with self.assertRaises(GuardError):
            self.assert_active(self.claim["token"])
        self.assertEqual(self.event_count(), 1)
        # The replacement secret was intentionally lost with the controller.
        # Recover by ending the old run and issuing a new run; never resurrect.
        self.now[0] = 1031
        self.assertEqual(self.runtime.recover(), 1)
        self.runtime.resume("A")
        next_claim = self.runtime.claim("recovered-controller")
        assert_run_credentials_active(self.runtime, next_claim["run_id"], next_claim["token"], expected_fence=next_claim["fence"])
        self.assertNotEqual(next_claim["run_id"], self.claim["run_id"])
        self.assertEqual(self.runtime.resource("output")["version"], 1)
        self.assertTrue(self.runtime.check_journal())
