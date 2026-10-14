"""Offline positive and fail-closed tests. No network, shell or credentials."""
import hashlib
import unittest

from universal.chat_readonly_mission import run_offline_hash


class ReadOnlyMissionTests(unittest.TestCase):
    SHA = "08cd3916cf2e76e0814e4ba62ed57a9c74df39be"

    def setUp(self):
        self.mission = {"mission_version": 1,
                        "repository_full_name": "sylvainride/CoGUni",
                        "repository_id": "1418009675", "owner_id": "265171248",
                        "actor_id": "265171248", "source_sha": self.SHA,
                        "nonce": "a" * 32, "expires_unix": 1005,
                        "kind": "READ_ONLY_HASH", "payload": "synthetic:pass1"}
        self.trust = dict(trusted_repo_id="1418009675", trusted_owner_id="265171248",
                          trusted_actor_id="265171248", trusted_source_sha=self.SHA,
                          now_unix=1000)

    def check_rejected(self, **changes):
        mission = dict(self.mission, **changes)
        with self.assertRaises(ValueError):
            run_offline_hash(mission, **self.trust)

    def test_synthetic_hash_is_deterministic(self):
        result = run_offline_hash(self.mission, **self.trust)
        self.assertEqual(result["payload_sha256"], hashlib.sha256(b"synthetic:pass1").hexdigest())
        self.assertEqual(result["source_sha"], self.SHA)
        self.assertEqual(result["scope"], "PURE_LOCAL_TEST_ONLY_NOT_AUTHORIZED_DISPATCH")

    def test_denies_wrong_repository_and_actor(self):
        self.check_rejected(repository_id="999")
        self.check_rejected(repository_full_name="somebody/CoGUni")
        self.check_rejected(actor_id="other")
        self.check_rejected(owner_id="other")

    def test_denies_wrong_sha_and_nonce(self):
        self.check_rejected(source_sha="b" * 40)
        self.check_rejected(nonce="abc")
        self.check_rejected(nonce="A" * 32)

    def test_denies_expiry_and_invalid_time(self):
        self.check_rejected(expires_unix=1000)
        self.check_rejected(expires_unix=1901)
        self.check_rejected(expires_unix=True)

    def test_denies_command_and_extra_fields(self):
        self.check_rejected(kind="RUN_SHELL")
        self.check_rejected(payload="synthetic:hi;rm -rf /")
        self.check_rejected(command="echo unsafe")
        self.check_rejected(mission_version=True)

    def test_denies_untrusted_controller_source(self):
        trust = dict(self.trust, trusted_source_sha="b" * 40)
        with self.assertRaises(ValueError):
            run_offline_hash(self.mission, **trust)
        with self.assertRaises(ValueError):
            run_offline_hash(self.mission, **dict(self.trust, trusted_actor_id="other"))


if __name__ == "__main__":
    unittest.main()
