"""Canary suppression and false-positive PASS refusals in offline logs."""
import json
import unittest
from universal.mission_contracts import canonical, MissionContractError
from universal.mission_liveness import Observation
from universal.mission_redaction import redacted_receipt, redacted_liveness
from tests.test_mission_contracts import receipt

CANARY = 'SYNTHETIC_SECRET_MARKER_DO_NOT_PUBLISH'


class RedactionTests(unittest.TestCase):
    def test_claimed_pass_and_sensitive_references_are_not_published(self):
        original = receipt()
        original['run_id'] = 'run-' + CANARY
        original['proof_refs'] = [CANARY]
        original['error_code'] = CANARY
        original['target_version_after'] = CANARY
        original['acceptance_status'] = 'PASS_SCOPED'
        published = redacted_receipt(canonical(original))
        serialized = json.dumps(published)
        self.assertNotIn(CANARY, serialized)
        self.assertNotIn('PASS_SCOPED', serialized)
        self.assertEqual(published['verification_state'], 'UNVERIFIED_INPUT')
        self.assertFalse(published['publication_authorized'])

    def test_raw_ids_and_status_only_projection(self):
        ob = Observation(now_unix=150, run_id='run-' + CANARY, fence=1,
                         provider_trusted=True, provider_run_id='provider-' + CANARY,
                         provider_fence=1, provider_state='RUNNING',
                         supervisor_trusted=True, supervisor_run_id='run-' + CANARY,
                         supervisor_fence=1, heartbeat_unix=150, lease_until_unix=200)
        result = redacted_liveness(ob)
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertEqual(result['reported_liveness'], 'SUSPECT_RECOVERY')
        self.assertFalse(result['effect_retry_authorized'])

    def test_unknown_effect_remains_unretryable(self):
        ob = Observation(now_unix=150, run_id='safe-run', fence=1, effect_ack_unknown=True)
        result = redacted_liveness(ob)
        self.assertEqual(result['reported_liveness'], 'UNKNOWN_EFFECT')
        self.assertFalse(result['effect_retry_authorized'])

    def test_bad_receipt_and_forged_observation_denied(self):
        with self.assertRaises(MissionContractError):
            redacted_receipt(b'{"approved":true}')
        with self.assertRaises(MissionContractError):
            redacted_liveness({'run_id': 'fake'})


if __name__ == '__main__':
    unittest.main()
