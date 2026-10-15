"""P16 deterministic mutation oracles, no untrusted process or external provider.

Seeded repetitions test invariants, not product certification. Fail-closed
conditions are checked against the actual versioned mission codecs and gates.
"""
import copy
import json
import random
import socket
import unittest
from unittest.mock import patch

from tests.test_mission_contracts import mission, receipt, event
from universal.mission_contracts import (
    canonical, decode_mission, decode_receipt, decode_event,
    fingerprint, MissionContractError,
)
from universal.mission_projects import profile_from_mission, preview_read_route, ReadCapability
from universal.mission_transitions import transition_eligible


class MissionAdversarialMatrixTests(unittest.TestCase):
    def test_seeded_mission_mutations_all_refuse(self):
        rng = random.Random(0xC0A600)
        for attempt in range(160):
            value = copy.deepcopy(mission())
            mode = attempt % 10
            if mode == 0:
                value['schema_version'] = rng.choice([0, 2, True])
            elif mode == 1:
                value['mission_id'] = '../project-B'
            elif mode == 2:
                value['idempotency_key'] = 'bad'
            elif mode == 3:
                value['contract']['allowed_actions'] = ['simulate', 'simulate']
            elif mode == 4:
                value['contract']['forbidden_actions'] = ['simulate']
            elif mode == 5:
                value['contract']['max_external_cost'] = float('inf')
            elif mode == 6:
                value['expires_unix'] = rng.choice([100, 150])
            elif mode == 7:
                value['project']['kind'] = rng.choice(['github\u202e', 'GITHUB', ''])
            elif mode == 8:
                value['contract']['dependencies'] = ['t-1']
            else:
                value['worker_approved'] = True
            with self.subTest(attempt=attempt, mode=mode), self.assertRaises((MissionContractError, ValueError)):
                decode_mission(json.dumps(value), now_unix=150)

    def test_seeded_event_replay_and_identity_mutations_refuse(self):
        before = event()
        later = dict(before, state='SILENT_RUNNING', event_seq=1, revision=2, observed_unix=126)
        self.assertTrue(transition_eligible(before, later))
        for attempt in range(160):
            rng = random.Random(attempt * 37 + 7)
            changed = dict(later)
            field = rng.choice(['mission_id', 'run_id', 'source_sha256', 'event_seq',
                                'revision', 'fence', 'observed_unix'])
            changed[field] = {
                'mission_id': 'B', 'run_id': 'other', 'source_sha256': 'b'*64,
                'event_seq': 0, 'revision': 1, 'fence': -1,
                'observed_unix': 124,
            }[field]
            with self.subTest(attempt=attempt, field=field):
                self.assertFalse(transition_eligible(before, changed))

    def test_unknown_receipt_worker_pass_not_equivalent_to_owner_validation(self):
        value = receipt()
        value['result_state'] = 'UNKNOWN_EFFECT'
        value['acceptance_status'] = 'PASS_SCOPED'
        with self.assertRaises(MissionContractError):
            decode_receipt(canonical(value))
        value = receipt()
        value['acceptance_status'] = 'PASS_SCOPED'
        self.assertEqual(decode_receipt(canonical(value)), value)  # parsed claim only
        self.assertNotIn('execution_authorized', value)

    def test_unicode_roundtrip_and_unpaired_surrogate_refusal(self):
        value = mission()
        value['contract']['objective'] = 'Étude ∆ 🛰️ fixture-only'
        self.assertEqual(decode_mission(canonical(value), now_unix=150), value)
        self.assertEqual(fingerprint(value), fingerprint(dict(reversed(list(value.items())))))
        value['contract']['objective'] = '\ud800'
        with self.assertRaises(MissionContractError):
            decode_mission(json.dumps(value), now_unix=150)

    def test_pure_router_never_opens_socket_on_fake_status(self):
        p = profile_from_mission(canonical(mission()), now_unix=150)
        c = ReadCapability(project_id=p.project_id, kind=p.kind, owner=p.owner,
                           base_version=p.base_version, source_sha256=p.source_sha256,
                           contract_sha256=p.contract_sha256, observed_unix=100, expires_unix=200,
                           api_declared=True, api_callable=True, api_tested=True,
                           api_connected=True, network_permission=True, read_permission=True,
                           budget_calls=1)
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            plan = preview_read_route(p, c, now_unix=150, planner_enabled=True)
        self.assertEqual(plan.route, 'FAKE_API')
        self.assertFalse(plan.execution_authorized)


if __name__ == '__main__':
    unittest.main()
