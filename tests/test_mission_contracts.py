"""Synthetic-only mission/receipt/event codec tests; no external authority."""
import copy
import json
import unittest

from universal.mission_contracts import (
    MissionContractError, canonical, decode_event, decode_mission, decode_receipt, fingerprint,
    MAX_WIRE_BYTES,
)

SHA = 'a' * 64


def mission(project='fixture-A'):
    return {
        'schema_version': 1, 'mission_id': 'm-1', 'idempotency_key': 'fixture-key-0001',
        'project': {'kind': 'local', 'id': project, 'owner': 'test-owner', 'base_version': 'v1', 'source_of_truth': 'fixture-only'},
        'contract': {'task_id': 't-1', 'objective': 'offline canonical round trip',
                     'allowed_actions': ['simulate'], 'forbidden_actions': ['publish'],
                     'criteria': ['exact output'], 'dependencies': [], 'max_attempts': 2,
                     'max_duration_seconds': 10, 'max_external_cost': 0, 'artifact_policy': 'public_synthetic'},
        'created_unix': 100, 'expires_unix': 200, 'source_sha256': SHA, 'privacy': 'PUBLIC_SYNTHETIC',
    }


def receipt():
    return {'schema_version': 1, 'mission_id': 'm-1', 'run_id': 'run-1', 'project_id': 'fixture-A',
            'source_sha256': SHA, 'result_state': 'RESULT_READY', 'artifact_sha256': 'b' * 64,
            'integrity_verified': False, 'application_status': 'NOT_APPLIED',
            'acceptance_status': 'NOT_TESTED'}


def event():
    return {'schema_version': 1, 'mission_id': 'm-1', 'run_id': 'run-1', 'source_sha256': SHA,
            'event_seq': 0, 'state': 'RUNNING', 'observed_unix': 125,
            'proof_kind': 'UNTRUSTED_WORKER', 'fence': 1, 'revision': 1}


class MissionContractsTests(unittest.TestCase):
    def test_two_independent_synthetic_projects_roundtrip(self):
        a, b = mission('fixture-A'), mission('fixture-B')
        self.assertEqual(decode_mission(canonical(a), now_unix=150), a)
        self.assertEqual(decode_mission(canonical(b), now_unix=150), b)
        self.assertNotEqual(fingerprint(a), fingerprint(b))

    def test_canonical_equivalent_key_order(self):
        obj = mission()
        self.assertEqual(fingerprint(obj), fingerprint(dict(reversed(list(obj.items())))))

    def test_reject_expired_future_and_unbounded(self):
        for now in (99, 200, True, -1):
            with self.subTest(now=now), self.assertRaises(MissionContractError):
                decode_mission(canonical(mission()), now_unix=now)
        bad = mission(); bad['expires_unix'] = 100 + 32 * 86400
        with self.assertRaises(MissionContractError):
            decode_mission(canonical(bad), now_unix=150)

    def test_extra_duplicate_nonfinite_invalid_utf8_and_scalar(self):
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{}', b'[]', b'{"unexpected":NaN}', b'\xff', b'"scalar"',
                    b' ' * (MAX_WIRE_BYTES + 1), b'{"x":1e999}'):
            with self.subTest(raw=raw[:24]), self.assertRaises(MissionContractError):
                decode_mission(raw, now_unix=150)

    def test_strict_nested_fields_and_value_types(self):
        cases = [
            ('extra root', lambda m: m.update(authorized=True)),
            ('extra project', lambda m: m['project'].update(access_token='secret')),
            ('extra contract', lambda m: m['contract'].update(execute=True)),
            ('bool version', lambda m: m.update(schema_version=True)),
            ('bad sha', lambda m: m.update(source_sha256='A' * 64)),
            ('bad key', lambda m: m.update(idempotency_key='bad')),
            ('bool attempts', lambda m: m['contract'].update(max_attempts=True)),
            ('duplicate action', lambda m: m['contract'].update(allowed_actions=['simulate', 'simulate'])),
            ('conflicting action', lambda m: m['contract'].update(forbidden_actions=['simulate'])),
            ('NaN cost', lambda m: m['contract'].update(max_external_cost=float('nan'))),
            ('negative cost', lambda m: m['contract'].update(max_external_cost=-1)),
            ('surrogate', lambda m: m['contract'].update(objective='\ud800')),
            ('self dependency', lambda m: m['contract'].update(dependencies=['t-1'])),
            ('private-public artifact', lambda m: m.update(privacy='PRIVATE_OWNER')),
        ]
        for title, edit in cases:
            with self.subTest(title=title):
                obj = mission(); edit(obj)
                with self.assertRaises((MissionContractError, UnicodeError, ValueError)):
                    decode_mission(json.dumps(obj, ensure_ascii=True), now_unix=150)

    def test_receipt_roundtrip_and_refusals(self):
        value = receipt()
        self.assertEqual(decode_receipt(canonical(value)), value)
        for patch in ({'integrity_verified': True, 'artifact_sha256': None},
                      {'result_state': 'UNKNOWN_EFFECT', 'acceptance_status': 'PASS_SCOPED'},
                      {'application_status': 'UNAUTHORIZED'}, {'approved': True},
                      {'schema_version': True}):
            with self.subTest(patch=patch), self.assertRaises(MissionContractError):
                decode_receipt(canonical(dict(value, **patch)))

    def test_events_handoff_is_not_completion(self):
        value = event()
        self.assertEqual(decode_event(canonical(value)), value)
        handoff = dict(value, state='CHAT_HANDOFF')
        self.assertEqual(decode_event(canonical(handoff))['state'], 'CHAT_HANDOFF')
        for patch in ({'state': 'ACCEPTED'}, {'state': 'APPLIED'}, {'revision': True},
                      {'proof_kind': 'FAKE_OWNER'}, {'event_digest': '0' * 64}):
            with self.subTest(patch=patch), self.assertRaises(MissionContractError):
                decode_event(canonical(dict(value, **patch)))
        value['event_digest'] = fingerprint(value)
        self.assertEqual(decode_event(canonical(value)), value)


if __name__ == '__main__':
    unittest.main()
