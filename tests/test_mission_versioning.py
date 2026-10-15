"""Synthetic portable snapshot replay and corruption/replacement refusals."""
import copy
import json
import unittest
from tests.test_mission_contracts import mission, receipt, event
from universal.mission_contracts import canonical, MissionContractError
from universal.mission_versioning import export_offline_bundle, import_offline_bundle, MAX_BUNDLE_BYTES


class MissionVersioningTests(unittest.TestCase):
    def setUp(self):
        self.items = [{'kind': 'mission', 'value': mission()},
                      {'kind': 'receipt', 'value': receipt()},
                      {'kind': 'event', 'value': event()}]

    def out(self, items=None):
        return export_offline_bundle(self.items if items is None else items, now_unix=150)

    def test_roundtrip_preserves_validated_values_and_is_deterministic(self):
        wire = self.out()
        self.assertEqual(self.out(), wire)
        self.assertEqual(import_offline_bundle(wire, now_unix=150), self.items)

    def test_existing_mission_cannot_be_overwritten(self):
        wire = self.out()
        for existing in ({'m-1'}, ('m-1',), ['m-1']):
            with self.assertRaises(MissionContractError):
                import_offline_bundle(wire, now_unix=150, existing_mission_ids=existing)

    def test_digest_corruption_and_rogue_authority_rejected(self):
        bundle = json.loads(self.out())
        for change in (lambda b: b['records'][0]['value'].update(mission_id='forged'),
                       lambda b: b.update(authority='TRUSTED_OWNER'),
                       lambda b: b.update(schema_version=0),
                       lambda b: b.update(format='legacy'),
                       lambda b: b.update(secret='token')):
            modified = copy.deepcopy(bundle)
            change(modified)
            with self.assertRaises(MissionContractError):
                import_offline_bundle(canonical(modified), now_unix=150)

    def test_unsupported_legacy_and_json_spoof_refused(self):
        for raw in (b'{}', b'{"schema_version":1,"schema_version":1}', b'[]',
                    b'\xff', b' '*(MAX_BUNDLE_BYTES + 1)):
            with self.assertRaises(MissionContractError):
                import_offline_bundle(raw, now_unix=150)

    def test_cross_project_bundle_and_source_splice_refused(self):
        crossed = copy.deepcopy(self.items)
        crossed[1]['value']['project_id'] = 'fixture-B'
        with self.assertRaises(MissionContractError):
            self.out(crossed)
        crossed = copy.deepcopy(self.items)
        crossed[2]['value']['source_sha256'] = 'b'*64
        with self.assertRaises(MissionContractError):
            self.out(crossed)

    def test_duplicate_records_and_invalid_version_refused(self):
        with self.assertRaises(MissionContractError):
            self.out(self.items + [self.items[1]])
        with self.assertRaises(MissionContractError):
            self.out(self.items + [self.items[2]])
        old = copy.deepcopy(self.items)
        old[0]['value']['schema_version'] = 2
        with self.assertRaises(MissionContractError):
            self.out(old)

    def test_unpaired_unicode_scalar_rejected_as_contract_error(self):
        import_bad = json.loads(self.out())
        import_bad['records'][0]['value']['contract']['objective'] = '\ud800'
        with self.assertRaises(MissionContractError):
            import_offline_bundle(json.dumps(import_bad), now_unix=150)
        export_bad = copy.deepcopy(self.items)
        export_bad[0]['value']['contract']['objective'] = '\ud800'
        with self.assertRaises(MissionContractError):
            self.out(export_bad)

    def test_expiry_fails_on_import_even_with_intact_digest(self):
        wire = self.out()
        with self.assertRaises(MissionContractError):
            import_offline_bundle(wire, now_unix=300)


if __name__ == '__main__':
    unittest.main()
