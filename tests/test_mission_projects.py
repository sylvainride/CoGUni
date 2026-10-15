"""P11/P12 cross-project binding, phase qualification and router default OFF."""
from dataclasses import replace
import unittest

from tests.test_mission_contracts import mission
from universal.mission_contracts import canonical
from universal.mission_projects import profile_from_mission, ReadCapability, preview_read_route

SHA = 'a'*64


class MissionProjectTests(unittest.TestCase):
    def profile(self, kind='local', project_id='fixture-A'):
        envelope = mission(project_id)
        envelope['project']['kind'] = kind
        return profile_from_mission(canonical(envelope), now_unix=150)

    def cap(self, profile, **changes):
        value = dict(project_id=profile.project_id, base_version=profile.base_version,
                     source_sha256=profile.source_sha256, observed_unix=100,
                     expires_unix=200, read_permission=True, network_permission=True,
                     budget_calls=1)
        value.update(changes)
        return ReadCapability(**value)

    def test_all_project_kinds_bind_exact_identity(self):
        profiles = [self.profile(k, f'fixture-{k}') for k in ('local', 'floot', 'github', 'other')]
        self.assertEqual(len({p.project_id for p in profiles}), 4)
        self.assertEqual(len({p.contract_sha256 for p in profiles}), 1)
        self.assertFalse(hasattr(profiles[0], 'execution_authorized'))

    def test_router_is_off_even_when_api_seems_available(self):
        p = self.profile()
        c = self.cap(p, api_declared=True, api_callable=True, api_tested=True, api_connected=True)
        self.assertEqual(preview_read_route(p, c, now_unix=150).route, 'DISABLED')
        proposed = preview_read_route(p, c, now_unix=150, planner_enabled=True)
        self.assertEqual(proposed.route, 'FAKE_API')
        self.assertFalse(proposed.execution_authorized)

    def test_requires_every_provider_observation_phase(self):
        p = self.profile()
        complete = self.cap(p, api_declared=True, api_callable=True, api_tested=True, api_connected=True)
        for field in ('api_declared', 'api_callable', 'api_tested', 'api_connected'):
            with self.subTest(field=field):
                invalid = replace(complete, **{field: False})
                self.assertEqual(preview_read_route(p, invalid, now_unix=150, planner_enabled=True).route, 'DENY')

    def test_offline_read_does_not_grant_external_effect(self):
        p = self.profile()
        c = self.cap(p, offline_possible=True, budget_calls=0, network_permission=False)
        result = preview_read_route(p, c, now_unix=150, planner_enabled=True)
        self.assertEqual(result.route, 'OFFLINE')
        self.assertFalse(result.execution_authorized)

    def test_cross_project_source_version_and_ttl_fail_closed(self):
        p = self.profile()
        c = self.cap(p, api_declared=True, api_callable=True, api_tested=True, api_connected=True)
        for override in ({'project_id': 'fixture-B'}, {'source_sha256': 'b'*64}, {'base_version': 'v2'}):
            self.assertEqual(preview_read_route(p, replace(c, **override), now_unix=150, planner_enabled=True).route, 'BLOCK')
        for now in (99, 200, True, -1):
            self.assertEqual(preview_read_route(p, c, now_unix=now, planner_enabled=True).route, 'BLOCK')

    def test_private_secret_or_missing_permission_denied(self):
        p = self.profile()
        c = self.cap(p, offline_possible=True)
        self.assertEqual(preview_read_route(p, replace(c, contains_secret=True), now_unix=150, planner_enabled=True).route, 'DENY')
        self.assertEqual(preview_read_route(p, replace(c, read_permission=False), now_unix=150, planner_enabled=True).route, 'DENY')
        private = replace(p, privacy='PRIVATE_OWNER')
        self.assertEqual(preview_read_route(private, c, now_unix=150, planner_enabled=True).route, 'DENY')

    def test_reject_truthy_flags_time_limit_and_spoof(self):
        p = self.profile()
        c = self.cap(p)
        for changes in ({'api_tested': 1}, {'read_permission': 'yes'}, {'budget_calls': True},
                        {'expires_unix': 9999}, {'observed_unix': -1}, {'source_sha256': 'NOT_SHA'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(c, **changes)
        self.assertEqual(preview_read_route(p, c, now_unix=150, planner_enabled='True').route, 'BLOCK')


if __name__ == '__main__':
    unittest.main()
