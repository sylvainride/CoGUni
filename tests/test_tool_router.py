"""Forty fixed route oracles count as one unittest, plus refusal/fault checks."""
from dataclasses import replace
import socket
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from universal.tool_router import Budget, BrowserSession, FakeReadOnlyAPI, Request, select


BASE = Request('READ', False, False, False, True, True, False, False, 1)
ORACLES = (
    ({'offline_possible': True}, 'OFFLINE'),
    ({'offline_possible': False, 'api_available': True}, 'FAKE_API'),
    ({'offline_possible': False, 'api_available': False, 'cli_available': True}, 'FAKE_CLI'),
    ({'offline_possible': False, 'api_available': False, 'cli_available': False,
      'browser_available': True, 'browser_permission': True}, 'SIMULATED_BROWSER'),
    ({'offline_possible': False, 'network_permission': False}, 'DENY'),
    ({'offline_possible': False, 'budget_calls': 0}, 'DENY'),
    ({'offline_possible': False, 'api_available': False, 'cli_available': False,
      'browser_available': True, 'browser_permission': False}, 'DENY'),
    ({'contains_secret': True}, 'DENY'), ({'task': 'WRITE'}, 'DENY'), ({'task': 'SHELL'}, 'DENY'),
)


class ToolRouterTests(unittest.TestCase):
    def test_40_fixed_decision_oracles(self):
        count = 0
        for index, (changes, expected) in enumerate(ORACLES):
            for calls in (1, 2, 3, 4):
                req = replace(BASE, **{'budget_calls': calls, **changes})
                with self.subTest(index=index, calls=calls):
                    decision = select(req, enabled=True)
                    self.assertEqual(decision.route, expected)
                    self.assertFalse(decision.execution_authorized)
                count += 1
        self.assertEqual(count, 40)

    def test_default_off_and_enabled_plan_never_authorize_an_effect(self):
        self.assertEqual(select(BASE).route, 'DISABLED')
        self.assertFalse(select(BASE, enabled=True).execution_authorized)
        self.assertEqual(select(replace(BASE, task='WRITE')).route, 'DENY')
        with self.assertRaises(ValueError):
            select(BASE, enabled='yes')

    def test_truthy_permission_values_and_noninteger_budgets_fail_closed(self):
        for name in ('api_available', 'network_permission', 'browser_permission', 'contains_secret', 'offline_possible'):
            for value in ('yes', 1, [], None):
                with self.subTest(name=name, value=value):
                    self.assertEqual(select(replace(BASE, **{name: value}), enabled=True).route, 'DENY')
        for value in (True, -1, 1.0, '1', 10**10):
            self.assertEqual(select(replace(BASE, budget_calls=value), enabled=True).route, 'DENY')
        self.assertEqual(select(replace(BASE, task='X' * 1000), enabled=True).route, 'DENY')
        with self.assertRaises(ValueError):
            select(None)

    def test_simulated_budget_charge_has_no_refund_or_negative_charge(self):
        initial = Budget(1, 10, 5, 0)
        self.assertEqual(initial.charge(calls=1).calls, 0)
        self.assertEqual(initial.calls, 1)
        for charge in ({'calls': 2}, {'millis': 11}, {'cpu_ms': 6}, {'retries': 1}, {'calls': -1}, {'calls': True}):
            with self.subTest(charge=charge), self.assertRaises(ValueError):
                initial.charge(**charge)
        for value in (True, -1, 10**10):
            with self.assertRaises(ValueError):
                Budget(value, 1, 1, 1)

    def test_fake_api_typed_failures_never_retry_automatically(self):
        for fault, status in [('OK', 200), ('UNAUTHENTICATED', 401), ('FORBIDDEN', 403),
                              ('RATELIMIT', 429), ('TIMEOUT', 504), ('UNKNOWN', 503)]:
            with self.subTest(fault=fault):
                api = FakeReadOnlyAPI(fault=fault)
                response = api.read('synthetic:x')
                self.assertEqual(response.status, status)
                self.assertEqual(response.uncertainty, fault in {'TIMEOUT', 'UNKNOWN'})
                self.assertFalse(response.retry_allowed)
                self.assertEqual(api.calls, 1)
                with self.assertRaises(ValueError):
                    api.read('synthetic:x')
                self.assertEqual(api.calls, 1)

    def test_fake_api_scope_and_input_refuse_without_consuming_call_budget(self):
        api = FakeReadOnlyAPI(scopes=set())
        self.assertEqual(api.read('synthetic:x').status, 403)
        self.assertEqual(api.calls, 0)
        api = FakeReadOnlyAPI()
        for value in ('../etc', 'synthetic:../x', 'synthetic:' + 'x' * 65, b'synthetic:x'):
            self.assertEqual(api.read(value).status, 400)
        self.assertEqual(api.calls, 0)
        with self.assertRaises(ValueError):
            FakeReadOnlyAPI(scopes={'write'})

    def test_browser_closed_releases_simulated_reservation(self):
        session = BrowserSession()
        self.assertFalse(session.reserved)
        session.move('ACTIVE')
        self.assertTrue(session.reserved)
        session.move('API_VERIFIED')
        session.move('CLOSED')
        self.assertFalse(session.reserved)
        self.assertFalse(session.secret_observed)
        with self.assertRaises(ValueError):
            session.move('ACTIVE')

    def test_browser_failure_also_releases_reservation(self):
        for history in ((), ('ACTIVE',), ('ACTIVE', 'API_VERIFIED')):
            session = BrowserSession()
            for state in history:
                session.move(state)
            session.move('FAILED')
            self.assertFalse(session.reserved)
            with self.assertRaises(ValueError):
                session.move('ACTIVE')

    def test_browser_secret_or_illegal_transition_cannot_allocate(self):
        session = BrowserSession()
        for target, key in [('API_VERIFIED', None), ('ACTIVE', 'synthetic-key')]:
            with self.assertRaises(ValueError):
                session.move(target, key=key)
            self.assertEqual(session.state, 'NEEDED')
            self.assertFalse(session.reserved)

    def test_planner_and_fake_sessions_never_use_network(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            self.assertEqual(select(replace(BASE, offline_possible=False, api_available=True), enabled=True).route, 'FAKE_API')
            self.assertEqual(FakeReadOnlyAPI().read('synthetic:x').status, 200)
            session = BrowserSession()
            session.move('ACTIVE')
            session.move('FAILED')
        self.assertFalse(session.reserved)

    def test_route_and_fake_budget_cannot_restore_revoked_runtime_grants(self):
        from universal.core import GuardError, Intent, Runtime, digest
        with tempfile.TemporaryDirectory() as root, Runtime(Path(root) / 'owner.sqlite', clock=lambda: 100) as rt:
            rt.put_resource('input', 'data')
            rt.put_resource('output', '')
            rt.source_snapshot('owner-pin', 'input', 'owner_contract')
            rt.add_task('T', 'input', 'output', 'copy', digest('data'))
            claim = rt.claim('fixture-worker', ttl=30)
            rt.revoke(claim['run_id'])
            before = rt.snapshot()
            decision = select(replace(BASE, offline_possible=False, api_available=True), enabled=True)
            self.assertEqual(decision.route, 'FAKE_API')
            self.assertFalse(decision.execution_authorized)
            self.assertEqual(rt.snapshot(), before)
            intent = Intent(claim['run_id'], 'artifact.write', 'output', 1, 'write', claim['fence'], {'content': 'data'})
            with self.assertRaises(GuardError):
                rt.execute(intent, claim['token'])
            self.assertEqual(rt.resource('output')['content'], '')
