"""Private original-store P5 host tests; subprocess readers are trusted fixtures.

No real GitHub GET, worker dispatch, external installation or new authority.
"""
from copy import deepcopy
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from universal.continuity import ContinuityJournal
from universal.core import GuardError, canonical
from universal import host_main as host
from universal.host_config import implementation_sha256, load_config, read_private
from universal.host_process import ProcessResult, run_bounded
from universal.parallel_policy import Access, Work
from universal.parallel_scheduler import OwnerScheduler
from universal.persistent_provider_observation import ProviderObservation

ROOT = Path(__file__).resolve().parents[1]
POLICY = dict(max_parallel=2, run_budget=4, duration_budget=3600, poll_budget=8,
              max_backlog=16, resource_aliases=[], case_insensitive_targets=[])


def binding(task='A'):
    return dict(repository_id=1418009675, actor_id=265171248, run_id=10001,
                attempt=1, commit='d' * 40, branch='work/mvp-mission-transport-p5-' + task,
                code_ref='a' * 40, request_sha256='b' * 64)


def fixture_read(argv, payload, **kw):
    """Reviewed test code only: production CLI has no reader injection flag."""
    pins = json.loads(payload)
    provider = ProviderObservation(observation_id=hashlib.sha256(payload).hexdigest(),
        **pins, status='in_progress', conclusion=None, observed_unix=int(time.time()))
    data = {'state': 'OBSERVED', 'observation': asdict(provider),
            'provenance': {**pins, 'scope': 'PUBLIC_GITHUB_HTTPS_METADATA_ONLY',
                'caller_authenticated': False, 'ordinary_file_verified': True, 'get_count': 4}}
    return ProcessResult('OK', canonical(data).encode(), .001, True, 0, 0)


CHILD = r'''
import os, signal, sys
from universal import host_main as host
from tests.test_host_main import fixture_read
host.run_bounded = fixture_read
if sys.argv[1] == 'crash':
    original = host._finish_read
    def lost_ack(journal, name, ordinal, row):
        if row['action'] == 'RECORDED':
            os.kill(os.getpid(), signal.SIGKILL)  # after COMMIT, before host ACK
        return original(journal, name, ordinal, row)
    host._finish_read = lost_ack
raise SystemExit(host.main(sys.argv[2:]))
'''


class HostMainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p5-original-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'owner-source.txt'
        self.source.write_text('immutable public synthetic source\n')
        self.source.chmod(0o600)
        self.db = self.root / 'original.sqlite'
        self.config_path = self.root / 'host.json'
        self.checkpoint = self.root / 'checkpoint.json'
        with ContinuityJournal(self.db) as journal:
            self.identity = journal.identity
            scheduler = self.scheduler(journal)
            self.seed(scheduler, 'A')
            self.initial = scheduler.status('A')
        self.db.chmod(0o600)
        self.config = dict(schema=1, mode='READ_ONLY_PUBLIC_SYNTHETIC', journal_path=str(self.db),
            journal_id=self.identity, implementation_sha256=implementation_sha256(), scheduler=deepcopy(POLICY),
            tasks=[{'task_id': 'A', 'binding': binding()}],
            limits=dict(hard_timeout_seconds=.2, max_ticks=3, max_seconds=8, interval_seconds=1))
        self.write_config()

    def scheduler(self, journal):
        options = {**POLICY, 'resource_aliases': (), 'case_insensitive_targets': ()}
        return OwnerScheduler(journal, enabled=True, **options,
            check_current=lambda *_: True, check_applied=lambda *_: False)

    def seed(self, scheduler, name, physical=None):
        pins = binding(name)
        work = Work(task_id=name, depends_on=(), authorized=True,
            accesses=(Access('github', 1418009675, 'public-synthetic', 'refs/heads/' + pins['branch'],
                            '/artifact', 'W', 'c' * 40, physical or 'resource-' + name),))
        scheduler.submit(work, source_path=self.source, code_ref=pins['code_ref'],
            request_sha256=pins['request_sha256'], branch=pins['branch'],
            expires_unix=int(time.time()) + 3600, key='submit-' + name)
        return scheduler.reserve(name, expected_revision=scheduler.status(name)['revision'],
            owner='private-owner', key='reserve-' + name)

    def write_config(self):
        self.config_path.write_text(canonical(self.config))
        self.config_path.chmod(0o600)

    def run_fixture(self, **kw):
        with patch.object(host, 'run_bounded', side_effect=fixture_read):
            return host.run_host(load_config(str(self.config_path)), **kw)

    def status_events(self):
        with ContinuityJournal(self.db) as journal:
            scheduler = self.scheduler(journal)
            return scheduler.status('A'), journal.events(), scheduler.ready()

    def child(self, mode='normal', extra=()):
        process = subprocess.Popen([sys.executable, '-B', '-c', CHILD, mode, 'observe-once',
            '--config', str(self.config_path), *extra], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(stderr, b'')
        return process.pid, process.returncode, json.loads(stdout) if stdout else None

    def test_finite_observer_preserves_original_owner_fence_lease_and_run_budget(self):
        result = self.run_fixture(checkpoint=str(self.checkpoint))
        state, events, budget = self.status_events()
        for key in ('owner', 'fence', 'lease_until', 'state'):
            self.assertEqual(state[key], self.initial[key])
        self.assertEqual(state['state'], 'IN_FLIGHT')
        self.assertEqual(result['ticks'][0][0]['liveness'], 'SUSPECT_RECOVERY')
        self.assertFalse(result['ticks'][0][0]['may_cancel'])
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['remote_writes'])
        self.assertEqual(result['budgets_before']['remaining_runs'], budget['remaining_runs'])
        self.assertEqual(result['read_attempts'], 1)
        self.assertEqual(result['read_budget_left'], POLICY['poll_budget'] - 1)
        self.assertEqual(self.checkpoint.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len([e for e in events if e['body']['request'].get('operation') == 'ps.observe']), 1)

    def test_two_distinct_os_processes_resume_same_sqlite_and_stable_observation(self):
        first_pid, code, first = self.child(extra=('--checkpoint', str(self.checkpoint)))
        self.assertEqual(code, 0)
        time.sleep(1.02)
        second_pid, code, second = self.child(extra=('--resume-hint', str(self.checkpoint)))
        self.assertEqual(code, 0)
        self.assertNotEqual(first_pid, second_pid)
        self.assertEqual((first['pid'], second['pid']), (first_pid, second_pid))
        self.assertEqual(first['journal_fingerprint'], second['journal_fingerprint'])
        self.assertEqual(second['ticks'][0][0]['action'], 'REPLAY')
        state, events, budget = self.status_events()
        self.assertEqual(state['fence'], self.initial['fence'])
        self.assertEqual(budget['polls_left'], POLICY['poll_budget'] - 1)
        self.assertEqual(second['read_budget_left'], POLICY['poll_budget'] - 2)

    def test_os_crash_after_sqlite_commit_recovers_receipt_without_new_read(self):
        first_pid, code, _ = self.child('crash')
        self.assertEqual(code, -9)
        second_pid, code, result = self.child()
        self.assertEqual(code, 0)
        self.assertNotEqual(first_pid, second_pid)
        self.assertEqual(result['ticks'][0][0]['reason'], 'RECOVERED_FROM_ORIGINAL_OBSERVATION_RECEIPT')
        self.assertEqual(result['read_attempts'], 1)
        state, events, budget = self.status_events()
        self.assertEqual(budget['polls_left'], POLICY['poll_budget'] - 1)
        self.assertEqual(state['fence'], self.initial['fence'])

    def test_crash_after_intent_before_ack_does_not_retry_uncertain_read(self):
        with patch.object(host, 'run_bounded', side_effect=RuntimeError('fixture crash')):
            with self.assertRaises(RuntimeError):
                host.run_host(self.config)
        with patch.object(host, 'run_bounded') as reader:
            result = host.run_host(self.config)
        reader.assert_not_called()
        self.assertEqual(result['ticks'][0][0]['reason'], 'ORIGINAL_READ_UNCERTAIN_NO_AUTOMATIC_RETRY')
        self.assertEqual(result['read_attempts'], 1)

    def test_timeout_debits_durably_and_stops_run_without_repeated_reader(self):
        timeout = ProcessResult('TIMEOUT', b'', .2, False, 123, -9)
        with patch.object(host, 'run_bounded', return_value=timeout) as reader:
            first = host.run_host(self.config, once=False)
            second = host.run_host(self.config, once=False)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(len(first['ticks']), 1)
        self.assertEqual(second['ticks'][0][0]['reason'], 'OWNER_REQUALIFICATION_REQUIRED')
        self.assertEqual(second['read_budget_left'], POLICY['poll_budget'] - 1)
        self.assertEqual(second['budgets_after']['polls_left'], POLICY['poll_budget'])

    def test_unavailable_rate_limit_stops_without_interpreting_as_job_failure(self):
        unavailable = ProcessResult('OK', canonical({'state':'UNAVAILABLE', 'reason':'RATE_LIMIT',
            'observed_unix':int(time.time())}).encode(), .01, True, 123, 0)
        with patch.object(host, 'run_bounded', return_value=unavailable) as reader:
            result = host.run_host(self.config, once=False)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(result['ticks'][0][0]['reason'], 'RATE_LIMIT')
        self.assertEqual(self.status_events()[0]['state'], 'IN_FLIGHT')

    def test_durable_cadence_cannot_be_reset_by_new_process(self):
        self.run_fixture()
        with patch.object(host, 'run_bounded') as reader:
            result = host.run_host(self.config)
        reader.assert_not_called()
        self.assertEqual(result['ticks'][0][0]['action'], 'WAIT')

    def test_two_tasks_rotate_after_global_cadence_instead_of_starvation(self):
        with ContinuityJournal(self.db) as journal:
            self.seed(self.scheduler(journal), 'B')
        self.config['tasks'].append({'task_id':'B', 'binding':binding('B')})
        self.config['limits']['max_ticks'] = 2
        self.write_config()
        result = self.run_fixture(once=False)
        self.assertEqual(result['ticks'][0][0]['task_id'], 'A')
        self.assertEqual(result['ticks'][1][0]['task_id'], 'B')
        self.assertEqual(result['ticks'][1][0]['action'], 'RECORDED')

    def test_checkpoint_cannot_replace_database_sidecars_config_or_source(self):
        for path in [self.db, Path(str(self.db)+'-wal'), Path(str(self.db)+'-shm'),
                     self.config_path, self.source]:
            before = path.read_bytes() if path.exists() else None
            with self.subTest(path=path.name), patch.object(host, 'run_bounded') as reader:
                with self.assertRaises((GuardError, ValueError)):
                    host.run_host(self.config, checkpoint=str(path))
                reader.assert_not_called()
                self.assertEqual(path.read_bytes() if path.exists() else None, before)

    def test_checkpoint_is_compact_reusable_and_stale_resume_refused_before_read(self):
        self.run_fixture(checkpoint=str(self.checkpoint))
        hint = json.loads(read_private(str(self.checkpoint)))
        self.assertNotIn('ticks', hint['receipt'])
        # A later authoritative original-journal transition invalidates the hint.
        with ContinuityJournal(self.db) as journal:
            scheduler = self.scheduler(journal)
            state = scheduler.status('A')
            scheduler.mark_unknown('A', expected_revision=state['revision'], fence=state['fence'],
                                   owner=state['owner'], key='uncertain-write')
        with patch.object(host, 'run_bounded') as reader, self.assertRaises(GuardError):
            host.run_host(self.config, resume_hint=str(self.checkpoint))
        reader.assert_not_called()

    def test_unknown_effect_does_not_read_recover_or_release_physical_resource(self):
        with ContinuityJournal(self.db) as journal:
            scheduler = self.scheduler(journal)
            state = scheduler.status('A')
            scheduler.mark_unknown('A', expected_revision=state['revision'], fence=state['fence'],
                                   owner=state['owner'], key='uncertain-effect')
        with patch.object(host, 'run_bounded') as reader:
            result = host.run_host(self.config)
        reader.assert_not_called()
        self.assertEqual(result['ticks'][0][0]['liveness'], 'UNKNOWN_EFFECT')
        self.assertEqual(self.status_events()[0]['fence'], self.initial['fence'])

    def test_owner_revision_changed_during_io_is_not_accepted_under_new_owner_state(self):
        def changed(*args, **kwargs):
            with ContinuityJournal(self.db) as journal:
                scheduler = self.scheduler(journal)
                state = scheduler.status('A')
                scheduler.mark_unknown('A', expected_revision=state['revision'], fence=state['fence'],
                                       owner=state['owner'], key='owner-concurrent-change')
            return fixture_read(*args, **kwargs)
        with patch.object(host, 'run_bounded', side_effect=changed):
            result = host.run_host(self.config)
        self.assertEqual(result['ticks'][0][0]['reason'], 'OWNER_CHANGED_DURING_READ')
        self.assertEqual(result['budgets_after']['polls_left'], POLICY['poll_budget'])

    def test_source_drift_during_io_refuses_observation(self):
        def changed(*args, **kwargs):
            self.source.write_text('concurrent source drift')
            return fixture_read(*args, **kwargs)
        with patch.object(host, 'run_bounded', side_effect=changed), self.assertRaises(GuardError):
            host.run_host(self.config)

    def test_tampered_reader_provenance_is_not_owner_proof(self):
        def tampered(*args, **kwargs):
            good = fixture_read(*args, **kwargs)
            data = json.loads(good.stdout)
            data['provenance']['caller_authenticated'] = True
            return ProcessResult('OK', canonical(data).encode(), .01, True, 0, 0)
        with patch.object(host, 'run_bounded', side_effect=tampered), self.assertRaises(GuardError):
            host.run_host(self.config)
        self.assertEqual(self.status_events()[2]['polls_left'], POLICY['poll_budget'])

    def test_lease_expiry_during_read_does_not_extend_lease_or_observe(self):
        # Owner clock is moved only in this synthetic pre-test authority setup.
        with ContinuityJournal(self.db) as journal:
            journal.db.execute('UPDATE continuity_tasks SET lease_until=? WHERE id=?',
                               (time.time() + .08, 'ps-job-A'))
        def delayed(*args, **kwargs):
            time.sleep(.12)
            return fixture_read(*args, **kwargs)
        with patch.object(host, 'run_bounded', side_effect=delayed):
            result = host.run_host(self.config)
        self.assertEqual(result['ticks'][0][0]['action'], 'HANDOFF')
        self.assertEqual(result['budgets_after']['polls_left'], POLICY['poll_budget'])

    def test_existing_external_poll_is_not_erased_by_later_p5_identity_mapping(self):
        pins = binding()
        observation_id = hashlib.sha256(canonical(pins).encode()).hexdigest()
        provider = ProviderObservation(observation_id=observation_id, **pins, status='in_progress',
                                       conclusion=None, observed_unix=int(time.time()))
        with ContinuityJournal(self.db) as journal:
            scheduler = self.scheduler(journal)
            state = scheduler.status('A')
            scheduler.observe('A', provider.scheduler_record(), expected_revision=state['revision'],
                fence=state['fence'], owner=state['owner'], key='p4-' + observation_id)
        result = self.run_fixture()
        self.assertEqual(result['ticks'][0][0]['action'], 'REPLAY')
        self.assertEqual(result['read_budget_left'], POLICY['poll_budget'] - 2)

    def test_crashed_identity_with_same_key_different_provider_cannot_claim_replay(self):
        original = fixture_read([], canonical(binding()).encode())
        provider = ProviderObservation(**json.loads(original.stdout)['observation'])
        substituted = {**provider.scheduler_record(), 'status':'queued'}
        with ContinuityJournal(self.db) as journal:
            scheduler = self.scheduler(journal)
            state = scheduler.status('A')
            scheduler.observe('A', substituted, expected_revision=state['revision'],
                fence=state['fence'], owner=state['owner'], key='p4-' + provider.observation_id)
        with patch.object(host, 'run_bounded', side_effect=fixture_read), self.assertRaises(GuardError):
            host.run_host(self.config)
        with patch.object(host, 'run_bounded') as reader:
            result = host.run_host(self.config)
        reader.assert_not_called()
        self.assertEqual(result['ticks'][0][0]['reason'], 'ORIGINAL_READ_UNCERTAIN_NO_AUTOMATIC_RETRY')

    def test_real_reader_process_ignores_poisoned_cwd_without_any_network_get(self):
        trap = self.root / 'trap'; trap.mkdir()
        package = trap / 'universal'; package.mkdir()
        (package/'__init__.py').write_text('')
        marker = self.root/'injected'
        (package/'host_github.py').write_text('open(' + repr(str(marker)) + ',"w").write("unsafe")')
        previous = Path.cwd()
        try:
            os.chdir(trap)
            result = run_bounded([sys.executable, '-B', '-P', '-m', 'universal.host_github'],
                                 b'{}', timeout_seconds=1)
        finally:
            os.chdir(previous)
        self.assertEqual(result.state, 'OK')
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(json.loads(result.stdout)['reason'], 'PROVENANCE_MISMATCH')
        self.assertFalse(marker.exists())

    def test_missing_or_copied_journal_never_implicitly_initializes(self):
        for path in [self.root/'missing.sqlite', self.root/'copy.sqlite']:
            if path.name.startswith('copy'):
                path.write_bytes(self.db.read_bytes()); path.chmod(0o600)
            self.config['journal_path'] = str(path)
            with self.subTest(path=path.name), self.assertRaises((GuardError, OSError)):
                host.run_host(self.config)
        self.assertFalse((self.root/'missing.sqlite').exists())

    def test_private_config_refuses_commands_urls_unknown_fields_or_new_budgets(self):
        for mutation in [dict(command='sh'), dict(url='https://attacker.invalid')]:
            self.config.update(mutation); self.write_config()
            with self.subTest(mutation=mutation), self.assertRaises(GuardError):
                load_config(str(self.config_path))
            for key in mutation:
                self.config.pop(key)
        self.config['scheduler']['poll_budget'] += 1
        with self.assertRaises(GuardError):
            host.run_host(self.config)

    def test_historical_source_pin_is_refused_without_reset_or_implicit_migration(self):
        with ContinuityJournal(self.db) as journal:
            old_contract = deepcopy(journal.get('ps-config')['contract'])
        source = str(ROOT/'universal/continuity.py')
        old_contract['sources'][source] = '0'*64
        old_store = self.root/'old-owner.sqlite'
        with ContinuityJournal(old_store) as journal:
            old_id = journal.identity
            journal.create_task('ps-config', old_contract, key='ps-config-v1')
        old_store.chmod(0o600)
        config = {**self.config, 'journal_path':str(old_store), 'journal_id':old_id}
        with patch.object(host, 'run_bounded') as reader, self.assertRaises(GuardError):
            host.run_host(config)
        reader.assert_not_called()
        with ContinuityJournal(old_store) as journal:
            self.assertEqual(journal.get('ps-config')['contract'], old_contract)
            self.assertEqual(len(journal.events()), 1)

    def test_identity_source_or_provider_substitution_refuses_before_get(self):
        mutations = [('journal_id','0'*64), ('implementation_sha256','0'*64)]
        for field, value in mutations:
            conf = deepcopy(self.config); conf[field] = value
            with self.subTest(field=field), patch.object(host, 'run_bounded') as reader, self.assertRaises(GuardError):
                host.run_host(conf)
            reader.assert_not_called()
        self.config['tasks'][0]['binding']['request_sha256'] = 'e'*64
        with self.assertRaises(GuardError):
            host.run_host(self.config)

    def test_symlinks_hardlinks_public_permissions_and_duplicate_keys_are_refused(self):
        self.config_path.chmod(0o644)
        with self.assertRaises(GuardError):
            load_config(str(self.config_path))
        self.config_path.chmod(0o600)
        alias = self.root/'alias.json'; alias.symlink_to(self.config_path)
        with self.assertRaises(GuardError):
            load_config(str(alias))
        alias.unlink(); os.link(self.config_path, alias)
        with self.assertRaises(GuardError):
            load_config(str(self.config_path))
        alias.unlink()
        self.config_path.write_text('{"schema":1,"schema":1}')
        with self.assertRaises((GuardError, ValueError)):
            load_config(str(self.config_path))

    def test_existing_host_flock_and_sqlite_writer_both_refuse_promptly(self):
        with self.db.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            _, code, result = self.child()
            self.assertEqual(code, 2)
            self.assertLess(time.monotonic() - started, 2)
        writer = sqlite3.connect(self.db, isolation_level=None)
        try:
            writer.execute('BEGIN IMMEDIATE')
            started = time.monotonic()
            with self.assertRaises(sqlite3.OperationalError):
                host.run_host(self.config)
            self.assertLess(time.monotonic() - started, .5)
        finally:
            writer.rollback(); writer.close()

    def test_deadline_without_cleanup_reserve_never_starts_reader(self):
        self.config['limits']['max_seconds'] = 1
        with patch.object(host, 'run_bounded') as reader:
            result = host.run_host(self.config)
        reader.assert_not_called()
        self.assertEqual(result['read_attempts'], 0)
        self.assertEqual(result['ticks'][0][0]['reason'], 'HOST_DEADLINE_NO_READ')

    def test_failed_cli_output_is_whitelisted_and_has_no_private_path(self):
        self.config['journal_id'] = '0'*64; self.write_config()
        _, code, result = self.child()
        self.assertEqual(code, 2)
        self.assertEqual(result['reason'], 'HOST_INPUT_OR_OWNER_REFUSED')
        self.assertNotIn(str(self.root), canonical(result))


class ContinuityHostTimeoutTests(unittest.TestCase):
    def test_default_timeout_retained_and_invalid_options_do_not_create_store(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'original.sqlite'
            for value in [True, -1, 10001, .1, '0']:
                with self.subTest(value=value), self.assertRaises(GuardError):
                    ContinuityJournal(path, busy_timeout_ms=value)
                self.assertFalse(path.exists())
            with ContinuityJournal(path) as journal:
                self.assertEqual(journal.db.execute('PRAGMA busy_timeout').fetchone()[0], 10000)
            with ContinuityJournal(path, busy_timeout_ms=0) as journal:
                self.assertEqual(journal.db.execute('PRAGMA busy_timeout').fetchone()[0], 0)
