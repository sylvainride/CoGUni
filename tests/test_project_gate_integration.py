"""Owner unittest cases execute fixture functions only through the V8 sandbox.

Candidate-supplied tests are inert tree data. These tests do not qualify an
arbitrary project build, a legal license audit, or a comprehensive secret scan.
"""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from universal.broker import environment_identity
from universal.core import GuardError, Intent, Runtime, canonical
from universal.generative import GenerativeValidator, MODE
from universal.policy_runner import git_tree_sha, run_policy_checks


FIXTURES = Path(__file__).parent / 'fixtures_project_gate'


def fixture(name):
    if name not in {'valid', 'invalid'}:
        raise ValueError('unknown trusted fixture')
    return {'candidate.py': (FIXTURES / name / 'worker.py').read_text(),
            'LICENSE': 'SPDX-License-Identifier: MIT\n'}


def owner_policy():
    return {'version': 1, 'entrypoint': 'candidate.py', 'function': 'normalize',
            'tests': [{'args': ['  ab  '], 'expected': 'AB'},
                      {'args': [''], 'expected': ''},
                      {'args': ['  été  '], 'expected': 'ÉTÉ'}],
            'allowed_licenses': ['MIT'], 'forbidden_markers': ['SYNTHETIC_PRIVATE_MARKER'],
            'max_seconds': 3.0}


class ProjectGateInputTests(unittest.TestCase):
    def test_no_fixture_path_or_arbitrary_command_is_accepted(self):
        for name in ('../valid', '/tmp/valid', 'valid;true', 'third-party'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                fixture(name)

    def test_missing_sandbox_never_uses_fixture_subprocess_fallback(self):
        actual = shutil.which
        with patch('universal.isolation.shutil.which', side_effect=lambda name, *a, **k:
                   None if name == 'bwrap' else actual(name, *a, **k)):
            result = run_policy_checks(fixture('valid'), owner_policy(), {'fixture': 'valid'})
        self.assertEqual(result['criteria']['tests']['outcome'], 'NOT_RUN')
        self.assertNotEqual(result['criteria']['environment']['outcome'], 'PASS')
        self.assertNotIn('signature', result)


@unittest.skipUnless(shutil.which('bwrap'), 'actual sandbox required')
class ProjectGateIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='coguni-project-gate-')
        self.now = [1000.0]
        self.rt = Runtime(Path(self.temp.name) / 'owner.sqlite', clock=lambda: self.now[0])
        self.validator = GenerativeValidator(self.rt)
        self.validator.register_policy('normalize-owner', owner_policy())
        self.rt.put_resource('mission', 'Implement normalization under owner policy')
        self.rt.source_snapshot('owner-source', 'mission', 'owner_contract')

    def tearDown(self):
        self.rt.close()
        self.temp.cleanup()

    def submit(self, name='P', files=None, *, source='mission', **extra):
        output = name + '-output'
        self.rt.put_resource(output, '')
        self.rt.add_task(name, source, output, 'candidate', None,
                         validation_mode=MODE, policy_id='normalize-owner', **extra)
        claim = self.rt.claim('fixture-producer', ttl=60, environment=environment_identity(),
                              supported_actions=['candidate'])
        self.assertEqual(claim['task']['id'], name)
        self.rt.execute(Intent(claim['run_id'], 'artifact.write', output, claim['output_version'],
                               name + '.write', claim['fence'],
                               {'content': canonical({'files': fixture('valid') if files is None else files})}),
                        claim['token'])
        return claim

    def verify(self, claim, **kwargs):
        return self.validator.verify(claim['task']['id'], environment_identity(),
                                     expected_run_id=claim['run_id'], **kwargs)

    def test_valid_fixture_has_real_tests_tree_and_signed_owner_proof(self):
        files = fixture('valid')
        result = self.verify(self.submit(files=files))
        self.assertEqual(result['outcome'], 'PASS')
        self.assertTrue(result['accepted_for_gate'])
        self.assertEqual(result['tree_sha'], git_tree_sha(files))
        self.assertTrue(self.rt.proof_is_accepted_for_gate(result['evidence'], environment_identity()))
        self.assertTrue(self.rt.check_journal())

    def test_buggy_fixture_and_forged_pass_do_not_open_gate(self):
        files = fixture('invalid')
        files['candidate.py'] += "\nprint('PASS')\n"
        files['test_candidate.py'] = "# Candidate claims all tests PASS; inert data\n"
        result = self.verify(self.submit(files=files))
        self.assertEqual(result['outcome'], 'FAIL')
        self.assertFalse(result['accepted_for_gate'])

    def test_candidate_tests_cannot_replace_owner_cases(self):
        files = fixture('invalid')
        files['test_candidate.py'] = 'raise RuntimeError("This file must never execute")\n'
        result = self.verify(self.submit(files=files))
        self.assertFalse(result['accepted_for_gate'])
        self.assertEqual(result['outcome'], 'FAIL')

    def test_real_marker_scan_covers_inert_files_and_has_declared_limits(self):
        files = fixture('valid')
        files['notes.txt'] = 'SYNTHETIC_PRIVATE_MARKER'
        result = run_policy_checks(files, owner_policy(), {'fixture': 'valid'})
        self.assertEqual(result['criteria']['tests']['outcome'], 'PASS')
        self.assertEqual(result['criteria']['security']['outcome'], 'FAIL')
        files['notes.txt'] = 'SYNTHETIC_' + 'OTHER_MARKER'
        # An unconfigured string is not detected: no completeness claim.
        result = run_policy_checks(files, owner_policy(), {'fixture': 'valid'})
        self.assertEqual(result['criteria']['security']['outcome'], 'PASS')

    def test_missing_or_disallowed_spdx_is_a_distinct_nonpositive_criterion(self):
        for license_text, outcome in [(None, 'UNKNOWN'), ('SPDX-License-Identifier: GPL-3.0-only\n', 'FAIL')]:
            files = fixture('valid')
            if license_text is None:
                del files['LICENSE']
            else:
                files['LICENSE'] = license_text
            with self.subTest(outcome=outcome):
                result = run_policy_checks(files, owner_policy(), {})
                self.assertEqual(result['criteria']['tests']['outcome'], 'PASS')
                self.assertEqual(result['criteria']['licenses']['outcome'], outcome)

    def test_source_version_mutated_after_real_checks_cannot_be_signed(self):
        claim = self.submit()
        def change(point):
            if point == 'after_checks_before_commit':
                self.rt.put_resource('mission', self.rt.resource('mission')['content'], 1)
        with self.assertRaises(GuardError):
            self.verify(claim, crash_hook=change)
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)

    def test_tree_rename_or_content_mutation_requires_a_new_proof(self):
        for name, transform in [('rename', lambda f: f.update(COPYING=f.pop('LICENSE'))),
                                ('edit', lambda f: f.update({'candidate.py': f['candidate.py'] + '\n# changed\n'}))]:
            with self.subTest(change=name):
                claim = self.submit(name)
                result = self.verify(claim)
                files = fixture('valid')
                transform(files)
                self.assertNotEqual(git_tree_sha(files), result['tree_sha'])
                output = name + '-output'
                self.rt.put_resource(output, canonical({'files': files}), 2)
                self.assertFalse(self.rt.proof_is_accepted_for_gate(result['evidence'], environment_identity()))

    def test_parent_to_child_chain_is_invalidated_by_same_byte_new_version(self):
        parent = self.verify(self.submit('A'))
        child = self.verify(self.submit('B', source='A-output', dependencies=['A'],
                           input_mode='VERIFIED_UPSTREAM_POLICY_OUTPUT', producer='A',
                           source_policy_id='normalize-owner'))
        self.assertTrue(parent['accepted_for_gate'] and child['accepted_for_gate'])
        self.rt.put_resource('A-output', self.rt.resource('A-output')['content'], 2)
        self.assertFalse(self.rt.proof_is_accepted_for_gate(child['evidence'], environment_identity()))

    def test_epoch_rotation_and_expired_grants_reject_resigning(self):
        result = self.verify(self.submit('A'))
        self.validator.rotate_signing_key()
        self.assertFalse(self.rt.proof_is_accepted_for_gate(result['evidence'], environment_identity()))
        claim = self.submit('B')
        def expire(point):
            if point == 'after_checks_before_commit':
                self.now[0] = 1061.0
        with self.assertRaises(GuardError):
            self.verify(claim, crash_hook=expire)
