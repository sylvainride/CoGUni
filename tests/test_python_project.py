"""Owner unittest oracles run flat multi-module projects in fresh bwrap children."""
import subprocess
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from universal.broker import environment_identity
from universal.core import GuardError, Intent, Runtime, canonical
from universal.generative import GenerativeValidator, MODE
from universal.policy_runner import run_policy_checks, git_tree_sha, validate_policy
from universal.project_runner import project_files


def files(kind='normalize'):
    root = Path(__file__).parent / 'fixtures_python_project' / kind
    return {p.name: p.read_text() for p in root.iterdir()}


def policy(kind='normalize'):
    return {'version': 1, 'profile': 'python-project-v1',
            'tests': [{'module': 'project_main', 'function': 'run',
                       'args': [' ab '] if kind == 'normalize' else [3, 4],
                       'expected': 'AB' if kind == 'normalize' else 25}],
            'allowed_licenses': ['MIT'], 'forbidden_markers': ['SYNTHETIC_OWNER_PRIVATE'],
            'max_seconds': 3.0}


class PythonProjectTests(unittest.TestCase):
    def test_profile_strict_opt_in_schema_and_module_paths(self):
        for change in [{'version': True}, {'shell': 'true'}, {'profile': 'general-shell'}]:
            p = {**policy(), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_policy(p)
        for name in ['../project_x.py', 'sys.py', 'project_x/__init__.py', 'requirements.txt']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                project_files({**files(), name: ''})

    def test_two_real_multi_file_projects_use_external_oracles(self):
        for kind in ['normalize', 'squares']:
            with self.subTest(kind=kind):
                f = files(kind)
                r = run_policy_checks(f, policy(kind), {'source': kind})
                self.assertTrue(all(c['outcome'] == 'PASS' for c in r['criteria'].values()), r['criteria'])
                self.assertEqual(r['tree_sha'], git_tree_sha(f))
                ready = r['observations']['cases'][0]['ready']
                self.assertTrue(ready['seccomp'] and ready['no_new_privs'])
                self.assertEqual(ready['limits']['processes'], 0)
                self.assertNotIn('signature', r)

    def test_forged_stdout_and_candidate_test_never_replace_owner_oracle(self):
        f = files()
        f['project_main.py'] = "print('PASS')\ndef run(x): return 'WRONG'\n"
        f['test_worker.py'] = "raise RuntimeError('Candidate self-test must remain inert')\n"
        r = run_policy_checks(f, policy(), {})
        self.assertEqual(r['criteria']['tests']['outcome'], 'FAIL')

    def test_module_import_and_test_discovery_are_bounded(self):
        f = files()
        f['project_util.py'] = 'from project_main import run\n'
        r = run_policy_checks(f, policy(), {})
        self.assertNotEqual(r['criteria']['tests']['outcome'], 'PASS')
        p = policy()
        p['tests'][0]['module'] = 'project_absent'
        r = run_policy_checks(files(), p, {})
        self.assertEqual(r['criteria']['tests']['outcome'], 'FAIL')

    def test_missing_sandbox_never_executes_in_owner(self):
        real = shutil.which
        with patch('universal.isolation.shutil.which', side_effect=lambda name, *a, **k:
                   None if name == 'bwrap' else real(name, *a, **k)):
            r = run_policy_checks(files(), policy(), {})
        self.assertEqual(r['criteria']['tests']['outcome'], 'NOT_RUN')
        self.assertNotEqual(r['criteria']['environment']['outcome'], 'PASS')

    def test_host_secret_owner_import_socket_fork_exec_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            secret = Path(root) / 'secret'
            secret.write_text('SYNTHETIC_OWNER_PRIVATE')
            attacks = [f"def run(x): return open({str(secret)!r}).read()\n",
                       'import universal.core\ndef run(x): return x\n',
                       'import socket\ndef run(x): return socket.socket()\n',
                       'import os\ndef run(x): return os.fork()\n',
                       "import os\ndef run(x): return os.execv('/bin/sh', ['sh'])\n"]
            for source in attacks:
                f = files()
                f['project_main.py'] = source
                r = run_policy_checks(f, policy(), {})
                self.assertEqual(r['criteria']['tests']['outcome'], 'FAIL', r)
                self.assertNotIn('SYNTHETIC_OWNER_PRIVATE', canonical(r))

    def test_cpu_memory_and_output_are_bounded_nonpositive(self):
        for source in ['def run(x):\n while True: pass\n',
                       'def run(x): return "X" * (512 * 1024 * 1024)\n',
                       'def run(x):\n print("X" * 100000)\n return "AB"\n']:
            f = files()
            f['project_main.py'] = source
            p = policy()
            p['max_seconds'] = .5
            r = run_policy_checks(f, p, {})
            self.assertNotEqual(r['criteria']['tests']['outcome'], 'PASS')
            self.assertLess(len(canonical(r)), 65536)

    def test_license_markers_and_compile_are_distinct_bounded_checks(self):
        for name, text, criterion, expected in [('LICENSE', '', 'licenses', 'UNKNOWN'),
                ('LICENSE', 'SPDX-License-Identifier: fake\n', 'licenses', 'FAIL'),
                ('README.md', 'SYNTHETIC_OWNER_PRIVATE', 'security', 'FAIL'),
                ('project_util.py', 'def broken(:', 'lint', 'FAIL')]:
            f = files()
            f[name] = text
            r = run_policy_checks(f, policy(), {})
            self.assertEqual(r['criteria'][criterion]['outcome'], expected)

    def test_project_source_and_test_policies_have_aggregate_bounds(self):
        f = files()
        f['README.md'] = 'X' * 48000
        with self.assertRaises(ValueError):
            run_policy_checks(f, policy(), {})
        p = policy()
        p['tests'] *= 21
        with self.assertRaises(ValueError):
            validate_policy(p)

    def owner(self, root):
        rt = Runtime(Path(root) / 'owner.sqlite', clock=lambda: 1000)
        validator = GenerativeValidator(rt)
        validator.register_policy('project-policy', policy())
        rt.put_resource('source', 'owner mini-project contract')
        rt.source_snapshot('owner-pin', 'source', 'owner_contract')
        rt.put_resource('output', '')
        rt.add_task('T', 'source', 'output', 'candidate', None, validation_mode=MODE, policy_id='project-policy')
        claim = rt.claim('producer', ttl=60, environment=environment_identity(), supported_actions=['candidate'])
        rt.execute(Intent(claim['run_id'], 'artifact.write', 'output', 1, 'candidate', claim['fence'],
                          {'content': canonical({'files': files()})}), claim['token'])
        return rt, validator, claim

    def test_existing_owner_signer_accepts_exact_project_then_rejects_tree_drift(self):
        with tempfile.TemporaryDirectory() as root:
            rt, validator, claim = self.owner(root)
            try:
                r = validator.verify('T', environment_identity(), expected_run_id=claim['run_id'])
                self.assertTrue(r['accepted_for_gate'])
                self.assertEqual(r['tree_sha'], git_tree_sha(files()))
                f = files()
                f['project_util.py'] += '\n# drift\n'
                rt.put_resource('output', canonical({'files': f}), 2)
                self.assertFalse(rt.proof_is_accepted_for_gate(r['evidence'], environment_identity()))
            finally:
                rt.close()

    def test_grant_revoke_and_source_drift_after_project_checks_prevent_signing(self):
        for mutation in ['revoke', 'source']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                rt, validator, claim = self.owner(root)
                try:
                    def change(point):
                        if point == 'after_checks_before_commit':
                            if mutation == 'revoke':
                                rt.revoke(claim['run_id'])
                            else:
                                rt.put_resource('source', rt.resource('source')['content'], 1)
                    with self.assertRaises(GuardError):
                        validator.verify('T', environment_identity(), expected_run_id=claim['run_id'], crash_hook=change)
                    self.assertEqual(rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)
                finally:
                    rt.close()

    def test_git_tree_timeout_is_nonpositive_evidence_not_an_exception(self):
        with patch('universal.project_runner._git_tree', side_effect=subprocess.TimeoutExpired('git', 1)):
            r = run_policy_checks(files(), policy(), {})
        for criterion in ('tests', 'provenance', 'environment'):
            self.assertEqual(r['criteria'][criterion]['outcome'], 'NOT_RUN')
