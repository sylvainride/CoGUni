"""Owner-only live binding contract; provider fixtures are not human auth."""
import copy
from pathlib import Path
import tempfile
import unittest

from tests import test_workspace as workspaces
from tests import test_project_gate_integration as gates
from universal.broker import environment_identity
from universal.core import Runtime, Intent, GuardError, canonical
from universal.generative import GenerativeValidator, MODE
from universal.git_owner import GitOwnerBroker, GitHubReadOnlyProvider
from universal.workspace import LocalWorkspace


class Provider:
    def __init__(self, binding):
        self.values = {'/user': {'id': 265171248, 'login': 'sylvainride'},
                       '/repos/sylvainride/CoGUni': {'id': binding.repository_id, 'node_id': binding.node_id,
                          'full_name': binding.full_name, 'owner': {'id': binding.owner_id, 'login': 'sylvainride'},
                          'private': False, 'default_branch': 'main', 'permissions': {'pull': True, 'push': True}},
                       '/repos/sylvainride/CoGUni/branches/main': {'name': 'main', 'commit': {'sha': binding.base_sha,
                          'commit': {'tree': {'sha': binding.base_tree}}}}}
        self.calls = []

    def get(self, route):
        self.calls.append(route)
        return copy.deepcopy(self.values[route])


class GitOwnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = workspaces.WorkspaceTests()
        self.fixture.setUp()
        self.rt = Runtime(Path(self.fixture.temp.name) / 'proof.sqlite', clock=lambda: self.fixture.now[0])
        self.provider = Provider(self.fixture.binding)
        self.broker = GitOwnerBroker(self.rt, provider=self.provider)

    def tearDown(self):
        self.rt.close()
        self.fixture.tearDown()

    def test_resolve_exact_repo_current_actor_permission_and_base(self):
        self.assertEqual(self.broker.observe(expected_base=self.fixture.sha), self.fixture.binding)
        self.assertEqual(len(self.provider.calls), 3)

    def test_wrong_node_owner_rename_actor_permissions_or_head_refused(self):
        variants = [('repo', 'node_id', 'other'), ('repo', 'full_name', 'other/CoGUni'),
                    ('repo', 'private', True), ('actor', 'id', 1), ('actor', 'id', True)]
        for scope, field, value in variants:
            provider = Provider(self.fixture.binding)
            route = '/user' if scope == 'actor' else '/repos/sylvainride/CoGUni'
            provider.values[route][field] = value
            with self.subTest(field=field), self.assertRaises(GuardError):
                GitOwnerBroker(self.rt, provider=provider).observe(expected_base=self.fixture.sha)
        self.provider.values['/repos/sylvainride/CoGUni']['permissions']['push'] = False
        with self.assertRaises(GuardError):
            self.broker.observe(expected_base=self.fixture.sha)
        with self.assertRaises(GuardError):
            GitOwnerBroker(self.rt, provider=Provider(self.fixture.binding)).observe(expected_base='1' * 40)

    def test_transport_refuses_other_repo_and_mutation_routes_before_network(self):
        for route in ['/repos/other/repo', '/repos/sylvainride/CoGUni/git/refs', 'https://evil.invalid', '/user?token=synthetic']:
            with self.subTest(route=route), self.assertRaises(GuardError):
                GitHubReadOnlyProvider().get(route)

    def proof(self):
        v = GenerativeValidator(self.rt)
        v.register_policy('normalize', gates.owner_policy())
        self.rt.put_resource('source', 'owner contract')
        self.rt.source_snapshot('pin', 'source', 'owner_contract')
        self.rt.put_resource('output', '')
        self.rt.add_task('T', 'source', 'output', 'candidate', None, validation_mode=MODE, policy_id='normalize')
        claim = self.rt.claim('producer', ttl=60, environment=environment_identity(), supported_actions=['candidate'])
        self.rt.execute(Intent(claim['run_id'], 'artifact.write', 'output', 1, 'candidate', claim['fence'],
                               {'content': canonical({'files': gates.fixture('valid')})}), claim['token'])
        return v.verify('T', environment_identity(), expected_run_id=claim['run_id']), v

    def workspace(self):
        return LocalWorkspace(self.fixture.source, self.fixture.binding, run_id='proof-bound',
                              allowed_paths=('candidate.py', 'LICENSE'), expires_unix=200,
                              clock=lambda: self.fixture.now[0])

    def test_current_signed_exact_project_produces_only_inert_plan(self):
        proof, _ = self.proof()
        with self.workspace() as ws:
            candidate = ws.prepare(gates.fixture('valid'), expected_head=self.fixture.sha, expected_tree=self.fixture.tree)
            plan = self.broker.plan(ws, candidate, evidence_id=proof['evidence'], environment=environment_identity())
            self.assertFalse(plan.execution_authorized)
            self.assertEqual(plan.candidate_tree, candidate.tree)
            self.assertEqual(ws.head(), self.fixture.sha)
            self.assertEqual(self.fixture.git('rev-parse', 'HEAD'), self.fixture.sha)

    def test_unsigned_tree_changed_blob_epoch_revoke_and_expiry_refuse_plan(self):
        proof, validator = self.proof()
        with self.workspace() as ws:
            changed = gates.fixture('valid')
            changed['candidate.py'] += '\n# drift\n'
            candidate = ws.prepare(changed, expected_head=self.fixture.sha, expected_tree=self.fixture.tree)
            for evidence, env in [(candidate.tree, environment_identity()), (proof['evidence'], 'wrong-env'),
                                  (proof['evidence'], environment_identity())]:
                with self.subTest(evidence=evidence, env=env), self.assertRaises(GuardError):
                    self.broker.plan(ws, candidate, evidence_id=evidence, environment=env)
            candidate = ws.prepare(gates.fixture('valid'), expected_head=self.fixture.sha, expected_tree=self.fixture.tree)
            self.fixture.now[0] = 161
            with self.assertRaises(GuardError):
                self.broker.plan(ws, candidate, evidence_id=proof['evidence'], environment=environment_identity())
            self.fixture.now[0] = 100
            validator.rotate_signing_key()
            with self.assertRaises(GuardError):
                self.broker.plan(ws, candidate, evidence_id=proof['evidence'], environment=environment_identity())
