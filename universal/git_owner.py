"""Owner-only live GitHub binding and inert signed-proof publication plans.

This module has no mutation transport, receiver, token API or worker opcode.
Actual remote publication still requires a separate scoped owner executor.
"""
from dataclasses import dataclass, field
import math
import urllib.request

from .core import GuardError
from .generative import candidate_files, strict_json
from .workspace import RepositoryBinding, Candidate, REMOTE, _oid

_REPOSITORY = '/repos/sylvainride/CoGUni'
_READS = frozenset({'/user', _REPOSITORY, _REPOSITORY + '/branches/main'})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise GuardError('provider redirect refused', 'BLOCK')


class GitHubReadOnlyProvider:
    """Fixed official endpoints, inherited authorized host transport only.

    No token discovery or propagation. Deployment needs its own legitimate
    authenticated transport; this class does not create credentials.
    """
    def get(self, route):
        if route not in _READS:
            raise GuardError('provider route outside owner scope', 'BLOCK')
        request = urllib.request.Request('https://api.github.com' + route,
                                         headers={'Accept': 'application/vnd.github+json'})
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=5) as response:
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise GuardError('provider response unavailable or oversized', 'BLOCK')
        value = strict_json(raw.decode('utf-8'))
        if type(value) is not dict:
            raise GuardError('invalid provider observation', 'BLOCK')
        return value


@dataclass(frozen=True)
class PromotionPlan:
    repository: RepositoryBinding
    candidate_sha: str
    candidate_tree: str
    evidence_id: str
    expires_at: float
    execution_authorized: bool = field(default=False, init=False)


class GitOwnerBroker:
    def __init__(self, runtime, *, provider=None):
        self.runtime = runtime
        self.provider = provider if provider is not None else GitHubReadOnlyProvider()

    def observe(self, *, expected_base):
        """Resolve current owner identity, permission and base; never mutate."""
        expected_base = _oid(expected_base)
        actor = self.provider.get('/user')
        repo = self.provider.get(_REPOSITORY)
        branch = self.provider.get(_REPOSITORY + '/branches/main')
        try:
            if (type(actor['id']) is not int or actor['id'] != 265171248 or actor['login'] != 'sylvainride'
                    or repo['owner']['id'] != actor['id'] or repo['owner']['login'] != actor['login']
                    or repo['private'] is not False or repo['default_branch'] != 'main'
                    or repo['permissions']['pull'] is not True or repo['permissions']['push'] is not True
                    or branch['name'] != 'main' or branch['commit']['sha'] != expected_base):
                raise GuardError('owner identity, permission or base changed', 'BLOCK')
            binding = RepositoryBinding(repo['id'], repo['node_id'], repo['full_name'],
                                        repo['owner']['id'], REMOTE, branch['commit']['sha'],
                                        branch['commit']['commit']['tree']['sha'])
        except (KeyError, TypeError, ValueError):
            raise GuardError('provider binding mismatch', 'BLOCK') from None
        return binding

    def plan(self, workspace, candidate, *, evidence_id, environment):
        """Require current signed project evidence before emitting an inert plan.

        The proof covers an exact bounded project projection, not unrelated
        repository files. No plan is a grant, CAS receipt or remote attestation.
        """
        rt = self.runtime
        binding = self.observe(expected_base=workspace.binding.base_sha)
        if binding != workspace.binding or type(candidate) is not Candidate or candidate.parent != binding.base_sha:
            raise GuardError('workspace base changed', 'BLOCK')
        with rt.transaction():
            rt._id(evidence_id)
            row = rt.db.execute('SELECT * FROM evidence WHERE id=?', (evidence_id,)).fetchone()
            if not row or not rt._proof_is_accepted_for_gate(row, environment):
                raise GuardError('current owner proof required', 'BLOCK')
            signed = rt.db.execute('SELECT body FROM generative_evaluations WHERE evidence=?', (evidence_id,)).fetchone()
            if not row or not signed:
                raise GuardError('generative project proof required', 'BLOCK')
            body = strict_json(signed['body'])
            context = body['context']
            project = candidate_files(rt.resource(context['artifact_id'])['content'])
            if not set(project) <= workspace.allowed_paths or workspace.tree(candidate.commit) != candidate.tree:
                raise GuardError('project scope or candidate tree mismatch', 'BLOCK')
            parents = workspace._git('rev-list', '--parents', '-n', '1', candidate.commit).decode().split()
            if parents != [candidate.commit, candidate.parent]:
                raise GuardError('candidate parent mismatch', 'BLOCK')
            changed = {p.decode() for p in workspace._git('diff-tree', '--no-commit-id', '--name-only', '-r', '-z',
                                                        candidate.parent, candidate.commit).split(b'\0') if p}
            if not changed or not changed <= set(project):
                raise GuardError('proof does not cover changed paths', 'BLOCK')
            for name, text in project.items():
                metadata = workspace._git('ls-tree', '-z', candidate.commit, '--', name)
                if not metadata or metadata.split(b' ', 1)[0] != b'100644':
                    raise GuardError('project blob mode mismatch', 'BLOCK')
                actual = workspace._git('show', candidate.commit + ':' + name).decode('utf-8', 'strict')
                if actual != text:
                    raise GuardError('candidate changed after project proof', 'BLOCK')
            workspace._live()
            now, expiry = rt.clock(), context['authorization']['expires']
            if type(now) not in (int, float) or not math.isfinite(now) or not body['decision_at'] <= now < expiry:
                raise GuardError('proof authorization expired or clock regressed', 'BLOCK')
            rt._event('owner', 'git.plan', evidence_id, 'INERT',
                      {'repository_id': binding.repository_id, 'base': binding.base_sha, 'tree': candidate.tree})
            return PromotionPlan(binding, candidate.commit, candidate.tree, evidence_id, expiry)
