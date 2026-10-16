"""Opt-in owner scheduling facade over ContinuityJournal, without dispatch.

The host supplies reviewed permission/source and acceptance checkers. They are
trusted owner code, never worker input or JSON approval flags. Reservations are
atomic in the existing journal; external operations still require the host's
actual connector CAS. No new store, grants, nonce service or remote outbox.
"""
from dataclasses import asdict, replace
import json
from pathlib import Path
import time

from .continuity import ContinuityJournal, source_sha, _id, _integer
from .core import GuardError, canonical, digest
from .parallel_policy import Access, Work, select_ready

_STAGES = ('READY', 'IN_FLIGHT', 'RESULT_READY', 'APPLY_PENDING', 'ACCEPTED_APPLIED',
           'UNKNOWN_EFFECT', 'SUSPECT', 'BLOCKED', 'CANCELLED', 'HANDOFF')


def _chunks(value):
    text = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    if len(text) > 7000:
        raise GuardError('scheduler contract exceeds bounded metadata')
    return [text[i:i+480] for i in range(0, len(text), 480)]


class OwnerScheduler:
    """A bounded local owner ledger. This object and DB never enter workers.

    check_current(work, metadata) must verify owner ACL, immutable code/source,
    current ref/version and resource identity. check_applied must independently
    verify the exact provider result AND target effect/readback. Neither a
    provider success nor a worker statement is accepted as that check.
    """
    def __init__(self, journal, *, enabled=False, max_parallel=2, run_budget=8,
                 duration_budget=3600, poll_budget=48, max_backlog=16,
                 check_current=None, check_applied=None, resource_aliases=(),
                 case_insensitive_targets=()):
        if type(journal) is not ContinuityJournal or type(enabled) is not bool:
            raise GuardError('trusted existing journal and explicit opt-in required')
        for value, maximum in ((max_parallel, 2), (run_budget, 16), (duration_budget, 14400),
                               (poll_budget, 128), (max_backlog, 32)):
            _integer(value, maximum=maximum)
        select_ready([], resource_aliases=resource_aliases, case_insensitive_targets=case_insensitive_targets)
        self.journal, self.enabled = journal, enabled
        self.check_current, self.check_applied = check_current, check_applied
        self.aliases, self.case_targets = resource_aliases, case_insensitive_targets
        self.config = {'max_parallel': max_parallel, 'run_budget': run_budget,
                       'duration_budget': duration_budget, 'poll_budget': poll_budget,
                       'max_backlog': max_backlog, 'resource_aliases': list(resource_aliases),
                       'case_insensitive_targets': list(case_insensitive_targets)}
        # Existing immutable task contract persists policy across restarts. A
        # changed budget/config cannot silently refresh spent reservations.
        from . import parallel_policy, dag, continuity, core
        paths = [Path(module.__file__).resolve() for module in (parallel_policy, dag, continuity, core)] + [Path(__file__).resolve()]
        contract = {'version': 1, 'mission': 'Bounded owner parallel scheduling policy',
                    'constraints': ['parallel-owner-v1', digest(canonical(self.config))],
                    'decisions': _chunks(self.config), 'sources': {str(path): source_sha(str(path)) for path in paths},
                    'files': [], 'criteria': ['no worker authority or external dispatch'],
                    'actions': [{'id': 'READY', 'tool': 'parallel_owner', 'files': [], 'description': 'owner configuration only'}],
                    'dependencies': {}, 'max_attempts': 1, 'budget': 1}
        journal.create_task('ps-config', contract, key='ps-config-v1')

    @staticmethod
    def _task(task_id):
        _id(task_id)
        return _id('ps-job-' + task_id)

    def _row(self, task_id, revision=None):
        if not self.journal._sources_current(self.journal.get('ps-config')['contract']):
            raise GuardError('owner scheduling implementation changed')
        row = self.journal.get(self._task(task_id))
        if revision is not None and row['revision'] != _integer(revision, maximum=2**63-1):
            raise GuardError('stale scheduler revision')
        try:
            meta = json.loads(''.join(row['contract']['decisions']))
            raw = meta['work']
            accesses = tuple(Access(**item) for item in raw['accesses'])
            work = Work(**{**raw, 'accesses': accesses, 'depends_on': tuple(raw['depends_on']),
                           'state': row['checkpoint']['active_action']})
        except (TypeError, KeyError, ValueError):
            raise GuardError('invalid owner scheduling contract') from None
        if not self.journal._sources_current(row['contract']):
            raise GuardError('scheduler source changed; reconcile before dispatch')
        return row, work, meta

    def _jobs(self):
        return [self._row(r['id'][7:]) for r in self.journal.db.execute(
            "SELECT id FROM continuity_tasks WHERE id LIKE 'ps-job-%' ORDER BY id")]

    def _current(self, work, meta):
        if not self.enabled or not callable(self.check_current):
            raise GuardError('owner scheduler disabled or no qualified source/ACL checker')
        # The checker performs observations only; every later host effect still
        # needs a fresh CAS. A local transaction cannot lock a GitHub branch.
        if self.check_current(work, meta) is not True:
            raise GuardError('owner source, permission or version check failed')

    def submit(self, work, *, source_path, code_ref, request_sha256, branch,
               expires_unix, key):
        if type(work) is not Work or work.state != 'READY':
            raise GuardError('new typed READY owner work required')
        # Pure validation covers resource aliases, source pins and DAG scopes.
        import re
        if (type(code_ref) is not str or not re.fullmatch(r'[0-9a-f]{40}', code_ref)
                or type(request_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', request_sha256)
                or type(branch) is not str or not re.fullmatch(r'work/mvp-mission-transport-[A-Za-z0-9._/-]{1,96}', branch)
                or type(expires_unix) is not int or not self.journal.clock() < expires_unix <= self.journal.clock() + 86400):
            raise GuardError('invalid owner branch/source/expiry pin')
        source = Path(source_path)
        if not source.is_absolute() or source.is_symlink() or str(source.resolve()) != str(source):
            raise GuardError('canonical nonsymlink owner source required')
        path = str(source)
        meta = {'work': asdict(work), 'code_ref': code_ref, 'request_sha256': request_sha256,
                'branch': branch, 'expires_unix': expires_unix}
        actions = [{'id': stage, 'tool': 'parallel_owner', 'files': [], 'description': 'owner scheduling ' + stage} for stage in _STAGES]
        contract = {'version': 1, 'mission': 'Owner public synthetic mission ' + work.task_id,
                    'constraints': ['parallel-owner-v1', 'config:' + digest(canonical(self.config))],
                    'decisions': _chunks(meta), 'sources': {path: source_sha(path)}, 'files': [],
                    'criteria': ['verified computation and independently applied target before dependency release'],
                    'actions': actions, 'dependencies': {}, 'max_attempts': 1, 'budget': 1}
        task = self._task(work.task_id)
        def change(now):
            # Global backlog, DAG and insertion share the existing owner write
            # transaction. Independent submitters cannot overbook a cold queue.
            prior = self._jobs()
            if any(w.task_id == work.task_id for _, w, _ in prior):
                raise GuardError('scheduler task already exists under another operation')
            select_ready([w for _, w, _ in prior] + [work], enabled=False,
                         max_backlog=self.config['max_backlog'], resource_aliases=self.aliases,
                         case_insensitive_targets=self.case_targets)
            serialized = self.journal._validate_contract(contract)
            context = self.journal._context(contract, digest(serialized), 'READY', None)
            self.journal.db.execute("INSERT INTO continuity_tasks VALUES(?,?,?,'READY',1,0,0,0,NULL,NULL,?,NULL,'[]',NULL,NULL)",
                                    (task, serialized, digest(serialized), canonical(context)))
            return task
        self.journal._operation(key, {'operation': 'ps.submit', 'task': work.task_id, 'contract': contract}, change)
        return self.status(work.task_id)

    def _polls(self):
        return sum(e['body']['request'].get('operation') == 'ps.observe' for e in self.journal.events())

    def ready(self):
        if not self.journal._sources_current(self.journal.get('ps-config')['contract']):
            raise GuardError('owner scheduling implementation changed')
        rows = self._jobs()
        spent_runs = sum(r['attempts'] * w.run_cost for r, w, _ in rows)
        spent_seconds = sum(r['attempts'] * w.duration_seconds for r, w, _ in rows)
        works = []
        for row, work, meta in rows:
            if work.state == 'READY' and self.journal.clock() >= meta['expires_unix']:
                work = replace(work, authorized=False)
            works.append(work)
        decision = select_ready(works, enabled=self.enabled,
                                max_parallel=self.config['max_parallel'],
                                remaining_runs=max(0, self.config['run_budget'] - spent_runs),
                                remaining_seconds=max(0, self.config['duration_budget'] - spent_seconds),
                                max_backlog=self.config['max_backlog'], resource_aliases=self.aliases,
                                case_insensitive_targets=self.case_targets)
        return {'selected': decision.selected, 'held': decision.held, 'blocked': decision.blocked,
                'remaining_runs': max(0, self.config['run_budget'] - spent_runs),
                'remaining_seconds': max(0, self.config['duration_budget'] - spent_seconds),
                'polls_left': max(0, self.config['poll_budget'] - self._polls()),
                'dispatch_performed': False, 'execution_authorized': False}

    def _update(self, row, stage, *, owner=None, claim=False):
        context = self.journal.context_for(row['id'], stage)
        if claim:
            self.journal.db.execute("UPDATE continuity_tasks SET state='RUNNING',revision=revision+1,fence=fence+1,attempts=attempts+1,spent=spent+1,owner=?,lease_until=?,checkpoint=? WHERE id=?",
                                    (owner, min(self.journal.clock() + min(300, self._row(row['id'][7:])[1].duration_seconds), self._row(row['id'][7:])[2]['expires_unix']), canonical(context), row['id']))
        else:
            self.journal.db.execute('UPDATE continuity_tasks SET checkpoint=?,revision=revision+1 WHERE id=?',
                                    (canonical(context), row['id']))
        return row['id']

    def reserve(self, task_id, *, expected_revision, owner, key):
        _id(owner)
        # Reserve BEFORE a host dispatch. Lost submit ACK retains this reservation
        # until exact run/ref reconciliation; it never becomes a free retry.
        def change(now):
            row, work, meta = self._row(task_id, expected_revision)
            self._current(work, meta)
            now = self.journal._now()
            row, work, meta = self._row(task_id, expected_revision)
            if now >= meta['expires_unix'] or task_id not in self.ready()['selected']:
                raise GuardError('dependency/resource/budget/backpressure gate closed')
            return self._update(row, 'IN_FLIGHT', owner=owner, claim=True)
        result = self.journal._operation(key, {'operation': 'ps.reserve', 'task': task_id,
                                              'revision': expected_revision, 'owner': owner}, change)
        return {**self.status(task_id), 'replayed': result['replayed']}

    def renew(self, task_id, *, expected_revision, fence, owner, key, ttl=300):
        _integer(ttl, maximum=300); _integer(fence, maximum=2**63-1); _id(owner)
        def change(now):
            row, work, meta = self._row(task_id, expected_revision)
            self._current(work, meta)
            now = self.journal._now()
            row, work, meta = self._row(task_id, expected_revision)
            provider = self.status(task_id)['provider']
            reservations = [e['body']['at'] for e in self.journal.events()
                            if e['body']['request'].get('operation') == 'ps.reserve'
                            and e['body']['request'].get('task') == task_id]
            deadline = min(meta['expires_unix'], reservations[0] + work.duration_seconds) if reservations else 0
            if (row['owner'] != owner or row['fence'] != fence or row['lease_until'] is None
                    or now >= row['lease_until'] or now >= deadline
                    or work.state not in {'IN_FLIGHT', 'RESULT_READY', 'SUSPECT'}
                    or not provider or provider['status'] not in {'queued', 'in_progress', 'completed'}):
                raise GuardError('lease renewal needs live bound owner and finite remaining budget')
            self.journal.db.execute('UPDATE continuity_tasks SET lease_until=?,revision=revision+1 WHERE id=?',
                                    (min(now + ttl, deadline), row['id']))
            return row['id']
        self.journal._operation(key, {'operation': 'ps.renew', 'task': task_id,
                                      'revision': expected_revision, 'fence': fence, 'owner': owner, 'ttl': ttl}, change)
        return self.status(task_id)

    def recover(self, task_id, *, expected_revision, owner, key):
        """Owner takes over an expired observation lease; never redispatches.

        The original provider binding and resource reservation survive. Any
        eventual application still needs independent acceptance and fresh CAS.
        """
        _id(owner)
        def change(now):
            row, work, meta = self._row(task_id, expected_revision)
            self._current(work, meta)
            now = self.journal._now()
            row, work, meta = self._row(task_id, expected_revision)
            provider = self.status(task_id)['provider']
            reservations = [e['body']['at'] for e in self.journal.events() if e['body']['request'].get('operation') == 'ps.reserve' and e['body']['request'].get('task') == task_id]
            deadline = min(meta['expires_unix'], reservations[0] + work.duration_seconds) if reservations else 0
            if (work.state not in {'IN_FLIGHT', 'RESULT_READY', 'SUSPECT', 'UNKNOWN_EFFECT', 'HANDOFF'}
                    or row['lease_until'] is None or now < row['lease_until']
                    or now >= deadline or not provider):
                raise GuardError('recovery requires expired reserved lease and original provider binding')
            self.journal.db.execute('UPDATE continuity_tasks SET owner=?,fence=fence+1,lease_until=?,revision=revision+1 WHERE id=?',
                                    (owner, min(now + 300, deadline), row['id']))
            return row['id']
        self.journal._operation(key, {'operation': 'ps.recover', 'task': task_id,
                                      'revision': expected_revision, 'owner': owner}, change)
        return self.status(task_id)

    def status(self, task_id):
        row, work, meta = self._row(task_id)
        events = [e for e in self.journal.events() if e['body']['request'].get('task') == task_id]
        observations = [e['body']['request']['provider'] for e in events if e['body']['request'].get('operation') == 'ps.observe']
        return {'task_id': task_id, 'state': work.state, 'revision': row['revision'],
                'fence': row['fence'], 'owner': row['owner'], 'lease_until': row['lease_until'],
                'journal_id': row['journal_id'], 'contract_sha256': row['contract_sha'],
                'code_ref': meta['code_ref'], 'request_sha256': meta['request_sha256'],
                'branch': meta['branch'], 'provider': observations[-1] if observations else None,
                'effect_retry_authorized': False}

    def observe(self, task_id, provider, *, expected_revision, fence, owner, key):
        # Owner obtains this sanitized snapshot from the actual provider tool.
        # No remote/public JSON endpoint exposes this owner-only method.
        _integer(fence, maximum=2**63-1); _id(owner)
        fields = {'repository_id', 'actor_id', 'run_id', 'attempt', 'commit', 'branch',
                  'code_ref', 'request_sha256', 'status', 'conclusion'}
        import re
        if type(provider) is not dict or set(provider) != fields:
            raise GuardError('exact provider observation required')
        if (provider['repository_id'] != 1418009675 or type(provider['repository_id']) is not int
                or provider['actor_id'] != 265171248 or type(provider['actor_id']) is not int
                or type(provider['run_id']) is not int or not 0 < provider['run_id'] < 10**15
                or type(provider['attempt']) is not int or not 0 < provider['attempt'] <= 100
                or type(provider['commit']) is not str or not re.fullmatch(r'[0-9a-f]{40}', provider['commit'])
                or provider['status'] not in ('queued', 'in_progress', 'completed')
                or provider['conclusion'] not in (None, 'success', 'failure', 'cancelled', 'timed_out', 'skipped')):
            raise GuardError('unqualified provider identity/status')
        def change(now):
            row, work, meta = self._row(task_id, expected_revision)
            if row['fence'] != fence or row['owner'] != owner or row['lease_until'] is None or now >= row['lease_until'] or work.state not in {'IN_FLIGHT', 'SUSPECT', 'RESULT_READY', 'UNKNOWN_EFFECT', 'HANDOFF'}:
                raise GuardError('stale or fenced observation')
            if self._polls() >= self.config['poll_budget']:
                raise GuardError('poll budget exhausted; handoff required')
            if any(provider[k] != meta[k] for k in ('code_ref', 'request_sha256', 'branch')):
                raise GuardError('provider source/branch substitution')
            old = self.status(task_id)['provider']
            if old and any(old[k] != provider[k] for k in ('run_id', 'attempt', 'commit')):
                raise GuardError('run/attempt/source substitution; reconcile original binding')
            if old and old['status'] == 'completed' and provider['status'] != 'completed':
                raise GuardError('late provider event cannot regress terminal state')
            # Success needs a separate artifact and target check. Failure may be
            # uncertain, so retain resources and never auto-repeat an effect.
            stage = 'SUSPECT' if provider['status'] == 'completed' and provider['conclusion'] != 'success' else work.state
            return self._update(row, stage)
        self.journal._operation(key, {'operation': 'ps.observe', 'task': task_id,
                                      'revision': expected_revision, 'provider': provider}, change)
        return self.status(task_id)

    def accept_applied(self, task_id, evidence, *, expected_revision, fence, owner, key):
        _integer(fence, maximum=2**63-1); _id(owner)
        def change(now):
            row, work, meta = self._row(task_id, expected_revision)
            self._current(work, meta)
            now = self.journal._now()
            row, work, meta = self._row(task_id, expected_revision)
            provider = self.status(task_id)['provider']
            if (row['fence'] != fence or row['owner'] != owner or work.state not in {'IN_FLIGHT', 'RESULT_READY', 'APPLY_PENDING', 'UNKNOWN_EFFECT'}
                    or not provider or provider['status'] != 'completed' or provider['conclusion'] != 'success'
                    or now >= meta['expires_unix'] or row['lease_until'] is None or now >= row['lease_until'] or not callable(self.check_applied)
                    or self.check_applied(work, meta, provider, evidence) is not True):
                raise GuardError('result alone cannot release dependency; owner applied/readback proof required')
            # Permission/proof checkers may perform bounded owner I/O. Never
            # sign/accept using a timestamp captured before those observations.
            now = self.journal._now()
            row, work, meta = self._row(task_id, expected_revision)
            if now >= meta['expires_unix'] or now >= row['lease_until'] or row['fence'] != fence or row['owner'] != owner:
                raise GuardError('owner proof expired or fenced during verification')
            return self._update(row, 'ACCEPTED_APPLIED')
        # A bounded owner-selected proof reference, never a worker verdict.
        if len(canonical(evidence).encode()) > 2048:
            raise GuardError('application proof reference too large')
        self.journal._operation(key, {'operation': 'ps.accept', 'task': task_id,
                                      'revision': expected_revision, 'evidence': evidence}, change)
        return self.status(task_id)

    def mark_unknown(self, task_id, *, expected_revision, fence, owner, key):
        _integer(fence, maximum=2**63-1); _id(owner)
        def change(now):
            row, work, _ = self._row(task_id, expected_revision)
            if row['fence'] != fence or row['owner'] != owner or row['lease_until'] is None or now >= row['lease_until'] or work.state not in {'IN_FLIGHT', 'RESULT_READY', 'APPLY_PENDING'}:
                raise GuardError('unknown effect requires original active reservation')
            return self._update(row, 'UNKNOWN_EFFECT')
        self.journal._operation(key, {'operation': 'ps.unknown', 'task': task_id, 'revision': expected_revision}, change)
        return self.status(task_id)

    def reconcile(self, task_id, evidence=None, **bindings):
        """Read exact binding, or accept a qualified original effect readback.

        Neither path calls a connector mutation or dispatches another run.
        """
        if evidence is None:
            return self.status(task_id)
        if self.status(task_id)['state'] != 'UNKNOWN_EFFECT':
            raise GuardError('qualified effect reconciliation requires UNKNOWN_EFFECT')
        return self.accept_applied(task_id, evidence, **bindings)

    def cancel_queued(self, task_id, *, expected_revision, key):
        def change(now):
            row, work, _ = self._row(task_id, expected_revision)
            if work.state != 'READY':
                raise GuardError('active/uncertain job cannot be cancelled by queue cleanup')
            return self._update(row, 'CANCELLED')
        self.journal._operation(key, {'operation': 'ps.cancel', 'task': task_id, 'revision': expected_revision}, change)
        return self.status(task_id)

    def handoff(self):
        return {'journal_id': self.journal.identity, 'tasks': [self.status(w.task_id) for _, w, _ in self._jobs()],
                'budgets': self.ready(), 'persistent_service': False, 'chat_wakeup_available': False,
                'message': 'Écris reprise pour continuer. Relire les refs/runs exacts; aucun effet à réémettre.'}
