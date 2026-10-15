"""Bounded local owner CLI for public synthetic missions.

The transport boundary is the host's authenticated process/file permissions.
This module is NOT an HTTP/MCP authenticator, a daemon, or a target writer. The
GitHub adapter separately authenticates provider context. All durable scheduling
and idempotency records use the existing ContinuityJournal; computation uses
Runtime and its isolated worker/verifier. No second database schema or outbox.
"""
import argparse
import fcntl
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from .continuity import ContinuityJournal, source_sha
from .core import GuardError
from .mission_artifacts import _secure_read
from .mission_contracts import (_read, canonical, decode_mission, fingerprint,
                                MissionContractError)

_PROJECTS = {'synthetic-A', 'synthetic-B'}
_SHA = re.compile(r'[0-9a-f]{40}\Z')
_PAYLOAD = re.compile(r'synthetic:[A-Za-z0-9._:-]{1,128}\Z')


def _directory(path):
    path = Path(path).absolute()
    if path.is_symlink() or str(path.resolve()) != str(path):
        raise GuardError('noncanonical owner directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.stat()
    if s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise GuardError('owner directory must be private and owned by current uid')
    return path


def _immutable(path, data):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        existing = _secure_read(str(path.parent), Path(path.name), max_bytes=16384)
        if existing != data:
            raise GuardError('immutable source conflict')
        return
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _process_start(pid):
    # Linux owner observation independent of stdout and worker input. The host
    # and same-uid controller are trusted. PID reuse never inherits a lease.
    fields = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()
    if fields[0] in {'Z', 'X'}:
        raise OSError('owner process terminated')
    return fields[19]


def _owner_identity():
    boot = hashlib.sha256(Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest()[:16]
    return 'proc-' + str(os.getpid()) + '-' + _process_start(os.getpid()) + '-' + boot


def _owner_alive(identity):
    if type(identity) is not str:
        return False
    try:
        prefix, pid, ticks, boot = identity.split('-')
        if prefix != 'proc' or not pid.isdigit():
            return False
        actual_boot = hashlib.sha256(Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest()[:16]
        return (boot == actual_boot and Path('/proc/' + pid).stat().st_uid == os.getuid()
                and _process_start(int(pid)) == ticks)
    except (OSError, ValueError, IndexError):
        return False


def _serialized(method):
    @wraps(method)
    def call(self, project, mission, *args, **kwargs):
        task = self._task(project, mission)
        fd = os.open(self.root / (task + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GuardError('mission operation in progress; observe, do not redispatch') from None
            return method(self, project, mission, *args, **kwargs)
        finally:
            os.close(fd)
    return call


class MissionClient:
    """Trusted owner facade; never expose arbitrary owner/path flags remotely."""
    def __init__(self, state, targets, owner, *, clock=time.time):
        if type(owner) is not str or not re.fullmatch(r'[A-Za-z0-9._:-]{1,96}', owner):
            raise GuardError('invalid owner identity')
        self.root, self.targets = _directory(state), _directory(targets)
        self.owner, self.clock = owner, clock
        # Reject DB symlink redirection before SQLite opens it. The private
        # owner directory and same-uid owner are trusted, not hostile writers.
        for name in ('continuity.sqlite', 'runtime.sqlite'):
            if (self.root / name).is_symlink():
                raise GuardError('owner store symlink denied')
        self._bootstrap_runtime()
        self.journal = ContinuityJournal(self.root / 'continuity.sqlite', clock=clock)

    def _bootstrap_runtime(self):
        # Runtime's historical migrations are not a concurrent bootstrap API.
        # Serialize first open at the owner-root boundary instead of changing
        # that schema or letting two projects migrate the same new store.
        from .core import Runtime
        fd = os.open(self.root / 'runtime-bootstrap.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise GuardError('runtime bootstrap busy; read before retry') from None
                    time.sleep(.01)
            with Runtime(self.root / 'runtime.sqlite'):
                pass
        finally:
            os.close(fd)

    def close(self):
        self.journal.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _executor(self):
        from .mission_executor import DeterministicExecutor
        return DeterministicExecutor(self.root / 'runtime.sqlite')

    def _task(self, project, mission):
        if project not in _PROJECTS or type(mission) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,95}', mission):
            raise GuardError('unknown project or mission')
        return 'mission-' + fingerprint({'project': project, 'mission': mission})[:40]

    def _loaded(self, project, mission, *, live=False):
        row = self.journal.get(self._task(project, mission))
        decisions = row['contract']['decisions']
        if not 2 <= len(decisions) <= 16 or decisions[0] != 'mission-cli-v1':
            raise GuardError('not a CLI mission')
        req = _read(''.join(decisions[1:]))
        env = req['envelope']
        if (env['project']['owner'] != self.owner or env['project']['id'] != project
                or env['mission_id'] != mission or req['targets'] != str(self.targets)
                or row['contract']['constraints'][-1] != 'cli-request:' + fingerprint(req)):
            raise GuardError('owner/project/target binding mismatch')
        # Validate format using its immutable creation time; current expiry is
        # enforced for every execution/acceptance, never from caller timestamps.
        decode_mission(canonical(env), now_unix=env['created_unix'])
        if not self.journal.verify_chain() or not self.journal._sources_current(row['contract']):
            raise GuardError('owner source or journal changed')
        revoked = self.journal.db.execute('SELECT 1 FROM continuity_receipts WHERE key=?', ('revoke-' + row['id'],)).fetchone()
        if live and revoked:
            raise GuardError('mission revoked')
        if live:
            decode_mission(canonical(env), now_unix=int(self.journal._now()))
            if row['state'] == 'CLOSED':
                raise GuardError('mission closed or revoked')
        return row, req

    def submit(self, request):
        if type(request) is not dict or set(request) != {'envelope', 'payload', 'action', 'code_ref'}:
            raise GuardError('exact submit fields required')
        # Deep copy/strict JSON bound before any filesystem mutation.
        req = _read(canonical(request))
        env = decode_mission(canonical(req['envelope']), now_unix=int(self.clock()))
        project = env['project']
        task = self._task(project['id'], env['mission_id'])
        if (project['owner'] != self.owner or project['kind'] != 'local'
                or project['source_of_truth'] != 'owner-synthetic-fixture'
                or env['privacy'] != 'PUBLIC_SYNTHETIC'
                or env.get('parent_mission_id') is not None
                or env.get('capability_snapshot_ref') is not None
                or env['expires_unix'] - env['created_unix'] > 86400
                or env['contract']['max_duration_seconds'] > 300
                or env['contract']['allowed_actions'] != ['simulate']
                or env['contract']['max_external_cost'] != 0
                or env['contract']['artifact_policy'] != 'public_synthetic'
                or env['contract']['dependencies']):
            raise GuardError('synthetic owner scope denied')
        if (type(req['payload']) is not str or not _PAYLOAD.fullmatch(req['payload'])
                or req['action'] not in ('uppercase', 'sha256')
                or type(req['code_ref']) is not str or not _SHA.fullmatch(req['code_ref'])
                or env['source_sha256'] != hashlib.sha256(req['payload'].encode()).hexdigest()):
            raise GuardError('unsupported deterministic payload/action/source')
        # The selected target is observed, never written by CoGUni. A stale
        # base blocks admission. Duplicate admission checks the same contract.
        data = _secure_read(str(self.targets), Path(project['id']) / 'result.txt', max_bytes=1024)
        expected = hashlib.sha256(data).hexdigest()
        source = self.root / (task + '.input')
        output = self.root / (task + '.unused-output')
        req['targets'] = str(self.targets)
        _immutable(source, req['payload'].encode())
        # Reuse admission validation/contract representation. Build the richer
        # immutable CLI metadata before the first journal commit, not after it.
        contract = {
            'version': 1, 'mission': env['contract']['objective'],
            'constraints': ['offline synthetic admission only', 'project:' + project['id'],
                            'version:' + project['base_version'], 'envelope:' + fingerprint(env),
                            'cli-request:' + fingerprint(req)],
            'decisions': ['mission-cli-v1'] + [json.dumps(req, sort_keys=True, separators=(',', ':'), ensure_ascii=True)[i:i+480] for i in range(0, len(json.dumps(req, sort_keys=True, separators=(',', ':'), ensure_ascii=True)), 480)],
            'sources': {str(source): env['source_sha256']}, 'files': [str(output)],
            'criteria': env['contract']['criteria'],
            'actions': [{'id': 'simulate', 'tool': 'offline_fixture', 'files': [str(output)],
                         'description': 'bounded isolated deterministic computation'}],
            'dependencies': {}, 'max_attempts': env['contract']['max_attempts'],
            'budget': env['contract']['max_attempts'],
        }
        key = 'admit-' + fingerprint({'owner': self.owner, 'project': project['id'],
                                      'key': env['idempotency_key']})[:40]
        existing = self.journal.db.execute('SELECT 1 FROM continuity_tasks WHERE id=?', (task,)).fetchone()
        if not existing and expected != project['base_version']:
            raise GuardError('target base version mismatch')
        row = self.journal.create_task(task, contract, key=key)
        # Return current state on replay (the original receipt remains immutable).
        self._executor().prepare(row['id'], req['payload'], req['action'])
        return {**self.status(project['id'], env['mission_id']), 'replayed': row['replayed']}

    def status(self, project, mission):
        row, req = self._loaded(project, mission)
        ex = self._executor()
        task = ex.task_id(row['id'], req['payload'], req['action'])
        result = ex.result(task)
        state = result['status']
        revoked = self.journal.db.execute('SELECT 1 FROM continuity_receipts WHERE key=?', ('revoke-' + row['id'],)).fetchone()
        if revoked:
            state = 'CANCELLED'
        elif row['state'] == 'CLOSED':
            state = 'CANCELLED'
            if row['disposition'] == 'OWNER_COMPLETED' and result['status'] == 'COMPLETED':
                data = _secure_read(str(self.targets), Path(project) / 'result.txt', max_bytes=1024)
                expected = req['payload'].upper() if req['action'] == 'uppercase' else hashlib.sha256(req['payload'].encode()).hexdigest()
                state = 'ACCEPTED' if data == expected.encode() and result['content'] == expected else 'SUSPECT'
        elif state != 'COMPLETED' and row['state'] == 'RUNNING':
            state = 'RUNNING' if row['lease_until'] > self.clock() and _owner_alive(row['owner']) else 'SUSPECT'
        elif self.clock() >= req['envelope']['expires_unix']:
            state = 'BLOCKED'
        return {'schema_version': 1, 'mission_id': mission, 'project_id': project,
                'owner': self.owner, 'journal_id': row['journal_id'], 'task_id': row['id'],
                'contract_sha256': row['contract_sha'], 'run_id': result['run_id'],
                'revision': row['revision'], 'fence': row['fence'], 'lease_until': row['lease_until'],
                'expires_unix': req['envelope']['expires_unix'], 'state': state,
                'source_sha256': req['envelope']['source_sha256'], 'code_ref': req['code_ref'],
                'acceptance': 'OWNER_READBACK' if state == 'ACCEPTED' else 'NOT_ACCEPTED',
                'effect_retry_authorized': False, 'chat_wakeup_available': False}

    @_serialized
    def execute(self, project, mission):
        row, req = self._loaded(project, mission, live=True)
        if row['state'] != 'READY':
            # After loss of execute ACK, attach to the durable existing task.
            # Never convert lease expiry into automatic redispatch.
            return self.result(project, mission)
        owner = _owner_identity()
        row = self.journal.claim(row['id'], owner, 'offline_fixture',
                                 expected_revision=row['revision'], key='claim-' + row['id'],
                                 ttl=min(300, req['envelope']['contract']['max_duration_seconds']))
        if row['state'] != 'RUNNING':
            raise GuardError('owner scheduling blocked')
        ex = self._executor()
        task = ex.prepare(row['id'], req['payload'], req['action'])
        ex.run(task, timeout=min(60, req['envelope']['contract']['max_duration_seconds']))
        return self.result(project, mission)

    def result(self, project, mission):
        row, req = self._loaded(project, mission)
        ex = self._executor()
        result = ex.result(ex.task_id(row['id'], req['payload'], req['action']))
        state = self.status(project, mission)
        return {**state, 'artifact': result if result['status'] == 'COMPLETED' and state['state'] not in {'CANCELLED', 'BLOCKED'} else None,
                'application_status': 'APPLIED_READBACK' if state['state'] == 'ACCEPTED' else 'NOT_APPLIED_BY_COGUNI'}

    @_serialized
    def ack(self, project, mission, *, artifact_sha256):
        row, req = self._loaded(project, mission)
        decode_mission(canonical(req['envelope']), now_unix=int(self.journal._now()))
        if self.journal.db.execute('SELECT 1 FROM continuity_receipts WHERE key=?', ('revoke-' + row['id'],)).fetchone():
            raise GuardError('mission revoked')
        if row['state'] == 'CLOSED' and row['disposition'] == 'OWNER_COMPLETED':
            # Revalidate the same current proof and target on lost ACK, without
            # performing another target write or changing a version.
            pass
        else:
            self._loaded(project, mission, live=True)
        if row['state'] == 'CLOSED' and row['disposition'] != 'OWNER_COMPLETED':
            raise GuardError('mission cancelled or revoked')
        result = self.result(project, mission)
        artifact = result['artifact']
        data = _secure_read(str(self.targets), Path(project) / 'result.txt', max_bytes=1024)
        expected = req['payload'].upper() if req['action'] == 'uppercase' else hashlib.sha256(req['payload'].encode()).hexdigest()
        if (not artifact or artifact_sha256 == req['envelope']['project']['base_version']
                or artifact_sha256 != artifact['output_sha256']
                or data != expected.encode() or artifact['content'] != expected
                or hashlib.sha256(data).hexdigest() != artifact_sha256):
            raise GuardError('independent target readback/oracle failed; rework required')
        if row['state'] != 'CLOSED':
            self.journal.close_task(row['id'], expected_revision=row['revision'],
                                    key='ack-' + row['id'], disposition='OWNER_COMPLETED')
        return self.result(project, mission)

    @_serialized
    def cancel(self, project, mission):
        row, _ = self._loaded(project, mission)
        if row['state'] != 'READY':
            raise GuardError('cancel only before dispatch; active/uncertain effects require reconciliation')
        self.journal.close_task(row['id'], expected_revision=row['revision'], key='cancel-' + row['id'])
        return self.status(project, mission)

    @_serialized
    def revoke(self, project, mission):
        row, req = self._loaded(project, mission)
        from .core import Runtime
        task = self._executor().task_id(row['id'], req['payload'], req['action'])
        self.journal._operation('revoke-' + row['id'], {'operation': 'mission.revoke', 'task': row['id']}, lambda now: row['id'])
        with Runtime(self.root / 'runtime.sqlite') as rt:
            for evidence in list(rt.db.execute('SELECT id FROM evidence WHERE task=?', (task,))):
                rt.revoke_evidence(evidence['id'], 'mission_revoked')
            for run in list(rt.db.execute('SELECT id FROM runs WHERE task=?', (task,))):
                rt.revoke(run['id'])
        if row['state'] != 'CLOSED':
            self.journal.close_task(row['id'], expected_revision=row['revision'], key='revoke-close-' + row['id'])
        return self.status(project, mission)

    @_serialized
    def reconcile(self, project, mission):
        row, req = self._loaded(project, mission, live=True)
        ex = self._executor()
        task = ex.task_id(row['id'], req['payload'], req['action'])
        observed = ex.result(task)
        if observed['task_status'] == 'RESULT_READY':
            # The committed output is already durable. Run only its confined
            # verifier; do not reset/reclaim READY or RUNNING computations.
            ex.run(task, timeout=min(60, req['envelope']['contract']['max_duration_seconds']))
        return self.result(project, mission)

    def handoff(self, project, mission):
        s = self.result(project, mission)
        last = self.journal.events()[-1]
        return {**s, 'last_event_digest': last['hash'], 'persistent_service': False,
                'resume': {'method': 'mission.result', 'params': {'project_id': project, 'mission_id': mission}},
                'message': 'Écris reprise. Revalider identités, run, preuve, TTL et cible; aucun effet à réémettre.'}

    def call(self, wire):
        obj = _read(wire)
        if set(obj) != {'schema_version', 'method', 'params'} or type(obj['schema_version']) is not int or obj['schema_version'] != 1:
            raise GuardError('unsupported API request')
        method, params = obj['method'], obj['params']
        if type(params) is not dict:
            raise GuardError('params object required')
        if type(method) is not str:
            raise GuardError('method string required')
        if method == 'mission.submit':
            return self.submit(params)
        required = {'project_id', 'mission_id'} | ({'artifact_sha256'} if method == 'mission.ack' else set())
        if set(params) != required:
            raise GuardError('unexpected operation fields')
        funcs = {'mission.status': self.status, 'mission.result': self.result,
                 'mission.execute': self.execute, 'mission.ack': self.ack,
                 'mission.cancel': self.cancel, 'mission.revoke': self.revoke,
                 'mission.handoff': self.handoff, 'mission.reconcile': self.reconcile}
        if type(method) is not str or method not in funcs:
            raise GuardError('unsupported method')
        return funcs[method](params['project_id'], params['mission_id'],
                             **({'artifact_sha256': params['artifact_sha256']} if method == 'mission.ack' else {}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state', required=True)
    p.add_argument('--targets', required=True)
    p.add_argument('--owner', required=True)
    args = p.parse_args()
    try:
        wire = sys.stdin.buffer.read(16385)
        if len(wire) > 16384:
            raise GuardError('request too large')
        with MissionClient(args.state, args.targets, args.owner) as client:
            result = client.call(wire)
        print(json.dumps({'ok': True, 'result': result}, sort_keys=True))
        return 0
    except (GuardError, MissionContractError, ValueError, OSError) as error:
        # No exception text, paths, request or credential in public transport.
        print(json.dumps({'ok': False, 'error': type(error).__name__, 'state': 'BLOCKED'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
