"""Finite private Linux owner observer; no dispatch, acceptance or remote writer.

Only inspected source supplies the reader executable. Configuration is private
owner input, not a mission/worker channel. All durable accounting stays in the
original ContinuityJournal. The CLI never creates a journal or an owner task.
"""
import argparse
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
import sqlite3
import sys
import time
from urllib.parse import quote

from .continuity import ContinuityJournal
from .core import GuardError, canonical, digest
from .host_config import ROOT, implementation_sha256, load_config, private_path, read_private, validate_config
from .host_github import validate_binding
from .host_process import HARD_OVERHEAD_SECONDS, run_bounded
from .mission_contracts import _read
from .parallel_scheduler import OwnerScheduler
from .persistent_provider_observation import ProviderObservation
from .persistent_resume import export_resume, validate_resume
from .persistent_supervisor import PassiveSupervisor


@contextmanager
def locked_original(config):
    """Lock the existing DB inode; no auxiliary store or implicit bootstrap."""
    path = private_path(config['journal_path'])
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    journal = None
    try:
        info = os.fstat(fd)
        if not info.st_size:
            raise GuardError('owner journal must already exist')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Reject an empty/foreign store before the historical constructor can
        # create schema/config. Read only, nonblocking precheck on the same inode.
        check = sqlite3.connect('file:' + quote(str(path), safe='/') + '?mode=rw', uri=True, timeout=0)
        try:
            if not check.execute("SELECT 1 FROM continuity_tasks WHERE id='ps-config'").fetchone():
                raise GuardError('original scheduler configuration missing')
        finally:
            check.close()
        _inode_current(config, (fd, info.st_dev, info.st_ino))
        journal = ContinuityJournal(path, busy_timeout_ms=0)
        if journal.identity != config['journal_id']:
            raise GuardError('foreign or replaced original journal')
        recorded = json.loads(''.join(journal.get('ps-config')['contract']['decisions']))
        if recorded != config['scheduler']:
            raise GuardError('existing owner scheduler policy differs')
        options = dict(config['scheduler'])
        options['resource_aliases'] = tuple(tuple(x) for x in options['resource_aliases'])
        options['case_insensitive_targets'] = tuple(options['case_insensitive_targets'])
        scheduler = OwnerScheduler(journal, enabled=True, **options,
                                   check_current=lambda *_: False, check_applied=lambda *_: False)
        yield journal, scheduler, (fd, info.st_dev, info.st_ino)
    finally:
        if journal is not None:
            journal.close()
        os.close(fd)


def _inode_current(config, handle):
    fd, device, inode = handle
    current = private_path(config['journal_path']).stat()
    if (current.st_dev, current.st_ino) != (device, inode) or os.fstat(fd).st_ino != inode:
        raise GuardError('original owner journal replaced during observation')


def _status_binding(status, binding):
    if any(status[k] != binding[k] for k in ('branch', 'code_ref', 'request_sha256')):
        raise GuardError('private pin differs from original owner ledger')
    prior = status['provider']
    if prior and any(prior[k] != binding[k] for k in ('repository_id', 'actor_id', 'run_id', 'attempt', 'commit')):
        raise GuardError('private pin attempts to rebind original provider')


def _anchor(journal, config):
    request = {'operation': 'p5.host_policy', 'config_sha256': digest(canonical(config)),
               'implementation_sha256': config['implementation_sha256']}
    # Receipt lookup protects owner configuration/source across restarts. This
    # is an audit receipt on ps-config, not a new task, grant, or policy engine.
    journal._operation('p5-host-policy-v1', request, lambda now: 'ps-config')


def _attempts(journal):
    return [e['body'] for e in journal.events() if e['body']['request'].get('operation') == 'p5.read_attempt']


def _read_budget(journal, scheduler):
    events = [e['body'] for e in journal.events()]
    reads = [e for e in events if e['request'].get('operation') == 'p5.read_attempt']
    mapped = set()
    # Existing/external polls are charged too. Success P5 polls are correlated
    # before persistence, so ACK loss cannot cause a second accounting debit.
    external = 0
    for event in events:
        if event['request'].get('operation') == 'p5.read_identity':
            mapped.add(event['request']['observation_key'])
        elif event['request'].get('operation') == 'ps.observe' and event['key'] not in mapped:
            external += 1
    return max(0, scheduler.config['poll_budget'] - len(reads) - external)


def _neutral(task_id, action, reason, state='UNKNOWN'):
    return {'task_id': task_id, 'action': action, 'liveness': state, 'reason': reason,
            'execution_authorized': False, 'may_cancel': False, 'may_retry_write': False}


def _finish_read(journal, name, ordinal, row):
    journal._operation('p5-read-outcome-' + str(ordinal),
        {'operation': 'p5.read_outcome', 'task': name, 'ordinal': ordinal,
         'action': row['action'], 'reason': row['reason']}, lambda at: 'ps-job-' + name)
    return row


def _pending_read(journal, name):
    events = [e['body'] for e in journal.events()]
    reads = [e for e in events if e['request'].get('operation') == 'p5.read_attempt'
             and e['request']['task'] == name]
    if not reads:
        return None
    ordinal = reads[-1]['request']['ordinal']
    outcome = next((e for e in events if e['key'] == 'p5-read-outcome-' + str(ordinal)), None)
    if outcome:
        if outcome['request']['action'] == 'HANDOFF':
            return _neutral(name, 'HANDOFF', 'OWNER_REQUALIFICATION_REQUIRED')
        return None
    identity = next((e for e in events if e['key'] == 'p5-read-identity-' + str(ordinal)), None)
    if identity:
        original = next((e for e in events if e['key'] == identity['request']['observation_key']), None)
        if (original and original['request'].get('operation') == 'ps.observe'
                and original['request'].get('task') == name
                and digest(canonical(original['request'].get('provider'))) == identity['request']['provider_sha256']):
            return _finish_read(journal, name, ordinal,
                _neutral(name, 'REPLAY', 'RECOVERED_FROM_ORIGINAL_OBSERVATION_RECEIPT'))
    return _neutral(name, 'HANDOFF', 'ORIGINAL_READ_UNCERTAIN_NO_AUTOMATIC_RETRY')


def _decode_read(result, binding):
    if result.state != 'OK' or not result.cleanup_verified:
        return None, None, 'READER_' + result.state
    data = _read(result.stdout)
    if data.get('state') == 'UNAVAILABLE' and set(data) == {'state', 'reason', 'observed_unix'}:
        if data['reason'] not in {'ACCESS_DENIED', 'NOT_FOUND', 'RATE_LIMIT', 'UNAVAILABLE', 'PROVENANCE_MISMATCH'}:
            raise GuardError('invalid reader failure')
        return None, None, data['reason']
    if set(data) != {'state', 'observation', 'provenance'} or data['state'] != 'OBSERVED':
        raise GuardError('unqualified reader protocol')
    provider = ProviderObservation(**data['observation'])
    if any(getattr(provider, k) != v for k, v in binding.items()):
        raise GuardError('reader source does not match owner pins')
    provenance = data['provenance']
    if (type(provenance) is not dict or provenance.get('scope') != 'PUBLIC_GITHUB_HTTPS_METADATA_ONLY'
            or provenance.get('caller_authenticated') is not False
            or provenance.get('ordinary_file_verified') is not True or provenance.get('get_count') != 4
            or any(provenance.get(k) != v for k, v in binding.items())):
        raise GuardError('reader provenance missing or substituted')
    # Only a whitelist is returned; no arbitrary provider text or worker flags.
    return provider, {k: provenance[k] for k in ('scope', 'caller_authenticated', 'ordinary_file_verified', 'get_count')}, None


def observe_task(config, journal, scheduler, handle, task, deadline):
    name, binding = task['task_id'], validate_binding(task['binding'])
    before = scheduler.status(name)
    _status_binding(before, binding)
    if before['state'] == 'UNKNOWN_EFFECT':
        return _neutral(name, 'RECONCILE', 'ORIGINAL_EFFECT_ONLY_NO_PROVIDER_READ', 'UNKNOWN_EFFECT')
    now = time.time()
    if before['state'] not in {'IN_FLIGHT', 'RESULT_READY', 'SUSPECT', 'HANDOFF'}:
        return _neutral(name, 'STOP', 'NO_ACTIVE_OWNER_RESERVATION')
    if before['owner'] is None or before['lease_until'] is None or now >= before['lease_until']:
        return _neutral(name, 'HANDOFF', 'LEASE_EXPIRED_NO_RECOVERY', 'SUSPECT_RECOVERY')
    pending = _pending_read(journal, name)
    if pending is not None:
        return pending
    if scheduler.ready()['polls_left'] <= 0 or _read_budget(journal, scheduler) <= 0:
        return _neutral(name, 'HANDOFF', 'ORIGINAL_POLL_OR_READ_BUDGET_EXHAUSTED')
    reads = _attempts(journal)
    if reads and now - reads[-1]['at'] < config['limits']['interval_seconds']:
        return _neutral(name, 'WAIT', 'DURABLE_READ_CADENCE')
    remaining = deadline - time.monotonic() - HARD_OVERHEAD_SECONDS - 0.1
    if remaining < 0.05:
        return _neutral(name, 'HANDOFF', 'HOST_DEADLINE_NO_READ')
    ordinal = len(reads) + 1
    def count_read(at):
        if len(_attempts(journal)) != ordinal - 1 or _read_budget(journal, scheduler) <= 0:
            raise GuardError('read budget raced')
        return 'ps-job-' + name
    receipt = journal._operation('p5-read-' + str(ordinal),
        {'operation': 'p5.read_attempt', 'task': name, 'ordinal': ordinal,
         'binding_sha256': digest(canonical(binding))}, count_read)
    if receipt['replayed']:
        return _neutral(name, 'HANDOFF', 'ORIGINAL_READ_INTENT_UNCERTAIN')
    timeout = min(config['limits']['hard_timeout_seconds'], remaining)
    # Guardian and reader import this reviewed source even when launched from a
    # different cwd. No caller/mission PYTHONPATH is accepted by this boundary.
    prior_pythonpath = os.environ.get('PYTHONPATH')
    os.environ['PYTHONPATH'] = str(ROOT)
    try:
        process = run_bounded([sys.executable, '-B', '-P', '-m', 'universal.host_github'],
                              canonical(binding).encode(), timeout_seconds=timeout, max_output_bytes=16384)
    finally:
        if prior_pythonpath is None:
            os.environ.pop('PYTHONPATH', None)
        else:
            os.environ['PYTHONPATH'] = prior_pythonpath
    _inode_current(config, handle)
    if implementation_sha256() != config['implementation_sha256']:
        raise GuardError('host source drift during read')
    current = scheduler.status(name)
    if any(current[k] != before[k] for k in ('revision', 'fence', 'owner', 'lease_until', 'state')):
        return _finish_read(journal, name, ordinal, _neutral(name, 'HANDOFF', 'OWNER_CHANGED_DURING_READ'))
    provider, provenance, failure = _decode_read(process, binding)
    if failure:
        row = _neutral(name, 'HANDOFF', failure)
        row['reader'] = {'state': process.state, 'cleanup_verified': process.cleanup_verified,
                         'elapsed_seconds': process.elapsed_seconds}
        return _finish_read(journal, name, ordinal, row)
    # No heartbeat is manufactured from provider status/logs. P4 receives a
    # typed, already-finished read at the current time, never a blocking callback.
    if time.monotonic() >= deadline:
        return _finish_read(journal, name, ordinal, _neutral(name, 'HANDOFF', 'HOST_DEADLINE_AFTER_READ'))
    observation_key = 'p4-' + provider.observation_id
    journal._operation('p5-read-identity-' + str(ordinal),
        {'operation': 'p5.read_identity', 'task': name, 'ordinal': ordinal,
         'observation_key': observation_key,
         'provider_sha256': digest(canonical(provider.scheduler_record()))}, lambda at: 'ps-job-' + name)
    verdict = PassiveSupervisor(scheduler).observe_once(name,
        provider_reader=lambda *_: (provider, None), now_unix=int(time.time()),
        deadline_monotonic=deadline)
    row = asdict(verdict)
    row.update(provenance=provenance, reader={'state': process.state,
        'cleanup_verified': process.cleanup_verified, 'elapsed_seconds': process.elapsed_seconds})
    return _finish_read(journal, name, ordinal, row)


def _checkpoint_target(path, config):
    target = private_path(path, existing=False)
    forbidden = {config['journal_path'] + suffix for suffix in ('', '-wal', '-shm', '-journal')}
    if str(target) in forbidden:
        raise GuardError('checkpoint cannot replace original journal')
    if target.exists():
        # Existing arbitrary private files (including config/source) cannot be
        # overwritten. Only a prior, correctly shaped host checkpoint qualifies.
        old = _read(read_private(str(target)))
        if (set(old) != {'schema', 'receipt', 'resume_hint'} or old['schema'] != 1
                or type(old['receipt']) is not dict or type(old['resume_hint']) is not str
                or old['receipt'].get('journal_fingerprint') != hashlib.sha256(config['journal_id'].encode()).hexdigest()):
            raise GuardError('checkpoint destination is not an original host checkpoint')
    return target


def _private_checkpoint(path, value, config):
    target = _checkpoint_target(path, config)
    wire = canonical(value) + '\n'
    if len(wire.encode()) > 16384:
        raise GuardError('private checkpoint exceeds bounded input')
    temporary = target.parent / ('.' + target.name + '.tmp-' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(wire); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def run_host(config, *, once=True, checkpoint=None, resume_hint=None):
    started = time.monotonic()
    validate_config(config)
    deadline = started + config['limits']['max_seconds']
    if checkpoint:
        _checkpoint_target(checkpoint, config)
    with locked_original(config) as (journal, scheduler, handle):
        for task in config['tasks']:
            _status_binding(scheduler.status(task['task_id']), task['binding'])
        if checkpoint:
            # Fail before any GET when the existing P4 resume descriptor cannot
            # represent this explicit selection within its original bound.
            export_resume(scheduler, tuple(t['task_id'] for t in config['tasks']))
        if resume_hint is not None:
            hint = _read(read_private(resume_hint))
            if set(hint) != {'schema', 'receipt', 'resume_hint'} or hint['schema'] != 1:
                raise GuardError('invalid private checkpoint')
            validated = validate_resume(scheduler, hint['resume_hint'])
            if validated.task_ids != tuple(t['task_id'] for t in config['tasks']):
                raise GuardError('resume task selection differs')
        _anchor(journal, config)
        before_budget = scheduler.ready()
        ticks = []
        for _ in range(1 if once else config['limits']['max_ticks']):
            if time.monotonic() >= deadline:
                break
            selection = list(config['tasks'])
            reads = _attempts(journal)
            if reads:
                last = reads[-1]['request']['task']
                index = next((i for i, task in enumerate(selection) if task['task_id'] == last), -1) + 1
                selection = selection[index:] + selection[:index]
            batch = []
            for task in selection:
                row = observe_task(config, journal, scheduler, handle, task, deadline)
                batch.append(row)
                if row['action'] == 'HANDOFF':
                    break
            ticks.append(batch)
            if once or any(row['action'] == 'HANDOFF' for row in batch) or len(ticks) >= config['limits']['max_ticks']:
                break
            pause = min(config['limits']['interval_seconds'], max(0, deadline - time.monotonic()))
            time.sleep(pause)
        _inode_current(config, handle)
        result = {'schema': 1, 'mode': 'READ_ONLY_PUBLIC_SYNTHETIC', 'pid': os.getpid(),
            'implementation_sha256': config['implementation_sha256'],
            'journal_fingerprint': hashlib.sha256(journal.identity.encode()).hexdigest(),
            'ticks': ticks, 'budgets_before': before_budget, 'budgets_after': scheduler.ready(),
            'read_attempts': len(_attempts(journal)), 'read_budget_left': _read_budget(journal, scheduler),
            'elapsed_seconds': time.monotonic() - started, 'execution_authorized': False,
            'remote_writes': False, 'external_scheduler_installed': False}
        if checkpoint:
            compact = {k: result[k] for k in ('pid', 'implementation_sha256', 'journal_fingerprint',
                'read_attempts', 'read_budget_left', 'execution_authorized', 'remote_writes')}
            compact['receipt_sha256'] = digest(canonical(result))
            _private_checkpoint(checkpoint, {'schema': 1, 'receipt': compact,
                'resume_hint': export_resume(scheduler, tuple(t['task_id'] for t in config['tasks']))}, config)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('fingerprint', 'observe-once', 'run'))
    parser.add_argument('--config')
    parser.add_argument('--checkpoint')
    parser.add_argument('--resume-hint')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.operation == 'fingerprint':
            if args.config or args.checkpoint or args.resume_hint:
                raise GuardError('fingerprint takes no private input')
            result = {'implementation_sha256': implementation_sha256()}
        else:
            if not args.config:
                raise GuardError('private config required')
            result = run_host(load_config(args.config), once=args.operation == 'observe-once',
                              checkpoint=args.checkpoint, resume_hint=args.resume_hint)
        print(canonical(result))
        return 0
    except (GuardError, ValueError, KeyError, TypeError, OSError, sqlite3.Error):
        # Whitelisted error only: no paths, SQLite data, raw HTTP or credentials.
        print(canonical({'schema': 1, 'action': 'HANDOFF', 'reason': 'HOST_INPUT_OR_OWNER_REFUSED',
                         'execution_authorized': False, 'remote_writes': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
