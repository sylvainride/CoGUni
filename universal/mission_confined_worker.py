"""Owner-side P30 bridge to the EXISTING sandboxed Python project checker.

This adapter never runs candidate code in the owner interpreter. It may call
only project_runner.run_project_checks, whose children require Linux bwrap,
seccomp and independent owner-defined cases. Returned observations are NOT a
signed GenerativeValidator proof, artifact grant, receipt, or PASS from Chat.
No new store, remote connector, model, or background service is introduced.
"""
from dataclasses import dataclass

from .continuity import ContinuityJournal
from .core import GuardError
from .mission_contracts import canonical, decode_mission, fingerprint
from .project_runner import run_project_checks, validate_project_policy

CRITERIA = frozenset({'tests', 'lint', 'security', 'licenses', 'provenance', 'environment'})


@dataclass(frozen=True)
class ConfinedInspection:
    project_id: str
    run_id: str
    source_sha256: str
    candidate_tree_sha: str | None
    criteria: dict
    observation_state: str
    accepted_for_gate: bool = False
    execution_authorized: bool = False


def _owner_running(journal, task_id, owner, expected_revision, expected_fence, envelope):
    row = journal.get(task_id)
    contract = row['contract']
    if (row['revision'] != expected_revision or row['fence'] != expected_fence
            or row['state'] != 'RUNNING' or row['owner'] != owner
            or row['lease_until'] is None or journal._now() >= row['lease_until']):
        raise GuardError('stale, expired or foreign owner claim', 'BLOCK')
    if (contract['sources'] != {path: envelope['source_sha256']
                               for path in contract['sources']}
            or len(contract['sources']) != 1
            or not journal._sources_current(contract)
            or len(contract['actions']) != 1
            or contract['actions'][0]['tool'] != 'offline_fixture'
            or 'offline synthetic admission only' not in contract['constraints']
            or 'project:' + envelope['project']['id'] not in contract['constraints']
            or 'version:' + envelope['project']['base_version'] not in contract['constraints']
            or 'envelope:' + fingerprint(envelope) not in contract['constraints']):
        raise GuardError('owner source/mission contract mismatch', 'BLOCK')
    if not journal.verify_chain():
        raise GuardError('owner journal chain verification failed', 'BLOCK')
    return row


def inspect_synthetic_candidate(journal, task_id, raw_envelope, files, owner_policy, *,
                                 now_unix, expected_owner, expected_revision,
                                 expected_fence, timeout=3.0):
    """One bounded isolated observation, with after-check lease/CAS revalidation.

    No worker success can call this a validated artifact: the existing
    GenerativeValidator or independent owner oracle remains required later.
    """
    if (type(journal) is not ContinuityJournal or type(task_id) is not str
            or type(expected_owner) is not str or not expected_owner
            or type(expected_revision) is not int or type(expected_fence) is not int):
        raise GuardError('typed owner claim required', 'BLOCK')
    envelope = decode_mission(raw_envelope, now_unix=now_unix)
    spec = envelope['contract']
    if (envelope['project']['kind'] != 'local' or envelope['privacy'] != 'PUBLIC_SYNTHETIC'
            or spec['allowed_actions'] != ['simulate'] or spec['max_external_cost'] != 0
            or spec['artifact_policy'] != 'public_synthetic' or spec['dependencies']):
        raise GuardError('confined synthetic mission only', 'BLOCK')
    original = _owner_running(journal, task_id, expected_owner,
                              expected_revision, expected_fence, envelope)
    # Policy comes from trusted owner; static preflight runs before any child.
    validate_project_policy(owner_policy)
    context = {'task': task_id, 'journal_id': original['journal_id'],
               'mission_id': envelope['mission_id'], 'project_id': envelope['project']['id'],
               'project_version': envelope['project']['base_version'],
               'source_sha256': envelope['source_sha256'],
               'owner_contract_sha': original['contract_sha'],
               'fence': expected_fence, 'revision': expected_revision}
    result = run_project_checks(files, owner_policy, context, timeout=timeout)
    # Observation, not independent signed proof. Discard worker-authored
    # metadata, errors and any unchecked status or self-reported PASS.
    statuses = {name: result['criteria'][name]['outcome'] for name in CRITERIA}
    if not set(statuses.values()) <= {'PASS', 'FAIL', 'UNKNOWN', 'NOT_RUN'}:
        raise GuardError('unexpected checker verdict', 'BLOCK')
    try:
        _owner_running(journal, task_id, expected_owner,
                       expected_revision, expected_fence, envelope)
    except GuardError:
        return ConfinedInspection(envelope['project']['id'], task_id,
                                  envelope['source_sha256'], None,
                                  statuses, 'STALE_AFTER_CHECKS')
    if statuses == {name: 'PASS' for name in CRITERIA}:
        if type(result['tree_sha']) is not str or len(result['tree_sha']) != 40:
            raise GuardError('missing bounded candidate tree', 'BLOCK')
        state = 'CHECKS_OBSERVED_ONLY'
    elif 'NOT_RUN' in statuses.values():
        state = 'NOT_RUN'
    elif 'FAIL' in statuses.values():
        state = 'FAILED_CHECKS'
    else:
        state = 'UNKNOWN'
    return ConfinedInspection(envelope['project']['id'], task_id,
                              envelope['source_sha256'], result['tree_sha'],
                              statuses, state)
