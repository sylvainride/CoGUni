"""Pure sanitized CI metadata contracts. No dispatch, auth or replay store.

Trusted provider observations are supplied by the owner caller. PR bodies,
comments, worker verdicts and integrity hashes never confer authority. Native
mission execution remains disconnected; owner consent has only local scope.
"""
from dataclasses import dataclass, field
import re

from .generative import strict_json
from .core import GuardError


_SHA = re.compile(r'[0-9a-f]{40}\Z')
_EVENT_FIELDS = {'event', 'repo', 'repo_id', 'owner_id', 'actor_id', 'pr',
                 'head_sha', 'base_sha', 'merge_sha', 'tree_sha', 'ref', 'run_id'}
_RECEIPT_FIELDS = {'kind', 'run_id', 'source_commit', 'source_tree', 'criterion', 'outcome', 'scope'}
_CRITERIA = frozenset({'owner-contracts', 'sandbox-runtime'})
_OUTCOMES = frozenset({'PASS', 'FAIL', 'UNKNOWN', 'NOT_RUN', 'STALE'})


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        raise ValueError('invalid source identity')
    return value


def _number(value):
    if type(value) is not int or not 0 < value < 10**15:
        raise ValueError('invalid bounded identifier')
    return value


@dataclass(frozen=True)
class CIEvent:
    pr: int
    run_id: int
    actor_id: int
    head_sha: str
    base_sha: str
    merge_sha: str
    tree_sha: str
    ref: str
    dispatch_authorized: bool = field(default=False, init=False)


def validate_event(event, *, trusted_actor_id, trusted_run_id, trusted_merge_sha,
                   trusted_tree_sha, trusted_head_sha, trusted_base_sha):
    """Validate only sanitized owner PR CI metadata against provider observations.

    This function cannot authenticate the caller's observations. Passing it is
    not an owner grant, a webhook signature, a replay check or mission dispatch.
    """
    if type(event) is not dict or set(event) != _EVENT_FIELDS:
        raise ValueError('unexpected event fields')
    if (type(event['event']) is not str or type(event['repo']) is not str
            or event['event'] != 'pull_request' or event['repo'] != 'sylvainride/CoGUni'
            or type(event['repo_id']) is not int or event['repo_id'] != 1418009675
            or type(event['owner_id']) is not int or event['owner_id'] != 265171248
            or _number(trusted_actor_id) != 265171248 or _number(event['actor_id']) != trusted_actor_id):
        raise ValueError('repository or owner event mismatch')
    pr = _number(event['pr'])
    if type(event['ref']) is not str or event['ref'] != 'refs/pull/' + str(pr) + '/merge':
        raise ValueError('unbound PR merge ref')
    if _number(event['run_id']) != _number(trusted_run_id):
        raise ValueError('run mismatch')
    for field_name, trusted in [('head_sha', trusted_head_sha), ('base_sha', trusted_base_sha),
                                ('merge_sha', trusted_merge_sha), ('tree_sha', trusted_tree_sha)]:
        if _sha(event[field_name]) != _sha(trusted):
            raise ValueError('source observation mismatch')
    return CIEvent(pr, event['run_id'], event['actor_id'], event['head_sha'], event['base_sha'],
                   event['merge_sha'], event['tree_sha'], event['ref'])


def parse_receipt(encoded, *, expected_run_id, expected_commit, expected_tree):
    """Strict inert receipt codec; integrity is not authenticity or acceptance."""
    if type(encoded) is not str or len(encoded) > 4096:
        raise ValueError('receipt exceeds bound')
    try:
        receipt = strict_json(encoded)
    except GuardError:
        raise ValueError('malformed receipt') from None
    if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
        raise ValueError('unexpected receipt fields')
    if (receipt['kind'] != 'CI_OBSERVATION' or receipt['scope'] != 'INERT_OBSERVATION_ONLY'
            or _number(receipt['run_id']) != _number(expected_run_id)
            or _sha(receipt['source_commit']) != _sha(expected_commit)
            or _sha(receipt['source_tree']) != _sha(expected_tree)
            or type(receipt['criterion']) is not str or receipt['criterion'] not in _CRITERIA
            or type(receipt['outcome']) is not str or receipt['outcome'] not in _OUTCOMES):
        raise ValueError('unbound receipt')
    return dict(receipt)
