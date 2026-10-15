"""Minimal non-authoritative log projections for offline synthetic observations.

Only allowlisted, bounded fields leave this interface. A hash/truncated run
label is *not* anonymous against exhaustive guesses and must not be published
without owner review. Raw provider IDs, proofs and arbitrary errors are omitted.
"""
import hashlib

from .mission_contracts import decode_receipt, MissionContractError
from .mission_liveness import Observation, classify


def _tag(run_id):
    if type(run_id) is not str or not 1 <= len(run_id) <= 96:
        raise MissionContractError('invalid run identity')
    return hashlib.sha256(run_id.encode('utf-8')).hexdigest()[:16]


def redacted_receipt(raw):
    """Whitelisted projection only; claimed status never means validated PASS."""
    record = decode_receipt(raw)
    return {
        'schema_version': 1, 'scope': 'SYNTHETIC_LOG_ONLY_NO_AUTHORITY',
        'run_tag': _tag(record['run_id']),
        'reported_result_state': record['result_state'],
        'reported_application_status': record['application_status'],
        'verification_state': 'UNVERIFIED_INPUT',
        'publication_authorized': False,
    }


def redacted_liveness(observation):
    """Do not echo worker/provider text or trust-flag declarations into logs."""
    if type(observation) is not Observation:
        raise MissionContractError('typed synthetic observation required')
    signal = classify(observation)
    return {
        'schema_version': 1, 'scope': 'SYNTHETIC_LOG_ONLY_NO_AUTHORITY',
        'run_tag': _tag(observation.run_id),
        'reported_liveness': signal.state,
        'effect_retry_authorized': False,
        'cancellation_authorized': False,
    }
