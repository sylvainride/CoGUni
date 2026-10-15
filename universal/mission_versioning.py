"""Deterministic, untrusted offline mission bundle portability without import effects.

An integrity digest is not an authenticated signature. Import only returns
validated values. It cannot overwrite the owner journal, grant capabilities,
renew leases, publish, or authorize remote work. A trusted owner must separately
check scope and source pins before admitting any imported mission.
"""
from .mission_contracts import (
    _read, canonical, decode_mission, decode_receipt, decode_event,
    fingerprint, MissionContractError,
)

MAX_BUNDLE_BYTES = 16384  # Same strict bound as shared JSON decoder.
MAX_RECORDS = 16
_KINDS = {'mission': decode_mission, 'receipt': decode_receipt, 'event': decode_event}


def _validated_records(records, now_unix):
    if type(records) is not list or not 1 <= len(records) <= MAX_RECORDS:
        raise MissionContractError('invalid bundle record count')
    result = []
    roots = set()
    receipts = set()
    events = set()
    mission_pins = {}
    for item in records:
        if type(item) is not dict or set(item) != {'kind', 'value'}:
            raise MissionContractError('unexpected record fields')
        kind, value = item['kind'], item['value']
        if type(kind) is not str or kind not in _KINDS or type(value) is not dict:
            raise MissionContractError('invalid record kind or body')
        if kind == 'mission':
            checked = decode_mission(canonical(value), now_unix=now_unix)
        else:
            checked = _KINDS[kind](canonical(value))
        key = checked['mission_id']
        pin = checked['source_sha256']
        if key in mission_pins and mission_pins[key] != pin:
            raise MissionContractError('same mission has inconsistent source')
        mission_pins[key] = pin
        if kind == 'mission':
            if key in roots:
                raise MissionContractError('duplicate mission')
            roots.add(key)
        elif kind == 'receipt':
            receipt_key = (key, checked['run_id'])
            if receipt_key in receipts:
                raise MissionContractError('duplicate run receipt')
            receipts.add(receipt_key)
        else:
            ev = (key, checked['run_id'], checked['event_seq'])
            if ev in events:
                raise MissionContractError('duplicate run event')
            events.add(ev)
        result.append({'kind': kind, 'value': checked})
    if len(roots) != 1:
        raise MissionContractError('exactly one mission envelope required')
    mission = next(x['value'] for x in result if x['kind'] == 'mission')
    if any(x['value']['mission_id'] != mission['mission_id'] for x in result):
        raise MissionContractError('bundle splices missions')
    for item in result:
        obj = item['value']
        if item['kind'] == 'receipt' and obj['project_id'] != mission['project']['id']:
            raise MissionContractError('receipt project mismatch')
        if item['kind'] == 'event' and obj.get('project_id', mission['project']['id']) != mission['project']['id']:
            raise MissionContractError('event project mismatch')
    return result


def export_offline_bundle(records, *, now_unix):
    """Export pure canonical bytes. No persistence, no live admission."""
    validated = _validated_records(records, now_unix)
    body = {'schema_version': 1, 'format': 'coguni-offline-fixture-bundle-v1',
            'authority': 'NONE', 'records': validated}
    bundle = {**body, 'digest': fingerprint(body)}
    wire = canonical(bundle)
    if len(wire) > MAX_BUNDLE_BYTES:
        raise MissionContractError('bundle exceeds hard byte limit')
    return wire


def import_offline_bundle(raw, *, now_unix, existing_mission_ids=()):
    """Validate immutable bundle only; never overwrite existing owner records."""
    if type(raw) not in (str, bytes):
        raise MissionContractError('invalid bundle byte input')
    data = raw.encode('utf-8') if type(raw) is str else raw
    if not 0 < len(data) <= MAX_BUNDLE_BYTES:
        raise MissionContractError('bundle exceeds hard byte limit')
    value = _read(data)
    if set(value) != {'schema_version', 'format', 'authority', 'records', 'digest'}:
        raise MissionContractError('unexpected bundle fields')
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['format'] != 'coguni-offline-fixture-bundle-v1'
            or value['authority'] != 'NONE'):
        raise MissionContractError('unsupported bundle version or authority')
    if type(value['digest']) is not str or value['digest'] != fingerprint({k:v for k,v in value.items() if k != 'digest'}):
        raise MissionContractError('bundle integrity mismatch')
    records = _validated_records(value['records'], now_unix)
    if type(existing_mission_ids) not in (set, frozenset, tuple, list) or any(type(x) is not str for x in existing_mission_ids):
        raise MissionContractError('invalid owner-existing identity set')
    mission = next(item['value'] for item in records if item['kind'] == 'mission')
    if mission['mission_id'] in existing_mission_ids:
        raise MissionContractError('existing mission cannot be overwritten')
    # The result is data, not a lease, token, authorizer, importer, or verifier.
    return records
