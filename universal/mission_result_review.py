"""Correlate two synthetic observations without elevating either to proof.

A digest, signed-looking worker receipt, or a PASS-looking checker result is
NOT a GateEngine signature, owner authorization or trusted sender attestation.
This module has no execution, state change, network, lease or external effect.
"""
from dataclasses import dataclass
import re

from .mission_artifacts import inspect_synthetic_artifact
from .mission_confined_worker import ConfinedInspection, CRITERIA
from .mission_contracts import decode_mission, decode_receipt, MissionContractError

_TREE_SHA = re.compile(r'[0-9a-f]{40}\Z')


@dataclass(frozen=True)
class ObservationCorrelation:
    project_id: str
    run_id: str
    source_sha256: str
    candidate_tree_sha: str
    artifact_sha256: str
    artifact_size: int
    state: str = 'OWNER_REVIEW_REQUIRED'
    accepted: bool = False
    application_authorized: bool = False
    evidence_signed: bool = False


def correlate_synthetic_result(inspection, raw_mission, raw_receipt, *, now_unix,
                               owner_run_id, owner_project_version,
                               owner_candidate_tree_sha, root, path):
    """Compare immutable owner pins with scoped observations; no PASS promotion.

    The owner must independently establish the expected tree, run and version;
    this function does NOT authenticate that owner. Caller-supplied forged
    inspection data therefore NEVER becomes a signed or accepted result.
    """
    if type(inspection) is not ConfinedInspection:
        raise MissionContractError('confined-inspection type required')
    if (type(owner_run_id) is not str or not owner_run_id
            or type(owner_project_version) is not str or not owner_project_version
            or type(owner_candidate_tree_sha) is not str
            or not _TREE_SHA.fullmatch(owner_candidate_tree_sha)):
        raise MissionContractError('valid owner version/run/tree pins required')
    mission = decode_mission(raw_mission, now_unix=now_unix)
    receipt = decode_receipt(raw_receipt)
    if (inspection.observation_state != 'CHECKS_OBSERVED_ONLY'
            or inspection.accepted_for_gate is not False
            or inspection.execution_authorized is not False
            or type(inspection.criteria) is not dict
            or set(inspection.criteria) != CRITERIA
            or any(type(value) is not str or value != 'PASS'
                   for value in inspection.criteria.values())
            or inspection.project_id != mission['project']['id']
            or inspection.run_id != owner_run_id
            or receipt['run_id'] != owner_run_id
            or inspection.source_sha256 != mission['source_sha256']
            or inspection.candidate_tree_sha != owner_candidate_tree_sha
            or mission['project']['base_version'] != owner_project_version):
        raise MissionContractError('unqualified or foreign candidate observation')
    artifact = inspect_synthetic_artifact(raw_mission, raw_receipt, now_unix=now_unix,
                                         expected_run_id=owner_run_id,
                                         expected_project_version=owner_project_version,
                                         root=root, path=path)
    return ObservationCorrelation(mission['project']['id'], owner_run_id,
                                  mission['source_sha256'], owner_candidate_tree_sha,
                                  artifact.artifact_sha256, artifact.size)
