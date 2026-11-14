"""Internal, conservative comparison of run-bound scan evidence.

This module reports response-set differences and bounded execution observations.
It does not determine whether code changed or a vulnerability was fixed.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Final

from ai_code_security_analyzer.api.schemas import ScanResponse
from ai_code_security_analyzer.scan_evidence_manifest import (
    CONTRACT_VERSION as MANIFEST_CONTRACT_VERSION,
    MAX_SCANNED_PATHS,
    MAX_SKIPPED_PATHS,
    MAX_SCOPE_PATH_BYTES,
    MAX_SCOPE_BYTES,
    ALLOWED_INVOCATION_IDS,
    EvidenceStatus,
    ExecutionEvidence,
    RuleEvidence,
    ScanEvidenceManifest,
    ScopeEvidence,
    SkippedPathEvidence,
    stored_skip_is_valid,
)
from ai_code_security_analyzer.semgrep_adapter import ScanStatus


EVALUATION_CONTRACT_VERSION: Final = "finding-disappearance-evaluation/v1"
MAX_EVALUATION_FINDINGS: Final = 100
MAX_EVALUATION_BYTES: Final = 262_144
_SCAN_REF = re.compile(r"\A[A-Za-z0-9_-]{32,64}\Z")
_SAFE_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")
_FINDING_ID = re.compile(r"\Asemgrep:[a-f0-9]{24}\Z")
_SEMVER = re.compile(r"\A\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z")
_RULE_FILE_ID = re.compile(r"\A[A-Za-z0-9_./-]{1,128}\Z")


class AssessmentStatus(StrEnum):
    """Status of an observation, hypothesis, or aggregate assessment."""

    COMPARABLE = "COMPARABLE"
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNDETERMINED = "UNDETERMINED"
    INCOMPARABLE = "INCOMPARABLE"
    EXPLANATION_SUPPORTED = "EXPLANATION_SUPPORTED"
    MULTIPLE_EXPLANATIONS_POSSIBLE = "MULTIPLE_EXPLANATIONS_POSSIBLE"


class FindingCategory(StrEnum):
    CURRENT_ONLY = "currentOnly"
    SHARED = "shared"
    BASELINE_ONLY = "baselineOnly"


class PathObservation(StrEnum):
    PATH_REPORTED_SCANNED = "PATH_REPORTED_SCANNED"
    PATH_EXPLICITLY_SKIPPED = "PATH_EXPLICITLY_SKIPPED"
    PATH_NOT_REPORTED = "PATH_NOT_REPORTED"
    SKIP_EVIDENCE_NOT_COLLECTED = "SKIP_EVIDENCE_NOT_COLLECTED"
    SCOPE_EVIDENCE_UNAVAILABLE = "SCOPE_EVIDENCE_UNAVAILABLE"
    FINDING_PATH_UNAVAILABLE = "FINDING_PATH_UNAVAILABLE"
    CONFLICTING = "CONFLICTING"


class LimitationCode(StrEnum):
    SCAN_CONTEXT_MISMATCH = "scan_context_mismatch"
    SCAN_REFERENCE_COLLISION = "scan_reference_collision"
    MANIFEST_BINDING_INVALID = "manifest_binding_invalid"
    RESPONSE_MANIFEST_BINDING_INVALID = "response_manifest_binding_invalid"
    DUPLICATE_FINDING_ID = "duplicate_finding_id"
    FINDING_ID_NOT_OBSERVED = "finding_id_not_observed"
    SCAN_INCOMPLETE = "scan_incomplete"
    FINDING_OMITTED = "finding_omitted"
    RULE_BYTES_UNVERIFIED = "rule_bytes_unverified"
    LOADED_RULE_IDENTITY_UNVERIFIED = "loaded_rule_identity_unverified"
    SOURCE_SNAPSHOT_NOT_COLLECTED = "source_snapshot_not_collected"
    SCOPE_COMPLETENESS_UNVERIFIED = "scope_completeness_unverified"
    PATH_REPORTED_SCANNED = "path_reported_scanned"
    PATH_EXPLICITLY_SKIPPED = "path_explicitly_skipped"
    PATH_NOT_REPORTED = "path_not_reported"
    SKIP_DETAILS_NOT_COLLECTED = "skip_details_not_collected"
    SCOPE_EVIDENCE_UNAVAILABLE = "scope_evidence_unavailable"
    FINDING_PATH_UNAVAILABLE = "finding_path_unavailable"
    SCANNED_SKIPPED_PATH_CONFLICT = "scanned_skipped_path_conflict"
    EVALUATION_OUTPUT_LIMIT_EXCEEDED = "evaluation_output_limit_exceeded"
    SCAN_RESULT_IS_NOT_SAFETY_PROOF = "scan_result_is_not_safety_proof"


class BundleBindingError(ValueError):
    """Raised when one response and manifest do not describe the same run."""


@dataclass(frozen=True, slots=True)
class RunEvidenceBundle:
    """A response/manifest pair retained by a trusted in-process caller.

    ScanResponse intentionally has no scan_ref. Thus this Python object is not
    a portable proof of provenance: callers must create it immediately from
    the tuple returned by ScanService._scan_with_manifest(). The checks below
    detect accidental or inconsistent pairing, not a malicious in-process
    caller forging both values.
    """

    response: ScanResponse
    manifest: ScanEvidenceManifest


@dataclass(frozen=True, slots=True)
class FindingEvaluation:
    finding_id: str
    category: FindingCategory
    path_observation: PathObservation | None
    skip_hypothesis: AssessmentStatus | None
    source_snapshot_hypothesis: AssessmentStatus | None
    rule_identity_hypothesis: AssessmentStatus | None


@dataclass(frozen=True, slots=True)
class FindingDisappearanceEvaluation:
    contract_version: str
    comparability: AssessmentStatus
    overall_assessment: AssessmentStatus
    findings: tuple[FindingEvaluation, ...]
    limitation_codes: tuple[str, ...]


def bind_run_evidence(
    response: ScanResponse, manifest: ScanEvidenceManifest
) -> RunEvidenceBundle:
    """Validate the response/manifest binding and return an immutable pair."""
    if not _bundle_is_valid(response, manifest):
        raise BundleBindingError("run_evidence_binding_invalid")
    return RunEvidenceBundle(response=response, manifest=manifest)


def _safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if (
        len(encoded) > MAX_SCOPE_PATH_BYTES
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        return False
    parts = value.split("/")
    return not any(part in {"", ".", ".."} for part in parts)


def _valid_unique_paths(paths: object, maximum: int) -> bool:
    if not isinstance(paths, tuple) or len(paths) > maximum:
        return False
    normalized: set[str] = set()
    total_bytes = 0
    for path in paths:
        if not _safe_relative_path(path):
            return False
        key = unicodedata.normalize("NFC", path)
        if key in normalized:
            return False
        normalized.add(key)
        total_bytes += len(path.encode("utf-8"))
        if total_bytes > MAX_SCOPE_BYTES:
            return False
    return True


def _scope_is_valid(scope: object) -> bool:
    if not isinstance(scope, ScopeEvidence):
        return False
    if not isinstance(scope.completeness_status, EvidenceStatus):
        return False
    # C1 never verifies full scope completeness; do not accept a silently
    # escalated status from a replaced or hand-constructed dataclass.
    if scope.completeness_status is not EvidenceStatus.UNVERIFIED:
        return False
    if not isinstance(scope.scanned_status, EvidenceStatus) or not isinstance(scope.skipped_status, EvidenceStatus):
        return False
    supported_scope_states = {
        EvidenceStatus.OBSERVED,
        EvidenceStatus.NOT_COLLECTED,
        EvidenceStatus.UNAVAILABLE,
    }
    if scope.scanned_status not in supported_scope_states or scope.skipped_status not in supported_scope_states:
        return False
    if scope.paths_object_present is not None and type(scope.paths_object_present) is not bool:
        return False
    if scope.scanned_field_present is not None and type(scope.scanned_field_present) is not bool:
        return False
    if scope.reported_scanned_count is not None and (
        type(scope.reported_scanned_count) is not int or not 0 <= scope.reported_scanned_count <= 2_000_000
    ):
        return False
    if scope.scanned_status is EvidenceStatus.OBSERVED:
        if scope.paths_object_present is not True or scope.scanned_field_present is not True:
            return False
        if not _valid_unique_paths(scope.scanned_paths, MAX_SCANNED_PATHS):
            return False
        if type(scope.reported_scanned_count) is not int or scope.reported_scanned_count != len(scope.scanned_paths):
            return False
    elif scope.scanned_paths or scope.scanned_status in {EvidenceStatus.CONFLICTING, EvidenceStatus.UNVERIFIED}:
        return False
    if scope.skipped_status is EvidenceStatus.OBSERVED:
        if not isinstance(scope.skipped_paths, tuple) or len(scope.skipped_paths) > MAX_SKIPPED_PATHS:
            return False
        seen: set[str] = set()
        total_bytes = 0
        for item in scope.skipped_paths:
            if not isinstance(item, SkippedPathEvidence):
                return False
            if not _safe_relative_path(item.path) or not stored_skip_is_valid(item.path, item.reason_code):
                return False
            key = unicodedata.normalize("NFC", item.path)
            if key in seen:
                return False
            seen.add(key)
            total_bytes += len(item.path.encode("utf-8"))
            if total_bytes > MAX_SCOPE_BYTES:
                return False
    elif scope.skipped_paths:
        return False
    for status, count in (
        (scope.skipped_rules_status, scope.skipped_rules_count),
        (scope.errors_status, scope.errors_count),
    ):
        if not isinstance(status, EvidenceStatus):
            return False
        if count is not None and (type(count) is not int or not 0 <= count <= 10_000):
            return False
        if status is EvidenceStatus.OBSERVED and count is None:
            return False
        if status is not EvidenceStatus.OBSERVED and count is not None:
            return False
    if not isinstance(scope.limitations, tuple) or len(scope.limitations) > 64:
        return False
    if any(not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code) for code in scope.limitations):
        return False
    return True


def _manifest_is_valid(manifest: object) -> bool:
    if not isinstance(manifest, ScanEvidenceManifest):
        return False
    if not isinstance(manifest.execution_evidence, ExecutionEvidence):
        return False
    if not isinstance(manifest.rule_evidence, RuleEvidence):
        return False
    if manifest.contract_version != MANIFEST_CONTRACT_VERSION:
        return False
    if not isinstance(manifest.scan_ref, str) or not _SCAN_REF.fullmatch(manifest.scan_ref):
        return False
    if not isinstance(manifest.target_id, str) or not _SAFE_ID.fullmatch(manifest.target_id):
        return False
    if not isinstance(manifest.rule_profile_id, str) or not _SAFE_ID.fullmatch(manifest.rule_profile_id):
        return False
    if manifest.rule_evidence.requested_profile_id != manifest.rule_profile_id:
        return False
    if not isinstance(manifest.rule_evidence.selected_rule_file_id, str) or not _RULE_FILE_ID.fullmatch(
        manifest.rule_evidence.selected_rule_file_id
    ):
        return False
    if (
        manifest.rule_evidence.selected_rule_file_id.startswith("/")
        or "\\" in manifest.rule_evidence.selected_rule_file_id
        or any(part in {"", ".", ".."} for part in manifest.rule_evidence.selected_rule_file_id.split("/"))
    ):
        return False
    if manifest.rule_evidence.selected_status is not EvidenceStatus.OBSERVED:
        return False
    if manifest.rule_evidence.byte_identity_status is not EvidenceStatus.UNVERIFIED:
        return False
    if manifest.rule_evidence.loaded_identity_status is not EvidenceStatus.UNVERIFIED:
        return False
    if manifest.execution_evidence.engine != "semgrep":
        return False
    if not isinstance(manifest.execution_evidence.invocation_id, str) or manifest.execution_evidence.invocation_id not in ALLOWED_INVOCATION_IDS:
        return False
    if manifest.execution_evidence.exit_code is not None and (
        type(manifest.execution_evidence.exit_code) is not int
        or not -255 <= manifest.execution_evidence.exit_code <= 255
    ):
        return False
    if manifest.execution_evidence.status != manifest.scan_status:
        return False
    if manifest.semgrep_version is not None and (
        not isinstance(manifest.semgrep_version, str) or not _SEMVER.fullmatch(manifest.semgrep_version)
    ):
        return False
    if manifest.execution_evidence.semgrep_version != manifest.semgrep_version:
        return False
    if not _scope_is_valid(manifest.scope_evidence):
        return False
    if (
        not isinstance(manifest.finding_ids, tuple)
        or len(manifest.finding_ids) > 50
        or any(not isinstance(item, str) or not _FINDING_ID.fullmatch(item) for item in manifest.finding_ids)
        or len(set(manifest.finding_ids)) != len(manifest.finding_ids)
    ):
        return False
    known_manifest_limitations = {
        "rule_bytes_identity_unverified", "semgrep_loaded_rule_identity_unverified",
        "source_snapshot_not_collected", "scanned_paths_do_not_prove_complete_analysis",
        "skip_details_not_collected",
        "semgrep_paths_not_reported", "scanned_paths_not_reported", "paths_structure_invalid",
        "path_list_structure_invalid", "path_count_limit_exceeded", "path_value_invalid",
        "duplicate_scanned_path", "normalized_path_collision", "scope_byte_limit_exceeded",
        "scanned_paths_invalid", "scanned_skipped_path_collision", "skipped_paths_structure_or_count_invalid",
        "skipped_path_structure_invalid", "skipped_path_invalid", "skipped_reason_unrecognized",
        "skipped_rules_structure_or_count_invalid", "errors_structure_or_count_invalid",
        "manifest_byte_limit_exceeded", "adapter_scope_evidence_not_provided", "manifest_capture_failed",
        "scope_evidence_unavailable", "scope_evidence_not_collected", "semgrep_json_not_collected",
        "semgrep_timeout_without_json", "semgrep_output_limit", "invalid_json_after_failed_execution",
        "invalid_json", "scope_capture_failed",
    }
    if not isinstance(manifest.limitations, tuple) or len(manifest.limitations) > 64 or any(
        not isinstance(item, str) or item not in known_manifest_limitations for item in manifest.limitations
    ):
        return False
    try:
        ScanStatus(manifest.scan_status)
    except (TypeError, ValueError):
        return False
    return True


def _response_matches_manifest(response: object, manifest: object) -> bool:
    if not isinstance(response, ScanResponse) or not isinstance(manifest, ScanEvidenceManifest):
        return False
    if response.semgrep_version != manifest.semgrep_version:
        return False
    if response.scan_status.value != manifest.scan_status:
        return False
    if response.completed is not (response.scan_status is ScanStatus.COMPLETED):
        return False
    if (
        response.finding_count != manifest.finding_count
        or response.displayed_finding_count != manifest.displayed_finding_count
        or response.omitted_finding_count != manifest.omitted_finding_count
        or response.displayed_finding_count != len(response.findings)
        or response.finding_count != response.displayed_finding_count + response.omitted_finding_count
    ):
        return False
    response_ids = tuple(item.finding_id for item in response.findings)
    if response_ids != manifest.finding_ids:
        return False
    if len(set(response_ids)) != len(response_ids) or any(not _FINDING_ID.fullmatch(item) for item in response_ids):
        return False
    return True


def _bundle_is_valid(response: object, manifest: object) -> bool:
    return _manifest_is_valid(manifest) and _response_matches_manifest(response, manifest)


def _path_observation(finding_path: str | None, scope: ScopeEvidence) -> PathObservation:
    if finding_path is None:
        return PathObservation.FINDING_PATH_UNAVAILABLE
    if not _safe_relative_path(finding_path):
        return PathObservation.SCOPE_EVIDENCE_UNAVAILABLE
    scanned_paths = scope.scanned_paths if scope.scanned_status is EvidenceStatus.OBSERVED else ()
    skipped_paths = tuple(item.path for item in scope.skipped_paths)
    scanned_keys = {unicodedata.normalize("NFC", path) for path in scanned_paths}
    skipped_keys = {unicodedata.normalize("NFC", path) for path in skipped_paths}
    if scanned_keys & skipped_keys:
        return PathObservation.CONFLICTING
    scanned = finding_path in scanned_paths
    skipped = scope.skipped_status is EvidenceStatus.OBSERVED and finding_path in skipped_paths
    if scanned:
        return PathObservation.PATH_REPORTED_SCANNED
    if skipped:
        return PathObservation.PATH_EXPLICITLY_SKIPPED
    if scope.scanned_status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.NOT_COLLECTED}:
        return PathObservation.SCOPE_EVIDENCE_UNAVAILABLE
    if scope.skipped_status is EvidenceStatus.UNAVAILABLE:
        return PathObservation.SCOPE_EVIDENCE_UNAVAILABLE
    if scope.skipped_status is EvidenceStatus.NOT_COLLECTED:
        if scope.scanned_status is EvidenceStatus.OBSERVED:
            return PathObservation.SKIP_EVIDENCE_NOT_COLLECTED
        return PathObservation.SCOPE_EVIDENCE_UNAVAILABLE
    return PathObservation.PATH_NOT_REPORTED


def _make_finding_evaluations(
    baseline: RunEvidenceBundle, current: RunEvidenceBundle
) -> tuple[FindingEvaluation, ...]:
    baseline_by_id = {item.finding_id: item for item in baseline.response.findings}
    current_by_id = {item.finding_id: item for item in current.response.findings}
    ids: list[tuple[FindingCategory, str]] = []
    ids.extend((FindingCategory.SHARED, item) for item in sorted(baseline_by_id.keys() & current_by_id.keys()))
    ids.extend((FindingCategory.CURRENT_ONLY, item) for item in sorted(current_by_id.keys() - baseline_by_id.keys()))
    ids.extend((FindingCategory.BASELINE_ONLY, item) for item in sorted(baseline_by_id.keys() - current_by_id.keys()))
    if len(ids) > MAX_EVALUATION_FINDINGS:
        raise OverflowError
    result: list[FindingEvaluation] = []
    for category, finding_id in ids:
        if category is FindingCategory.BASELINE_ONLY:
            observation = _path_observation(
                baseline_by_id[finding_id].file_path, current.manifest.scope_evidence
            )
            if observation is PathObservation.PATH_EXPLICITLY_SKIPPED:
                skip_status = AssessmentStatus.SUPPORTED
            elif observation is PathObservation.PATH_REPORTED_SCANNED:
                skip_status = AssessmentStatus.CONTRADICTED
            elif observation is PathObservation.CONFLICTING:
                skip_status = AssessmentStatus.INCOMPARABLE
            else:
                skip_status = AssessmentStatus.UNDETERMINED
            result.append(FindingEvaluation(
                finding_id, category, observation, skip_status,
                AssessmentStatus.UNDETERMINED, AssessmentStatus.UNDETERMINED,
            ))
        else:
            result.append(FindingEvaluation(finding_id, category, None, None, None, None))
    return tuple(result)


def evaluate_finding_disappearance(
    baseline: RunEvidenceBundle, current: RunEvidenceBundle
) -> FindingDisappearanceEvaluation:
    """Evaluate only run-bound facts; unsupported causal claims stay unknown."""
    if not isinstance(baseline, RunEvidenceBundle) or not isinstance(current, RunEvidenceBundle):
        return _blocked("manifest_binding_invalid")
    if not _manifest_is_valid(baseline.manifest) or not _manifest_is_valid(current.manifest):
        return _blocked("manifest_binding_invalid")
    if not _response_matches_manifest(baseline.response, baseline.manifest) or not _response_matches_manifest(
        current.response, current.manifest
    ):
        return _blocked("response_manifest_binding_invalid")
    if not _bundle_is_valid(baseline.response, baseline.manifest) or not _bundle_is_valid(
        current.response, current.manifest
    ):
        return _blocked("manifest_binding_invalid")
    if baseline.manifest.scan_ref == current.manifest.scan_ref:
        return _blocked("scan_reference_collision")
    if (
        baseline.manifest.target_id != current.manifest.target_id
        or baseline.manifest.rule_profile_id != current.manifest.rule_profile_id
        or baseline.manifest.semgrep_version is None
        or current.manifest.semgrep_version is None
        or baseline.manifest.semgrep_version != current.manifest.semgrep_version
        or baseline.manifest.execution_evidence.invocation_id != current.manifest.execution_evidence.invocation_id
        or baseline.manifest.rule_evidence.selected_rule_file_id
        != current.manifest.rule_evidence.selected_rule_file_id
    ):
        return _blocked("scan_context_mismatch")

    limitation_codes = [
        LimitationCode.RULE_BYTES_UNVERIFIED.value,
        LimitationCode.LOADED_RULE_IDENTITY_UNVERIFIED.value,
        LimitationCode.SOURCE_SNAPSHOT_NOT_COLLECTED.value,
        LimitationCode.SCOPE_COMPLETENESS_UNVERIFIED.value,
        LimitationCode.SCAN_RESULT_IS_NOT_SAFETY_PROOF.value,
    ]
    if (
        baseline.response.scan_status is not ScanStatus.COMPLETED
        or current.response.scan_status is not ScanStatus.COMPLETED
        or not baseline.response.completed
        or not current.response.completed
    ):
        limitation_codes.append(LimitationCode.SCAN_INCOMPLETE.value)
    if baseline.response.omitted_finding_count or current.response.omitted_finding_count:
        limitation_codes.append(LimitationCode.FINDING_OMITTED.value)

    current_scope = current.manifest.scope_evidence
    scope_conflict = (
        current_scope.scanned_status is EvidenceStatus.OBSERVED
        and current_scope.skipped_status is EvidenceStatus.OBSERVED
        and bool(
            {unicodedata.normalize("NFC", path) for path in current_scope.scanned_paths}
            & {unicodedata.normalize("NFC", item.path) for item in current_scope.skipped_paths}
        )
    )
    try:
        findings = _make_finding_evaluations(baseline, current)
    except OverflowError:
        return _blocked("evaluation_output_limit_exceeded")

    for item in findings:
        if item.path_observation is None:
            continue
        if item.category is FindingCategory.BASELINE_ONLY:
            limitation_codes.append(LimitationCode.FINDING_ID_NOT_OBSERVED.value)
        code = {
            PathObservation.PATH_REPORTED_SCANNED: LimitationCode.PATH_REPORTED_SCANNED,
            PathObservation.PATH_EXPLICITLY_SKIPPED: LimitationCode.PATH_EXPLICITLY_SKIPPED,
            PathObservation.PATH_NOT_REPORTED: LimitationCode.PATH_NOT_REPORTED,
            PathObservation.SKIP_EVIDENCE_NOT_COLLECTED: LimitationCode.SKIP_DETAILS_NOT_COLLECTED,
            PathObservation.SCOPE_EVIDENCE_UNAVAILABLE: LimitationCode.SCOPE_EVIDENCE_UNAVAILABLE,
            PathObservation.FINDING_PATH_UNAVAILABLE: LimitationCode.FINDING_PATH_UNAVAILABLE,
            PathObservation.CONFLICTING: LimitationCode.SCANNED_SKIPPED_PATH_CONFLICT,
        }[item.path_observation]
        limitation_codes.append(code.value)

    limitation_codes = list(dict.fromkeys(limitation_codes))
    incomplete = LimitationCode.SCAN_INCOMPLETE.value in limitation_codes or LimitationCode.FINDING_OMITTED.value in limitation_codes
    conflict = scope_conflict or LimitationCode.SCANNED_SKIPPED_PATH_CONFLICT.value in limitation_codes
    if scope_conflict and LimitationCode.SCANNED_SKIPPED_PATH_CONFLICT.value not in limitation_codes:
        limitation_codes.append(LimitationCode.SCANNED_SKIPPED_PATH_CONFLICT.value)
    baseline_only = [item for item in findings if item.category is FindingCategory.BASELINE_ONLY]
    if incomplete or conflict:
        overall = AssessmentStatus.INCOMPARABLE
        comparability = AssessmentStatus.INCOMPARABLE
    else:
        comparability = AssessmentStatus.COMPARABLE
        if baseline_only and all(item.skip_hypothesis is AssessmentStatus.SUPPORTED for item in baseline_only):
            overall = AssessmentStatus.EXPLANATION_SUPPORTED
        else:
            overall = AssessmentStatus.UNDETERMINED

    result = FindingDisappearanceEvaluation(
        contract_version=EVALUATION_CONTRACT_VERSION,
        comparability=comparability,
        overall_assessment=overall,
        findings=findings,
        limitation_codes=tuple(limitation_codes),
    )
    if _evaluation_size(result) > MAX_EVALUATION_BYTES:
        return _blocked("evaluation_output_limit_exceeded")
    return result


def _blocked(code: str) -> FindingDisappearanceEvaluation:
    allowed = {item.value for item in LimitationCode}
    safe_code = code if code in allowed else LimitationCode.MANIFEST_BINDING_INVALID.value
    return FindingDisappearanceEvaluation(
        EVALUATION_CONTRACT_VERSION,
        AssessmentStatus.INCOMPARABLE,
        AssessmentStatus.INCOMPARABLE,
        (),
        (safe_code,),
    )


def _evaluation_size(result: FindingDisappearanceEvaluation) -> int:
    return len(json.dumps(asdict(result), ensure_ascii=True, separators=(",", ":")).encode("utf-8"))
