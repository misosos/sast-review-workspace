"""Bounded, process-local evidence captured from one Semgrep scan execution.

This module deliberately does not persist or serialize a manifest to the public
API. Semgrep's reported paths are observations, not proof of complete analysis.
"""

from __future__ import annotations

import json
import re
import secrets
import stat
import unicodedata
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


CONTRACT_VERSION = "scan-evidence-manifest/v1"
INVOCATION_ID = "semgrep-json-local-v1"
INVESTIGATION_VERBOSE_INVOCATION_ID = "semgrep-json-investigation-verbose-v1"
RULE_BYTES_INVOCATION_ID = "semgrep-json-investigation-rule-bytes-v1"
ALLOWED_INVOCATION_IDS = frozenset({INVOCATION_ID, INVESTIGATION_VERBOSE_INVOCATION_ID, RULE_BYTES_INVOCATION_ID})
MAX_SCANNED_PATHS = 100_000
MAX_SKIPPED_PATHS = 10_000
MAX_SCOPE_PATH_BYTES = 1_024
MAX_SCOPE_BYTES = 1_048_576
MAX_MANIFEST_BYTES = 1_048_576
MAX_STRUCTURAL_COUNT = 10_000
_SCAN_REF = re.compile(r"\A[A-Za-z0-9_-]{32,64}\Z")
_SAFE_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")
_FINDING_ID = re.compile(r"\Asemgrep:[a-f0-9]{24}\Z")
# Names the adapter itself always excludes (``--exclude``), at any depth: version
# control metadata and installed dependency trees. A target's ignore files cannot
# re-include them. Normal source folders are deliberately absent, including
# build outputs, so nothing is dropped only because Git ignores it.
ADAPTER_EXCLUDED_NAMES = (".git", "node_modules", ".venv")
ADAPTER_POLICY_SKIP_REASON = "adapter_policy_exclusion"
_IGNORE_FILE_SKIP_REASON = "semgrepignore_patterns_match"
_SEMGREP_CLI_EXCLUDE_REASON = "cli_exclude_flags_match"
_KNOWN_SKIP_REASONS = frozenset({_IGNORE_FILE_SKIP_REASON, ADAPTER_POLICY_SKIP_REASON})


class EvidenceStatus(StrEnum):
    OBSERVED = "OBSERVED"
    NOT_COLLECTED = "NOT_COLLECTED"
    UNAVAILABLE = "UNAVAILABLE"
    CONFLICTING = "CONFLICTING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True, slots=True)
class SkippedPathEvidence:
    path: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class ScopeEvidence:
    completeness_status: EvidenceStatus
    paths_object_present: bool | None
    scanned_field_present: bool | None
    scanned_status: EvidenceStatus
    scanned_paths: tuple[str, ...]
    reported_scanned_count: int | None
    skipped_status: EvidenceStatus
    skipped_paths: tuple[SkippedPathEvidence, ...]
    skipped_rules_status: EvidenceStatus
    skipped_rules_count: int | None
    errors_status: EvidenceStatus
    errors_count: int | None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionEvidence:
    engine: str
    status: str
    semgrep_version: str | None
    exit_code: int | None
    invocation_id: str


@dataclass(frozen=True, slots=True)
class RuleEvidence:
    requested_profile_id: str
    selected_rule_file_id: str
    selected_status: EvidenceStatus
    byte_identity_status: EvidenceStatus
    loaded_identity_status: EvidenceStatus


@dataclass(frozen=True, slots=True)
class ScanEvidenceManifest:
    contract_version: str
    scan_ref: str
    target_id: str
    rule_profile_id: str
    semgrep_version: str | None
    scan_status: str
    finding_count: int
    displayed_finding_count: int
    omitted_finding_count: int
    finding_ids: tuple[str, ...]
    execution_evidence: ExecutionEvidence
    rule_evidence: RuleEvidence
    scope_evidence: ScopeEvidence
    limitations: tuple[str, ...]


class ManifestBindingError(ValueError):
    """Raised when evidence is presented for a different request or run."""


def new_scan_ref() -> str:
    """Create a fresh opaque identifier; it is not a durable run registry."""
    return secrets.token_urlsafe(24)


def _is_adapter_excluded_path(path: str) -> bool:
    return path.rsplit("/", 1)[-1] in ADAPTER_EXCLUDED_NAMES


def classify_reported_skip(path: str, semgrep_reason: object) -> str | None:
    """Map one Semgrep-reported skip to a stored reason code, or None when unrecognized.

    A path named like an adapter exclusion is excluded by the adapter whichever
    filter Semgrep credits, so it is recorded as the adapter's policy. Semgrep's
    CLI-exclude reason on any other path was not requested by the adapter and
    stays unrecognized, like every reason outside this closed set.
    """
    if semgrep_reason == _SEMGREP_CLI_EXCLUDE_REASON:
        return ADAPTER_POLICY_SKIP_REASON if _is_adapter_excluded_path(path) else None
    if semgrep_reason == _IGNORE_FILE_SKIP_REASON:
        return ADAPTER_POLICY_SKIP_REASON if _is_adapter_excluded_path(path) else _IGNORE_FILE_SKIP_REASON
    return None


def stored_skip_is_valid(path: object, reason_code: object) -> bool:
    """A stored skip is valid only in the one form ``classify_reported_skip`` produces."""
    if not isinstance(path, str) or not isinstance(reason_code, str) or reason_code not in _KNOWN_SKIP_REASONS:
        return False
    return (reason_code == ADAPTER_POLICY_SKIP_REASON) is _is_adapter_excluded_path(path)


def only_adapter_policy_exclusions(scope: "ScopeEvidence") -> bool:
    """True when every skipped path was validated and is an adapter-owned exclusion."""
    return scope.skipped_status is EvidenceStatus.OBSERVED and all(
        item.reason_code == ADAPTER_POLICY_SKIP_REASON and stored_skip_is_valid(item.path, item.reason_code)
        for item in scope.skipped_paths
    )


def _invalid_scope(
    reason: str,
    *,
    paths_object_present: bool | None,
    scanned_field_present: bool | None,
    scanned_count: int | None = None,
) -> ScopeEvidence:
    return ScopeEvidence(
        completeness_status=EvidenceStatus.UNVERIFIED,
        paths_object_present=paths_object_present,
        scanned_field_present=scanned_field_present,
        scanned_status=EvidenceStatus.UNAVAILABLE,
        scanned_paths=(),
        reported_scanned_count=scanned_count,
        skipped_status=EvidenceStatus.NOT_COLLECTED,
        skipped_paths=(),
        skipped_rules_status=EvidenceStatus.NOT_COLLECTED,
        skipped_rules_count=None,
        errors_status=EvidenceStatus.NOT_COLLECTED,
        errors_count=None,
        limitations=(reason,),
    )


def _safe_relative_path(raw: Any, project_root: Path) -> str | None:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8", errors="surrogatepass")) > MAX_SCOPE_PATH_BYTES:
        return None
    if "\\" in raw or ":" in raw or any(unicodedata.category(char).startswith("C") for char in raw):
        return None
    root = project_root.resolve()
    supplied = Path(raw)
    try:
        if supplied.is_absolute():
            raw_parts = raw.split("/")
            if not raw.startswith("/") or any(part in {"", ".", ".."} for part in raw_parts[1:]):
                return None
            candidate = supplied
        else:
            parts = raw.split("/")
            if any(part in {"", ".", ".."} for part in parts):
                return None
            candidate = root / supplied
        relative = candidate.relative_to(root).as_posix()
    except (OSError, ValueError, RuntimeError):
        return None
    if (
        relative in {"", "."}
        or relative.startswith("../")
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or len(relative.encode("utf-8", errors="surrogatepass")) > MAX_SCOPE_PATH_BYTES
        or any(unicodedata.category(char).startswith("C") for char in relative)
    ):
        return None
    # Refuse currently visible symlink components. This is a bounded path
    # validation step, not a race-free proof of what Semgrep opened.
    current = root
    for part in relative.split("/"):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            break
        except OSError:
            return None
        if stat.S_ISLNK(mode):
            return None
    return relative


def _validate_path_list(
    raw_paths: Any,
    project_root: Path,
    *,
    maximum: int,
    seen_keys: dict[str, str] | None = None,
) -> tuple[tuple[str, ...] | None, str | None, int | None]:
    if not isinstance(raw_paths, list):
        return None, "path_list_structure_invalid", None
    reported_count = len(raw_paths)
    if reported_count > maximum:
        return None, "path_count_limit_exceeded", reported_count
    collected: list[str] = []
    keys = seen_keys if seen_keys is not None else {}
    total_bytes = 0
    for raw in raw_paths:
        path = _safe_relative_path(raw, project_root)
        if path is None:
            return None, "path_value_invalid", reported_count
        key = unicodedata.normalize("NFC", path)
        previous = keys.get(key)
        if previous is not None:
            reason = "duplicate_scanned_path" if previous == path else "normalized_path_collision"
            return None, reason, reported_count
        keys[key] = path
        total_bytes += len(path.encode("utf-8"))
        if total_bytes > MAX_SCOPE_BYTES:
            return None, "scope_byte_limit_exceeded", reported_count
        collected.append(path)
    return tuple(collected), None, reported_count


def parse_scope_evidence(document: dict[str, Any], project_root: Path) -> ScopeEvidence:
    """Extract a bounded allowlisted summary without retaining raw JSON fields."""
    paths_value = document.get("paths")
    paths_present = "paths" in document
    if not paths_present:
        scanned_status = EvidenceStatus.NOT_COLLECTED
        scanned_present: bool | None = False
        scanned_paths: tuple[str, ...] = ()
        scanned_count: int | None = None
        limitations: list[str] = ["semgrep_paths_not_reported"]
    elif not isinstance(paths_value, dict):
        return _invalid_scope(
            "paths_structure_invalid", paths_object_present=True, scanned_field_present=None
        )
    else:
        scanned_present = "scanned" in paths_value
        if not scanned_present:
            scanned_status = EvidenceStatus.NOT_COLLECTED
            scanned_paths = ()
            scanned_count = None
            limitations = ["scanned_paths_not_reported"]
        else:
            validated, error, scanned_count = _validate_path_list(
                paths_value.get("scanned"), project_root, maximum=MAX_SCANNED_PATHS
            )
            if error is not None or validated is None:
                return _invalid_scope(
                    error or "scanned_paths_invalid",
                    paths_object_present=True,
                    scanned_field_present=True,
                    scanned_count=scanned_count,
                )
            scanned_status = EvidenceStatus.OBSERVED
            scanned_paths = validated
            limitations = ["scanned_paths_do_not_prove_complete_analysis"]

    skipped_status = EvidenceStatus.NOT_COLLECTED
    skipped_paths: tuple[SkippedPathEvidence, ...] = ()
    if isinstance(paths_value, dict) and "skipped" in paths_value:
        raw_skipped = paths_value.get("skipped")
        if not isinstance(raw_skipped, list) or len(raw_skipped) > MAX_SKIPPED_PATHS:
            skipped_status = EvidenceStatus.UNAVAILABLE
            limitations.append("skipped_paths_structure_or_count_invalid")
        else:
            skipped_result: list[SkippedPathEvidence] = []
            keys = {unicodedata.normalize("NFC", item): item for item in scanned_paths}
            total_bytes = sum(len(item.encode("utf-8")) for item in scanned_paths)
            invalid_reason: str | None = None
            for item in raw_skipped:
                if not isinstance(item, dict):
                    invalid_reason = "skipped_path_structure_invalid"
                    break
                path = _safe_relative_path(item.get("path"), project_root)
                reason = item.get("reason")
                if path is None:
                    invalid_reason = "skipped_path_invalid"
                    break
                reason_code = classify_reported_skip(path, reason)
                if reason_code is None:
                    invalid_reason = "skipped_reason_unrecognized"
                    break
                key = unicodedata.normalize("NFC", path)
                if key in keys:
                    invalid_reason = "scanned_skipped_path_collision"
                    break
                keys[key] = path
                total_bytes += len(path.encode("utf-8"))
                if total_bytes > MAX_SCOPE_BYTES:
                    invalid_reason = "scope_byte_limit_exceeded"
                    break
                skipped_result.append(SkippedPathEvidence(path, reason_code))
            if invalid_reason is None:
                skipped_status = EvidenceStatus.OBSERVED
                skipped_paths = tuple(skipped_result)
            else:
                skipped_status = EvidenceStatus.UNAVAILABLE
                limitations.append(invalid_reason)
    elif scanned_status is EvidenceStatus.OBSERVED:
        limitations.append("skip_details_not_collected")

    skipped_rules_status = EvidenceStatus.NOT_COLLECTED
    skipped_rules_count: int | None = None
    if "skipped_rules" in document:
        rules = document.get("skipped_rules")
        if isinstance(rules, list) and len(rules) <= MAX_STRUCTURAL_COUNT:
            skipped_rules_status = EvidenceStatus.OBSERVED
            skipped_rules_count = len(rules)
        else:
            skipped_rules_status = EvidenceStatus.UNAVAILABLE
            limitations.append("skipped_rules_structure_or_count_invalid")

    errors_status = EvidenceStatus.NOT_COLLECTED
    errors_count: int | None = None
    if "errors" in document:
        errors = document.get("errors")
        if isinstance(errors, list) and len(errors) <= MAX_STRUCTURAL_COUNT:
            errors_status = EvidenceStatus.OBSERVED
            errors_count = len(errors)
        else:
            errors_status = EvidenceStatus.UNAVAILABLE
            limitations.append("errors_structure_or_count_invalid")

    return ScopeEvidence(
        completeness_status=EvidenceStatus.UNVERIFIED,
        paths_object_present=paths_present,
        scanned_field_present=scanned_present,
        scanned_status=scanned_status,
        scanned_paths=scanned_paths,
        reported_scanned_count=scanned_count,
        skipped_status=skipped_status,
        skipped_paths=skipped_paths,
        skipped_rules_status=skipped_rules_status,
        skipped_rules_count=skipped_rules_count,
        errors_status=errors_status,
        errors_count=errors_count,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def unavailable_scope_evidence(reason: str) -> ScopeEvidence:
    """Return a closed, non-sensitive state for runs without usable JSON."""
    if not re.fullmatch(r"[a-z_]{1,64}", reason):
        reason = "scope_evidence_unavailable"
    return _invalid_scope(reason, paths_object_present=None, scanned_field_present=None)


def not_collected_scope_evidence(reason: str) -> ScopeEvidence:
    if not re.fullmatch(r"[a-z_]{1,64}", reason):
        reason = "scope_evidence_not_collected"
    return ScopeEvidence(
        completeness_status=EvidenceStatus.UNVERIFIED,
        paths_object_present=None,
        scanned_field_present=None,
        scanned_status=EvidenceStatus.NOT_COLLECTED,
        scanned_paths=(),
        reported_scanned_count=None,
        skipped_status=EvidenceStatus.NOT_COLLECTED,
        skipped_paths=(),
        skipped_rules_status=EvidenceStatus.NOT_COLLECTED,
        skipped_rules_count=None,
        errors_status=EvidenceStatus.NOT_COLLECTED,
        errors_count=None,
        limitations=(reason,),
    )


def create_scan_evidence_manifest(
    *,
    scan_ref: str,
    target_id: str,
    rule_profile_id: str,
    semgrep_version: str | None,
    exit_code: int | None,
    scan_status: str,
    finding_count: int,
    displayed_finding_count: int,
    omitted_finding_count: int,
    finding_ids: tuple[str, ...],
    selected_rule_file_id: str,
    scope_evidence: ScopeEvidence,
    invocation_id: str = INVOCATION_ID,
) -> ScanEvidenceManifest:
    if not _SCAN_REF.fullmatch(scan_ref):
        raise ManifestBindingError("scan_reference_invalid")
    if not _SAFE_ID.fullmatch(target_id) or not _SAFE_ID.fullmatch(rule_profile_id):
        raise ManifestBindingError("scan_context_invalid")
    if not isinstance(invocation_id, str) or invocation_id not in ALLOWED_INVOCATION_IDS:
        raise ManifestBindingError("invocation_id_invalid")
    if any(not _FINDING_ID.fullmatch(item) for item in finding_ids):
        raise ManifestBindingError("finding_reference_invalid")
    if (
        type(finding_count) is not int or type(displayed_finding_count) is not int
        or type(omitted_finding_count) is not int
        or min(finding_count, displayed_finding_count, omitted_finding_count) < 0
        or displayed_finding_count != len(finding_ids)
        or finding_count != displayed_finding_count + omitted_finding_count
    ):
        raise ManifestBindingError("finding_count_binding_invalid")
    if not re.fullmatch(r"[a-z0-9_]{1,64}", scan_status):
        raise ManifestBindingError("scan_status_invalid")
    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", selected_rule_file_id):
        raise ManifestBindingError("rule_file_reference_invalid")
    if semgrep_version is not None and not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", semgrep_version):
        semgrep_version = None

    def build(scope: ScopeEvidence) -> ScanEvidenceManifest:
        final_limitations = [
            *scope.limitations,
            "rule_bytes_identity_unverified",
            "semgrep_loaded_rule_identity_unverified",
            "source_snapshot_not_collected",
        ]
        return ScanEvidenceManifest(
            contract_version=CONTRACT_VERSION,
            scan_ref=scan_ref,
            target_id=target_id,
            rule_profile_id=rule_profile_id,
            semgrep_version=semgrep_version,
            scan_status=scan_status,
            finding_count=finding_count,
            displayed_finding_count=displayed_finding_count,
            omitted_finding_count=omitted_finding_count,
            finding_ids=tuple(finding_ids),
            execution_evidence=ExecutionEvidence(
                engine="semgrep",
                status=scan_status,
                semgrep_version=semgrep_version,
                exit_code=exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None,
                invocation_id=invocation_id,
            ),
            rule_evidence=RuleEvidence(
                requested_profile_id=rule_profile_id,
                selected_rule_file_id=selected_rule_file_id,
                selected_status=EvidenceStatus.OBSERVED,
                byte_identity_status=EvidenceStatus.UNVERIFIED,
                loaded_identity_status=EvidenceStatus.UNVERIFIED,
            ),
            scope_evidence=scope,
            limitations=tuple(dict.fromkeys(final_limitations)),
        )

    manifest = build(scope_evidence)
    encoded_size = len(json.dumps(asdict(manifest), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    if encoded_size > MAX_MANIFEST_BYTES:
        manifest = build(unavailable_scope_evidence("manifest_byte_limit_exceeded"))
    return manifest


def validate_manifest_binding(
    manifest: ScanEvidenceManifest,
    scan_ref: str,
    target_id: str,
    rule_profile_id: str,
) -> None:
    if (
        manifest.contract_version != CONTRACT_VERSION
        or manifest.scan_ref != scan_ref
        or manifest.target_id != target_id
        or manifest.rule_profile_id != rule_profile_id
        or manifest.rule_evidence.requested_profile_id != rule_profile_id
    ):
        raise ManifestBindingError("manifest_binding_mismatch")
