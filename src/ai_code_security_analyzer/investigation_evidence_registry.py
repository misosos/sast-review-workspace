"""Bounded process-local lifecycle for trusted scan evidence.

Handles locate in-memory records; they are not authentication credentials.
The module is intentionally private to the API process and exposes no route.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Callable

from pydantic import ValidationError

from ai_code_security_analyzer.api.schemas import ScanResponse
from ai_code_security_analyzer.finding_disappearance_evaluator import (
    FindingDisappearanceEvaluation,
    RunEvidenceBundle,
    bind_run_evidence,
    evaluate_finding_disappearance,
)
from ai_code_security_analyzer.scan_evidence_manifest import (
    ALLOWED_INVOCATION_IDS,
    CONTRACT_VERSION as MANIFEST_VERSION,
    MAX_MANIFEST_BYTES,
    EvidenceStatus,
    ExecutionEvidence,
    RuleEvidence,
    ScanEvidenceManifest,
    ScopeEvidence,
    SkippedPathEvidence,
)
from ai_code_security_analyzer.rule_bytes_identity import (
    RULE_BYTES_INVOCATION_ID,
    RULE_BYTES_OBSERVATION_VERSION,
    RuleBytesComparison,
    RuleBytesObservation,
)


CONTRACT_VERSION = "investigation-evidence-registry/v1"
MAX_RUN_HANDLE_CHARS = 64
MAX_RUN_HANDLE_BYTES = 32
MAX_RUNS = 4
MAX_SESSIONS = 2
RUN_TTL_SECONDS = 900.0
SESSION_TTL_SECONDS = 900.0
# The measured max-valid ScanResponse (~213 KiB) plus C1's 1 MiB manifest
# fits a 1.25 MiB record. Four such records plus metadata fit a 5.25 MiB cap.
MAX_RUN_RECORD_BYTES = 1_310_720  # 1.25 MiB
MAX_REGISTRY_BYTES = 5_505_024  # 5.25 MiB
MAX_SESSION_RECORD_BYTES = 8 * 1024
MAX_SESSION_BYTES = 16 * 1024
MAX_EVALUATION_BYTES = 256 * 1024
RULE_BYTES_COMPARISON_VERSION = "rule-bytes-comparison/v1"
MAX_RULE_BYTES_SIDECAR_BYTES = 512
_HANDLE_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
_MANIFEST_LIMITATIONS = frozenset({
    "scanned_paths_do_not_prove_complete_analysis", "scanned_paths_not_reported",
    "semgrep_paths_not_reported", "skip_details_not_collected", "paths_structure_invalid",
    "scanned_paths_invalid", "path_list_structure_invalid", "path_count_limit_exceeded",
    "path_value_invalid", "duplicate_scanned_path", "normalized_path_collision",
    "scope_byte_limit_exceeded", "skipped_paths_structure_or_count_invalid",
    "skipped_path_structure_invalid", "skipped_path_invalid", "skipped_reason_unrecognized",
    "scanned_skipped_path_collision", "skipped_rules_structure_or_count_invalid",
    "errors_structure_or_count_invalid", "manifest_byte_limit_exceeded",
    "scope_evidence_unavailable", "scope_evidence_not_collected",
    "rule_bytes_identity_unverified", "semgrep_loaded_rule_identity_unverified",
    "source_snapshot_not_collected",
    # Reasons recorded when a scan produced no usable scope evidence (timeout,
    # output limit, unparsable output, capture failure). Such a run must reach
    # the evaluator and be judged incomplete, not fail while being read back.
    "semgrep_json_not_collected", "semgrep_timeout_without_json", "semgrep_output_limit",
    "invalid_json_after_failed_execution", "invalid_json", "scope_capture_failed",
    "adapter_scope_evidence_not_provided", "manifest_capture_failed",
})


class RegistryErrorCode(StrEnum):
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    BINDING_REJECTED = "binding_rejected"
    RESOURCE_LIMIT = "resource_limit"
    INTERNAL_UNAVAILABLE = "internal_unavailable"
    EVALUATION_BUSY = "evaluation_busy"


class EvidenceRegistryError(RuntimeError):
    """Fixed, non-sensitive registry failure."""

    def __init__(self, code: RegistryErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class _InvalidWire(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise _InvalidWire("non_finite_number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise _InvalidWire("duplicate_key")
        output[key] = value
    return output


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _exact_keys(value: object, expected: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise _InvalidWire("object_shape_invalid")
    if any(not isinstance(key, str) for key in value):
        raise _InvalidWire("object_key_invalid")
    return value


def _enum(enum_type: type[StrEnum], value: object) -> StrEnum:
    if not isinstance(value, str):
        raise _InvalidWire("enum_invalid")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise _InvalidWire("enum_invalid") from exc


def _strict_int(value: object, *, minimum: int | None = None, maximum: int | None = None) -> int:
    if type(value) is not int or (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        raise _InvalidWire("integer_invalid")
    return value


def _strict_optional_int(value: object, *, minimum: int, maximum: int) -> int | None:
    return None if value is None else _strict_int(value, minimum=minimum, maximum=maximum)


def _strict_optional_bool(value: object) -> bool | None:
    if value is not None and type(value) is not bool:
        raise _InvalidWire("boolean_invalid")
    return value


def _strict_string(value: object, *, maximum: int, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or len(value.encode("utf-8", errors="strict")) > maximum:
        raise _InvalidWire("string_invalid")
    return value


def _string_tuple(value: object, *, maximum_items: int, maximum_item_bytes: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise _InvalidWire("array_invalid")
    result = tuple(_strict_string(item, maximum=maximum_item_bytes) for item in value)
    return tuple(item for item in result if isinstance(item, str))


def _limitation_tuple(value: object) -> tuple[str, ...]:
    items = _string_tuple(value, maximum_items=64, maximum_item_bytes=64)
    if any(item not in _MANIFEST_LIMITATIONS for item in items):
        raise _InvalidWire("limitation_code_invalid")
    return items


def _parse_manifest(raw: object) -> ScanEvidenceManifest:
    top = _exact_keys(raw, {
        "contract_version", "scan_ref", "target_id", "rule_profile_id", "semgrep_version",
        "scan_status", "finding_count", "displayed_finding_count", "omitted_finding_count",
        "finding_ids", "execution_evidence", "rule_evidence", "scope_evidence", "limitations",
    })
    if top["contract_version"] != MANIFEST_VERSION:
        raise _InvalidWire("manifest_version_invalid")
    execution = _exact_keys(top["execution_evidence"], {"engine", "status", "semgrep_version", "exit_code", "invocation_id"})
    rules = _exact_keys(top["rule_evidence"], {"requested_profile_id", "selected_rule_file_id", "selected_status", "byte_identity_status", "loaded_identity_status"})
    scope = _exact_keys(top["scope_evidence"], {
        "completeness_status", "paths_object_present", "scanned_field_present", "scanned_status",
        "scanned_paths", "reported_scanned_count", "skipped_status", "skipped_paths",
        "skipped_rules_status", "skipped_rules_count", "errors_status", "errors_count", "limitations",
    })
    skipped_raw = scope["skipped_paths"]
    if not isinstance(skipped_raw, list) or len(skipped_raw) > 10_000:
        raise _InvalidWire("skipped_paths_invalid")
    skipped = tuple(
        SkippedPathEvidence(
            _strict_string(_exact_keys(item, {"path", "reason_code"})["path"], maximum=1024),
            _strict_string(item["reason_code"], maximum=64),
        )
        for item in skipped_raw
    )
    execution_item = ExecutionEvidence(
        engine=_strict_string(execution["engine"], maximum=64),
        status=_strict_string(execution["status"], maximum=64),
        semgrep_version=_strict_string(execution["semgrep_version"], maximum=64, nullable=True),
        exit_code=_strict_optional_int(execution["exit_code"], minimum=-255, maximum=255),
        invocation_id=_strict_string(execution["invocation_id"], maximum=64),
    )
    if execution_item.invocation_id not in ALLOWED_INVOCATION_IDS:
        raise _InvalidWire("invocation_id_invalid")
    rule_item = RuleEvidence(
        requested_profile_id=_strict_string(rules["requested_profile_id"], maximum=64),
        selected_rule_file_id=_strict_string(rules["selected_rule_file_id"], maximum=128),
        selected_status=_enum(EvidenceStatus, rules["selected_status"]),
        byte_identity_status=_enum(EvidenceStatus, rules["byte_identity_status"]),
        loaded_identity_status=_enum(EvidenceStatus, rules["loaded_identity_status"]),
    )
    scope_item = ScopeEvidence(
        completeness_status=_enum(EvidenceStatus, scope["completeness_status"]),
        paths_object_present=_strict_optional_bool(scope["paths_object_present"]),
        scanned_field_present=_strict_optional_bool(scope["scanned_field_present"]),
        scanned_status=_enum(EvidenceStatus, scope["scanned_status"]),
        scanned_paths=_string_tuple(scope["scanned_paths"], maximum_items=100_000, maximum_item_bytes=1024),
        reported_scanned_count=_strict_optional_int(scope["reported_scanned_count"], minimum=0, maximum=2_000_000),
        skipped_status=_enum(EvidenceStatus, scope["skipped_status"]),
        skipped_paths=skipped,
        skipped_rules_status=_enum(EvidenceStatus, scope["skipped_rules_status"]),
        skipped_rules_count=_strict_optional_int(scope["skipped_rules_count"], minimum=0, maximum=10_000),
        errors_status=_enum(EvidenceStatus, scope["errors_status"]),
        errors_count=_strict_optional_int(scope["errors_count"], minimum=0, maximum=10_000),
        limitations=_limitation_tuple(scope["limitations"]),
    )
    finding_ids = _string_tuple(top["finding_ids"], maximum_items=100, maximum_item_bytes=64)
    return ScanEvidenceManifest(
        contract_version=_strict_string(top["contract_version"], maximum=64),
        scan_ref=_strict_string(top["scan_ref"], maximum=64),
        target_id=_strict_string(top["target_id"], maximum=64),
        rule_profile_id=_strict_string(top["rule_profile_id"], maximum=64),
        semgrep_version=_strict_string(top["semgrep_version"], maximum=64, nullable=True),
        scan_status=_strict_string(top["scan_status"], maximum=64),
        finding_count=_strict_int(top["finding_count"], minimum=0, maximum=2_000_000),
        displayed_finding_count=_strict_int(top["displayed_finding_count"], minimum=0, maximum=50),
        omitted_finding_count=_strict_int(top["omitted_finding_count"], minimum=0, maximum=2_000_000),
        finding_ids=finding_ids,
        execution_evidence=execution_item,
        rule_evidence=rule_item,
        scope_evidence=scope_item,
        limitations=_limitation_tuple(top["limitations"]),
    )


def serialize_run_evidence(bundle: RunEvidenceBundle) -> bytes:
    """Serialize only closed Response/Manifest fields after C2 binding."""
    try:
        validated = bind_run_evidence(bundle.response, bundle.manifest)
        manifest_data = asdict(validated.manifest)
        response_data = validated.response.model_dump(mode="json")
        manifest_bytes = _json_bytes(manifest_data)
        response_bytes = _json_bytes(response_data)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES or len(response_bytes) > 4_194_304:
            raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
        document = {
            "contract_version": CONTRACT_VERSION,
            "response": response_data,
            "manifest": manifest_data,
        }
        payload = _json_bytes(document)
        if len(payload) > MAX_RUN_RECORD_BYTES:
            raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
        return payload
    except EvidenceRegistryError:
        raise
    except Exception as exc:
        raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED) from exc


def deserialize_run_evidence(payload: bytes) -> RunEvidenceBundle:
    """Strictly restore one canonical record and revalidate its C2 binding."""
    if not isinstance(payload, bytes) or len(payload) > MAX_RUN_RECORD_BYTES:
        raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
    try:
        text = payload.decode("utf-8", errors="strict")
        document = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        top = _exact_keys(document, {"contract_version", "response", "manifest"})
        if top["contract_version"] != CONTRACT_VERSION:
            raise _InvalidWire("registry_version_invalid")
        response_bytes = _json_bytes(top["response"])
        manifest_bytes = _json_bytes(top["manifest"])
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise _InvalidWire("manifest_size_invalid")
        response = ScanResponse.model_validate_json(response_bytes, strict=True)
        manifest = _parse_manifest(top["manifest"])
        bundle = bind_run_evidence(response, manifest)
        if _json_bytes({"contract_version": CONTRACT_VERSION, "response": response.model_dump(mode="json"), "manifest": asdict(manifest)}) != payload:
            raise _InvalidWire("canonical_encoding_invalid")
        return bundle
    except EvidenceRegistryError:
        raise
    except Exception as exc:
        raise EvidenceRegistryError(RegistryErrorCode.INTERNAL_UNAVAILABLE) from exc


@dataclass(frozen=True, slots=True)
class _RunRecord:
    scan_ref: str
    handle_digest: bytes
    payload: bytes
    target_id: str
    rule_profile_id: str
    created_at: float
    expires_at: float
    metadata_bytes: int
    rule_bytes_digest: bytes | None = None

    def __repr__(self) -> str:
        return f"_RunRecord(payload_bytes={len(self.payload)}, active=True)"


@dataclass(frozen=True, slots=True)
class _SessionRecord:
    handle_digest: bytes
    investigation_ref: str
    baseline_scan_ref: str
    current_scan_ref: str
    target_id: str
    rule_profile_id: str
    created_at: float
    expires_at: float
    metadata_bytes: int

    def __repr__(self) -> str:
        return "_SessionRecord(active=True)"


@dataclass(frozen=True, slots=True)
class RuleBytesComparisonProjection:
    contract_version: str
    status: RuleBytesComparison
    limitation_codes: tuple[str, ...]


class RunEvidenceRegistry:
    """Thread-safe registry owned by one API app instance."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        run_ttl_seconds: float = RUN_TTL_SECONDS,
        session_ttl_seconds: float = SESSION_TTL_SECONDS,
        max_runs: int = MAX_RUNS,
        max_sessions: int = MAX_SESSIONS,
        max_run_record_bytes: int = MAX_RUN_RECORD_BYTES,
        max_registry_bytes: int = MAX_REGISTRY_BYTES,
        handle_factory: Callable[[], str] = lambda: secrets.token_urlsafe(MAX_RUN_HANDLE_BYTES),
        evaluation_hook: Callable[[], object] | None = None,
    ) -> None:
        if (
            type(run_ttl_seconds) not in {int, float}
            or type(session_ttl_seconds) not in {int, float}
            or not math.isfinite(run_ttl_seconds)
            or not math.isfinite(session_ttl_seconds)
            or run_ttl_seconds <= 0
            or session_ttl_seconds <= 0
            or any(type(value) is not int or value <= 0 for value in (max_runs, max_sessions, max_run_record_bytes, max_registry_bytes))
        ):
            raise ValueError("registry_limits_invalid")
        self._clock = clock
        self._run_ttl = float(run_ttl_seconds)
        self._session_ttl = float(session_ttl_seconds)
        self._max_runs = max_runs
        self._max_sessions = max_sessions
        self._max_record_bytes = max_run_record_bytes
        self._max_registry_bytes = max_registry_bytes
        self._handle_factory = handle_factory
        self._evaluation_hook = evaluation_hook
        self._lock = threading.RLock()
        self._evaluation_slot = threading.Lock()
        self._runs: dict[bytes, _RunRecord] = {}
        self._scan_refs: dict[str, bytes] = {}
        self._sessions: dict[bytes, _SessionRecord] = {}
        self._pins: dict[str, int] = {}
        self._stored_bytes = 0
        self._session_bytes = 0

    def __repr__(self) -> str:
        return f"RunEvidenceRegistry(runs={len(self._runs)}, sessions={len(self._sessions)}, stored_bytes={self._stored_bytes})"

    @staticmethod
    def _digest(handle: object) -> bytes:
        if not isinstance(handle, str) or len(handle) > MAX_RUN_HANDLE_CHARS or not _HANDLE_RE.fullmatch(handle):
            raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
        return hashlib.sha256(handle.encode("ascii")).digest()

    def _new_handle(self, table: dict[bytes, object]) -> tuple[str, bytes]:
        for _ in range(3):
            try:
                value = self._handle_factory()
                digest = self._digest(value)
            except EvidenceRegistryError as exc:
                raise EvidenceRegistryError(RegistryErrorCode.INTERNAL_UNAVAILABLE) from exc
            if digest not in table and digest not in self._runs and digest not in self._sessions:
                return value, digest
        raise EvidenceRegistryError(RegistryErrorCode.INTERNAL_UNAVAILABLE)

    def _new_investigation_ref(self) -> str:
        existing = {item.investigation_ref for item in self._sessions.values()}
        for _ in range(3):
            value = secrets.token_urlsafe(24)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,64}", value) and value not in existing:
                return value
        raise EvidenceRegistryError(RegistryErrorCode.INTERNAL_UNAVAILABLE)

    def _remove_run(self, digest: bytes, record: _RunRecord) -> None:
        del self._runs[digest]
        self._scan_refs.pop(record.scan_ref, None)
        self._stored_bytes -= len(record.payload) + record.metadata_bytes + (
            len(record.rule_bytes_digest) if record.rule_bytes_digest is not None else 0
        )

    def _remove_session(self, digest: bytes) -> None:
        record = self._sessions.pop(digest, None)
        if record is not None:
            self._session_bytes -= record.metadata_bytes

    def _cleanup_locked(self, now: float) -> int:
        removed = 0
        for digest, session in list(self._sessions.items()):
            if now >= session.expires_at and self._pins.get(f"s:{digest.hex()}", 0) == 0:
                self._remove_session(digest)
                removed += 1
        for digest, record in list(self._runs.items()):
            if now >= record.expires_at and self._pins.get(f"r:{record.scan_ref}", 0) == 0:
                self._remove_run(digest, record)
                removed += 1
        return removed

    def cleanup_expired(self) -> int:
        with self._lock:
            return self._cleanup_locked(self._clock())

    def register_run(self, response: ScanResponse, manifest: ScanEvidenceManifest) -> str:
        return self._register_run(response, manifest, None)

    def register_rule_bytes_run(
        self, response: ScanResponse, manifest: ScanEvidenceManifest, observation: RuleBytesObservation
    ) -> str:
        """Atomically admit a run and its trusted, execution-bound sidecar."""
        if type(observation) is not RuleBytesObservation:
            raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
        if (
            observation.contract_version != RULE_BYTES_OBSERVATION_VERSION
            or observation.scan_ref != manifest.scan_ref
            or observation.target_id != manifest.target_id
            or observation.rule_profile_id != manifest.rule_profile_id
            or observation.invocation_id != RULE_BYTES_INVOCATION_ID
            or manifest.execution_evidence.invocation_id != RULE_BYTES_INVOCATION_ID
            or observation.semgrep_version != manifest.semgrep_version
            or (observation._digest is not None and len(observation._digest) != 32)
        ):
            raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
        return self._register_run(response, manifest, observation._digest)

    def _register_run(
        self, response: ScanResponse, manifest: ScanEvidenceManifest, rule_bytes_digest: bytes | None
    ) -> str:
        try:
            bundle = bind_run_evidence(response, manifest)
            payload = serialize_run_evidence(bundle)
        except EvidenceRegistryError:
            raise
        except Exception as exc:
            raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED) from exc
        if len(payload) > self._max_record_bytes:
            raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            if manifest.scan_ref in self._scan_refs:
                raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
            metadata_bytes = len(_json_bytes({
                "scan_ref": manifest.scan_ref,
                "target_id": manifest.target_id,
                "rule_profile_id": manifest.rule_profile_id,
                "created_at": now,
                "expires_at": now + self._run_ttl,
                "rule_bytes_sidecar": rule_bytes_digest is not None,
            }))
            sidecar_bytes = len(rule_bytes_digest) if rule_bytes_digest is not None else 0
            if sidecar_bytes > MAX_RULE_BYTES_SIDECAR_BYTES:
                raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
            record_bytes = len(payload) + metadata_bytes + sidecar_bytes
            if record_bytes > self._max_record_bytes:
                raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
            if len(self._runs) >= self._max_runs or self._stored_bytes + self._session_bytes + record_bytes > self._max_registry_bytes:
                raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
            handle, digest = self._new_handle(self._runs)
            record = _RunRecord(manifest.scan_ref, digest, payload, manifest.target_id,
                                manifest.rule_profile_id, now, now + self._run_ttl, metadata_bytes,
                                rule_bytes_digest)
            self._runs[digest] = record
            self._scan_refs[record.scan_ref] = digest
            self._stored_bytes += record_bytes
            return handle

    def evaluate_rule_bytes(self, session_handle: str) -> RuleBytesComparisonProjection:
        """Return only equality and fixed limitations; never expose either digest."""
        digest = self._digest(session_handle)
        if not self._evaluation_slot.acquire(blocking=False):
            raise EvidenceRegistryError(RegistryErrorCode.EVALUATION_BUSY)
        pins: tuple[str, ...] = ()
        try:
            with self._lock:
                now = self._clock()
                self._cleanup_locked(now)
                session = self._sessions.get(digest)
                if session is None or now >= session.expires_at:
                    raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
                baseline_digest = self._scan_refs.get(session.baseline_scan_ref)
                current_digest = self._scan_refs.get(session.current_scan_ref)
                baseline = self._runs.get(baseline_digest) if baseline_digest else None
                current = self._runs.get(current_digest) if current_digest else None
                if baseline is None or current is None or now >= baseline.expires_at or now >= current.expires_at:
                    raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
                pins = (f"s:{digest.hex()}", f"r:{baseline.scan_ref}", f"r:{current.scan_ref}")
                for key in pins:
                    self._pins[key] = self._pins.get(key, 0) + 1
                baseline_payload, current_payload = baseline.payload, current.payload
                baseline_rule, current_rule = baseline.rule_bytes_digest, current.rule_bytes_digest
                expected_baseline = (baseline.scan_ref, baseline.target_id, baseline.rule_profile_id)
                expected_current = (current.scan_ref, current.target_id, current.rule_profile_id)
            baseline_bundle = deserialize_run_evidence(baseline_payload)
            current_bundle = deserialize_run_evidence(current_payload)
            if (
                (baseline_bundle.manifest.scan_ref, baseline_bundle.manifest.target_id,
                 baseline_bundle.manifest.rule_profile_id) != expected_baseline
                or (current_bundle.manifest.scan_ref, current_bundle.manifest.target_id,
                    current_bundle.manifest.rule_profile_id) != expected_current
            ):
                raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
            if self._evaluation_hook is not None:
                self._evaluation_hook()
            if (
                baseline.scan_ref == current.scan_ref
                or baseline.target_id != current.target_id
                or baseline.rule_profile_id != current.rule_profile_id
                or baseline_bundle.manifest.execution_evidence.invocation_id != RULE_BYTES_INVOCATION_ID
                or current_bundle.manifest.execution_evidence.invocation_id != RULE_BYTES_INVOCATION_ID
                or baseline_bundle.manifest.semgrep_version != current_bundle.manifest.semgrep_version
            ):
                status = RuleBytesComparison.INCOMPARABLE
            elif (
                not baseline_bundle.response.completed
                or not current_bundle.response.completed
                or baseline_rule is None
                or current_rule is None
            ):
                status = RuleBytesComparison.UNVERIFIED
            elif len(baseline_rule) != 32 or len(current_rule) != 32:
                status = RuleBytesComparison.INCOMPARABLE
            else:
                status = (
                    RuleBytesComparison.SAME_SELECTED_BYTES
                    if secrets.compare_digest(baseline_rule, current_rule)
                    else RuleBytesComparison.DIFFERENT_SELECTED_BYTES
                )
            with self._lock:
                now = self._clock()
                current_session = self._sessions.get(digest)
                if current_session is not session or now >= session.expires_at:
                    raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
                for scan_ref in (session.baseline_scan_ref, session.current_scan_ref):
                    run_digest = self._scan_refs.get(scan_ref)
                    record = self._runs.get(run_digest) if run_digest else None
                    if record is None or now >= record.expires_at:
                        raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
            limitations = ("selected_rule_bytes_only", "loaded_rule_identity_unverified")
            return RuleBytesComparisonProjection(RULE_BYTES_COMPARISON_VERSION, status, limitations)
        except EvidenceRegistryError:
            raise
        except Exception as exc:
            raise EvidenceRegistryError(RegistryErrorCode.INTERNAL_UNAVAILABLE) from exc
        finally:
            if pins:
                with self._lock:
                    for key in pins:
                        count = self._pins.get(key, 0)
                        if count <= 1:
                            self._pins.pop(key, None)
                        else:
                            self._pins[key] = count - 1
            self._evaluation_slot.release()

    def get_run(self, handle: str) -> RunEvidenceBundle:
        digest = self._digest(handle)
        with self._lock:
            now = self._clock()
            self._cleanup_locked(now)
            record = self._runs.get(digest)
            if record is None or now >= record.expires_at:
                raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
            payload = record.payload
            pin = f"r:{record.scan_ref}"
            self._pins[pin] = self._pins.get(pin, 0) + 1
        try:
            restored = deserialize_run_evidence(payload)
            if (
                restored.manifest.scan_ref != record.scan_ref
                or restored.manifest.target_id != record.target_id
                or restored.manifest.rule_profile_id != record.rule_profile_id
            ):
                raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
            with self._lock:
                current = self._runs.get(digest)
                if current is not record or self._clock() >= record.expires_at:
                    raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
            return restored
        finally:
            with self._lock:
                count = self._pins.get(pin, 0)
                if count <= 1:
                    self._pins.pop(pin, None)
                else:
                    self._pins[pin] = count - 1

    def create_session(self, baseline_handle: str, current_handle: str) -> str:
        baseline_digest, current_digest = self._digest(baseline_handle), self._digest(current_handle)
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            baseline, current = self._runs.get(baseline_digest), self._runs.get(current_digest)
            if baseline is None or current is None or now >= baseline.expires_at or now >= current.expires_at:
                raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
            if baseline.scan_ref == current.scan_ref:
                raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
            if baseline.target_id != current.target_id or baseline.rule_profile_id != current.rule_profile_id:
                raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
            if len(self._sessions) >= self._max_sessions:
                raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
            handle, digest = self._new_handle(self._sessions)
            investigation_ref = self._new_investigation_ref()
            expires_at = min(now + self._session_ttl, baseline.expires_at, current.expires_at)
            metadata_bytes = len(_json_bytes({
                "investigation_ref": investigation_ref,
                "baseline_scan_ref": baseline.scan_ref,
                "current_scan_ref": current.scan_ref,
                "target_id": baseline.target_id,
                "rule_profile_id": baseline.rule_profile_id,
                "created_at": now,
                "expires_at": expires_at,
            }))
            if metadata_bytes > MAX_SESSION_RECORD_BYTES or self._session_bytes + metadata_bytes > MAX_SESSION_BYTES:
                raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
            if self._stored_bytes + self._session_bytes + metadata_bytes > self._max_registry_bytes:
                raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
            self._sessions[digest] = _SessionRecord(
                digest, investigation_ref, baseline.scan_ref, current.scan_ref, baseline.target_id,
                baseline.rule_profile_id, now, expires_at, metadata_bytes,
            )
            self._session_bytes += metadata_bytes
            return handle

    def evaluate(self, session_handle: str) -> FindingDisappearanceEvaluation:
        digest = self._digest(session_handle)
        if not self._evaluation_slot.acquire(blocking=False):
            raise EvidenceRegistryError(RegistryErrorCode.EVALUATION_BUSY)
        pins: tuple[str, ...] = ()
        try:
            with self._lock:
                now = self._clock()
                self._cleanup_locked(now)
                session = self._sessions.get(digest)
                if session is None or now >= session.expires_at:
                    raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
                baseline_digest = self._scan_refs.get(session.baseline_scan_ref)
                current_digest = self._scan_refs.get(session.current_scan_ref)
                baseline = self._runs.get(baseline_digest) if baseline_digest else None
                current = self._runs.get(current_digest) if current_digest else None
                if baseline is None or current is None or now >= baseline.expires_at or now >= current.expires_at:
                    raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
                pins = (f"s:{digest.hex()}", f"r:{baseline.scan_ref}", f"r:{current.scan_ref}")
                for key in pins:
                    self._pins[key] = self._pins.get(key, 0) + 1
                baseline_bytes, current_bytes = baseline.payload, current.payload
                expected_baseline = (baseline.scan_ref, baseline.target_id, baseline.rule_profile_id)
                expected_current = (current.scan_ref, current.target_id, current.rule_profile_id)
            baseline_bundle = deserialize_run_evidence(baseline_bytes)
            current_bundle = deserialize_run_evidence(current_bytes)
            if (
                (baseline_bundle.manifest.scan_ref, baseline_bundle.manifest.target_id, baseline_bundle.manifest.rule_profile_id)
                != expected_baseline
                or (current_bundle.manifest.scan_ref, current_bundle.manifest.target_id, current_bundle.manifest.rule_profile_id)
                != expected_current
            ):
                raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
            if self._evaluation_hook is not None:
                self._evaluation_hook()
            result = evaluate_finding_disappearance(baseline_bundle, current_bundle)
            result_bytes = _json_bytes(asdict(result))
            if len(result_bytes) > MAX_EVALUATION_BYTES:
                raise EvidenceRegistryError(RegistryErrorCode.RESOURCE_LIMIT)
            with self._lock:
                now = self._clock()
                current_session = self._sessions.get(digest)
                if current_session is not session or now >= session.expires_at:
                    raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
                for scan_ref in (session.baseline_scan_ref, session.current_scan_ref):
                    run_digest = self._scan_refs.get(scan_ref)
                    record = self._runs.get(run_digest) if run_digest else None
                    if record is None or now >= record.expires_at:
                        raise EvidenceRegistryError(RegistryErrorCode.EVIDENCE_UNAVAILABLE)
            return result
        except EvidenceRegistryError:
            raise
        except Exception as exc:
            raise EvidenceRegistryError(RegistryErrorCode.INTERNAL_UNAVAILABLE) from exc
        finally:
            if pins:
                with self._lock:
                    for key in pins:
                        count = self._pins.get(key, 0)
                        if count <= 1:
                            self._pins.pop(key, None)
                        else:
                            self._pins[key] = count - 1
            self._evaluation_slot.release()

    def release_session(self, handle: str) -> bool:
        digest = self._digest(handle)
        with self._lock:
            self._cleanup_locked(self._clock())
            if self._pins.get(f"s:{digest.hex()}", 0):
                raise EvidenceRegistryError(RegistryErrorCode.EVALUATION_BUSY)
            if digest not in self._sessions:
                return False
            self._remove_session(digest)
            return True

    def release_run(self, handle: str) -> bool:
        digest = self._digest(handle)
        with self._lock:
            self._cleanup_locked(self._clock())
            record = self._runs.get(digest)
            if record is None:
                return False
            if self._pins.get(f"r:{record.scan_ref}", 0):
                raise EvidenceRegistryError(RegistryErrorCode.EVALUATION_BUSY)
            if any(record.scan_ref in {item.baseline_scan_ref, item.current_scan_ref} for item in self._sessions.values()):
                raise EvidenceRegistryError(RegistryErrorCode.BINDING_REJECTED)
            self._remove_run(digest, record)
            return True

    @property
    def stored_bytes(self) -> int:
        with self._lock:
            return self._stored_bytes + self._session_bytes

    @property
    def active_run_count(self) -> int:
        with self._lock:
            return len(self._runs)

    @property
    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)
