from __future__ import annotations

import json
from dataclasses import replace
import os
import shutil
import sys
import threading
from pathlib import Path

import pytest

from ai_code_security_analyzer.api.schemas import ScanResponse
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.api import __main__ as api_main
from ai_code_security_analyzer.finding_disappearance_evaluator import (
    AssessmentStatus,
    FindingCategory,
    bind_run_evidence,
)
from ai_code_security_analyzer.investigation_evidence_registry import (
    EvidenceRegistryError,
    MAX_RUN_RECORD_BYTES,
    RegistryErrorCode,
    RunEvidenceRegistry,
    deserialize_run_evidence,
    serialize_run_evidence,
)
from ai_code_security_analyzer.services.scan_service import ApiSettings
from ai_code_security_analyzer.services.scan_service import ScanService
from ai_code_security_analyzer.semgrep_adapter import ScanStatus
from ai_code_security_analyzer.semgrep_adapter import SemgrepAdapter
from ai_code_security_analyzer.rule_bytes_identity import (
    RULE_BYTES_INVOCATION_ID,
    RULE_BYTES_OBSERVATION_VERSION,
    RuleBytesComparison,
    RuleBytesObservation,
)
from ai_code_security_analyzer.scan_evidence_manifest import (
    EvidenceStatus,
    SkippedPathEvidence,
    unavailable_scope_evidence,
)
from test_finding_disappearance_evaluator import bundle, finding


def test_run_registration_uses_separate_opaque_handle_and_bounded_canonical_bytes() -> None:
    registry = RunEvidenceRegistry()
    response, manifest = bundle(finding("a")).response, bundle(finding("b")).manifest
    # Bundle mismatch is rejected; do not let a caller recombine separate runs.
    with pytest.raises(EvidenceRegistryError) as error:
        registry.register_run(response, manifest)
    assert error.value.code is RegistryErrorCode.BINDING_REJECTED

    source = bundle(finding("a"))
    handle = registry.register_run(source.response, source.manifest)
    assert handle != source.manifest.scan_ref
    assert registry.get_run(handle).manifest.scan_ref == source.manifest.scan_ref
    assert len(registry._runs) == 1
    assert next(iter(registry._runs.values())).payload.startswith(b'{')
    assert handle not in repr(registry)


def test_handles_are_unique_and_distinct_registries_do_not_share_records() -> None:
    first, second = RunEvidenceRegistry(), RunEvidenceRegistry()
    run = bundle(finding("a"))
    handle = first.register_run(run.response, run.manifest)
    with pytest.raises(EvidenceRegistryError):
        second.get_run(handle)
    other = bundle(finding("b"))
    assert first.register_run(other.response, other.manifest) != handle


def test_duplicate_scan_reference_is_rejected_without_overwrite() -> None:
    registry = RunEvidenceRegistry()
    run = bundle(finding("a"))
    handle = registry.register_run(run.response, run.manifest)
    with pytest.raises(EvidenceRegistryError) as error:
        registry.register_run(run.response, run.manifest)
    assert error.value.code is RegistryErrorCode.BINDING_REJECTED
    assert registry.get_run(handle).manifest.finding_ids == run.manifest.finding_ids


def test_session_evaluation_and_release_are_bound_to_two_runs() -> None:
    registry = RunEvidenceRegistry()
    baseline = bundle(finding("a"), finding("b"), scanned=("src/a.js", "src/b.js"))
    current = bundle(finding("a"), finding("c"), scanned=("src/a.js", "src/c.js"))
    baseline_handle = registry.register_run(baseline.response, baseline.manifest)
    current_handle = registry.register_run(current.response, current.manifest)
    session = registry.create_session(baseline_handle, current_handle)
    session_record = next(iter(registry._sessions.values()))
    assert session_record.investigation_ref not in {session, baseline.manifest.scan_ref, current.manifest.scan_ref}
    assert session_record.baseline_scan_ref == baseline.manifest.scan_ref
    assert session_record.current_scan_ref == current.manifest.scan_ref
    evaluation = registry.evaluate(session)
    assert evaluation.overall_assessment is AssessmentStatus.UNDETERMINED
    assert [(item.category, item.finding_id) for item in evaluation.findings] == [
        (FindingCategory.SHARED, finding("a").finding_id),
        (FindingCategory.CURRENT_ONLY, finding("c").finding_id),
        (FindingCategory.BASELINE_ONLY, finding("b").finding_id),
    ]
    assert registry.release_session(session) is True
    assert registry.release_session(session) is False
    with pytest.raises(EvidenceRegistryError):
        registry.evaluate(session)


def test_rule_bytes_sidecar_is_atomic_bounded_and_removed_with_run() -> None:
    registry = RunEvidenceRegistry()
    first = bundle(finding("a"), invocation=RULE_BYTES_INVOCATION_ID)
    second = bundle(finding("b"), invocation=RULE_BYTES_INVOCATION_ID)

    def observation(run, digest: bytes) -> RuleBytesObservation:
        return RuleBytesObservation(
            RULE_BYTES_OBSERVATION_VERSION,
            run.manifest.scan_ref,
            run.manifest.target_id,
            run.manifest.rule_profile_id,
            RULE_BYTES_INVOCATION_ID,
            run.manifest.semgrep_version,
            digest,
        )

    a = registry.register_rule_bytes_run(first.response, first.manifest, observation(first, b"a" * 32))
    b = registry.register_rule_bytes_run(second.response, second.manifest, observation(second, b"a" * 32))
    session = registry.create_session(a, b)
    projection = registry.evaluate_rule_bytes(session)
    assert projection.status is RuleBytesComparison.SAME_SELECTED_BYTES
    assert "a" * 32 not in repr(registry)
    registry.release_session(session)
    assert registry.release_run(a) is True
    assert registry.release_run(b) is True
    assert registry.stored_bytes == 0


def test_rule_bytes_evaluation_pins_session_and_runs_during_release() -> None:
    entered = threading.Event()
    resume = threading.Event()
    registry = RunEvidenceRegistry(evaluation_hook=lambda: (entered.set(), resume.wait(2)))
    first = bundle(finding("a"), invocation=RULE_BYTES_INVOCATION_ID)
    second = bundle(finding("b"), invocation=RULE_BYTES_INVOCATION_ID)

    def observation(run) -> RuleBytesObservation:
        return RuleBytesObservation(
            RULE_BYTES_OBSERVATION_VERSION, run.manifest.scan_ref,
            run.manifest.target_id, run.manifest.rule_profile_id,
            RULE_BYTES_INVOCATION_ID, run.manifest.semgrep_version, b"a" * 32,
        )

    first_handle = registry.register_rule_bytes_run(first.response, first.manifest, observation(first))
    second_handle = registry.register_rule_bytes_run(second.response, second.manifest, observation(second))
    session = registry.create_session(first_handle, second_handle)
    outcomes = []
    worker = threading.Thread(target=lambda: outcomes.append(registry.evaluate_rule_bytes(session)))
    worker.start()
    assert entered.wait(2)
    with pytest.raises(EvidenceRegistryError) as session_error:
        registry.release_session(session)
    assert session_error.value.code is RegistryErrorCode.EVALUATION_BUSY
    with pytest.raises(EvidenceRegistryError) as run_error:
        registry.release_run(first_handle)
    assert run_error.value.code is RegistryErrorCode.EVALUATION_BUSY
    resume.set()
    worker.join(2)
    assert [item.status for item in outcomes] == [RuleBytesComparison.SAME_SELECTED_BYTES]


def test_rule_bytes_projection_is_different_unverified_or_incomparable_without_digest_disclosure() -> None:
    registry = RunEvidenceRegistry()
    runs = [bundle(finding(char), invocation=RULE_BYTES_INVOCATION_ID) for char in "abcd"]
    observations = [RuleBytesObservation(
        RULE_BYTES_OBSERVATION_VERSION, run.manifest.scan_ref, run.manifest.target_id,
        run.manifest.rule_profile_id, RULE_BYTES_INVOCATION_ID, run.manifest.semgrep_version,
        bytes([index]) * 32,
    ) for index, run in enumerate(runs, 1)]
    handles = [registry.register_rule_bytes_run(run.response, run.manifest, item) for run, item in zip(runs, observations)]
    projection = registry.evaluate_rule_bytes(registry.create_session(handles[0], handles[1]))
    assert projection.status is RuleBytesComparison.DIFFERENT_SELECTED_BYTES
    assert set(projection.__dict__ if hasattr(projection, "__dict__") else ()) == set()

    mixed_registry = RunEvidenceRegistry()
    bound = runs[2]
    bound_handle = mixed_registry.register_rule_bytes_run(bound.response, bound.manifest, observations[2])
    plain = bundle(finding("e"))
    plain_handle = mixed_registry.register_run(plain.response, plain.manifest)
    mixed = mixed_registry.evaluate_rule_bytes(mixed_registry.create_session(bound_handle, plain_handle))
    assert mixed.status is RuleBytesComparison.INCOMPARABLE


def test_same_run_target_or_profile_cannot_be_linked() -> None:
    registry = RunEvidenceRegistry()
    run = bundle(finding("a"))
    handle = registry.register_run(run.response, run.manifest)
    with pytest.raises(EvidenceRegistryError):
        registry.create_session(handle, handle)
    target = bundle(finding("b"), target="other")
    target_handle = registry.register_run(target.response, target.manifest)
    with pytest.raises(EvidenceRegistryError):
        registry.create_session(handle, target_handle)
    profile = bundle(finding("c"), profile="other")
    profile_handle = registry.register_run(profile.response, profile.manifest)
    with pytest.raises(EvidenceRegistryError):
        registry.create_session(handle, profile_handle)


def test_fake_monotonic_clock_expires_records_without_sliding_ttl() -> None:
    now = [10.0]
    registry = RunEvidenceRegistry(clock=lambda: now[0], run_ttl_seconds=10, session_ttl_seconds=10)
    first, second = bundle(finding("a")), bundle(finding("b"))
    h1 = registry.register_run(first.response, first.manifest)
    now[0] = 19.0
    registry.get_run(h1)
    now[0] = 20.0
    with pytest.raises(EvidenceRegistryError) as error:
        registry.get_run(h1)
    assert error.value.code is RegistryErrorCode.EVIDENCE_UNAVAILABLE
    h2 = registry.register_run(second.response, second.manifest)
    assert registry.cleanup_expired() == 0
    assert registry.active_run_count == 1
    assert registry.get_run(h2)


def test_active_records_are_not_evicted_and_capacity_fails_closed() -> None:
    registry = RunEvidenceRegistry(max_runs=1)
    first, second = bundle(finding("a")), bundle(finding("b"))
    h1 = registry.register_run(first.response, first.manifest)
    with pytest.raises(EvidenceRegistryError) as error:
        registry.register_run(second.response, second.manifest)
    assert error.value.code is RegistryErrorCode.RESOURCE_LIMIT
    assert registry.get_run(h1).manifest.scan_ref == first.manifest.scan_ref


def test_per_record_and_total_byte_caps_reject_without_partial_admission() -> None:
    run = bundle(finding("a"))
    too_small_record = RunEvidenceRegistry(max_run_record_bytes=1)
    with pytest.raises(EvidenceRegistryError) as error:
        too_small_record.register_run(run.response, run.manifest)
    assert error.value.code is RegistryErrorCode.RESOURCE_LIMIT
    assert too_small_record.active_run_count == 0

    too_small_total = RunEvidenceRegistry(max_registry_bytes=1)
    with pytest.raises(EvidenceRegistryError) as error:
        too_small_total.register_run(run.response, run.manifest)
    assert error.value.code is RegistryErrorCode.RESOURCE_LIMIT
    assert too_small_total.active_run_count == 0


def test_serializer_rejects_manifest_bytes_over_c1_limit_before_registry_admission() -> None:
    from dataclasses import asdict
    import json

    paths = tuple(f"src/{index:05d}/" + "x" * 88 + ".js" for index in range(10_000))
    valid = bundle(finding("a"), scanned=paths)
    assert len(json.dumps(asdict(valid.manifest), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()) < 1_048_576
    serialize_run_evidence(valid)
    too_long_paths = tuple(f"src/{index:05d}/" + "x" * 89 + ".js" for index in range(10_000))
    invalid = bundle(finding("b"), scanned=too_long_paths)
    assert len(json.dumps(asdict(invalid.manifest), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()) > 1_048_576
    with pytest.raises(EvidenceRegistryError) as error:
        serialize_run_evidence(invalid)
    assert error.value.code is RegistryErrorCode.RESOURCE_LIMIT


def test_session_count_limit_does_not_evict_live_session() -> None:
    registry = RunEvidenceRegistry(max_sessions=1)
    runs = [bundle(finding(char)) for char in "abcd"]
    handles = [registry.register_run(run.response, run.manifest) for run in runs]
    first = registry.create_session(handles[0], handles[1])
    with pytest.raises(EvidenceRegistryError) as error:
        registry.create_session(handles[2], handles[3])
    assert error.value.code is RegistryErrorCode.RESOURCE_LIMIT
    assert registry.active_session_count == 1
    assert registry.evaluate(first)


def test_run_release_blocked_while_session_references_it() -> None:
    registry = RunEvidenceRegistry()
    a, b = bundle(finding("a")), bundle(finding("b"))
    ah = registry.register_run(a.response, a.manifest)
    bh = registry.register_run(b.response, b.manifest)
    session = registry.create_session(ah, bh)
    with pytest.raises(EvidenceRegistryError):
        registry.release_run(ah)
    registry.release_session(session)
    assert registry.release_run(ah) is True
    assert registry.release_run(ah) is False


def test_canonical_serialization_is_strict_and_round_trips() -> None:
    run = bundle(finding("a"))
    encoded = serialize_run_evidence(run)
    decoded = deserialize_run_evidence(encoded)
    assert decoded == run
    assert encoded == serialize_run_evidence(decoded)
    for raw in (
        b'{"contract_version":"x","contract_version":"y"}',
        b'{"contract_version":"x","bad":NaN}',
        b'{"contract_version":"x","bad":Infinity}',
    ):
        with pytest.raises(EvidenceRegistryError):
            deserialize_run_evidence(raw)


def test_adapter_exclusion_skip_evidence_round_trips() -> None:
    run = bundle(
        finding("a"),
        skipped=(SkippedPathEvidence("node_modules", "adapter_policy_exclusion"),),
        skipped_status=EvidenceStatus.OBSERVED,
    )
    assert deserialize_run_evidence(serialize_run_evidence(run)) == run


@pytest.mark.parametrize(
    "reason",
    [
        "semgrep_timeout_without_json", "semgrep_output_limit", "invalid_json_after_failed_execution",
        "invalid_json", "scope_capture_failed", "adapter_scope_evidence_not_provided",
        "manifest_capture_failed",
    ],
)
def test_run_without_usable_scope_evidence_is_evaluated_as_incomparable(reason: str) -> None:
    """A failed scan must be read back and judged, not fail inside the registry."""
    registry = RunEvidenceRegistry()
    baseline = bundle(finding("a"), finding("b", "src/b.js"), scanned=("src/a.js", "src/b.js"))
    failed = bundle(status=ScanStatus.TIMED_OUT, scanned=())
    failed = bind_run_evidence(
        failed.response, replace(failed.manifest, scope_evidence=unavailable_scope_evidence(reason))
    )
    assert deserialize_run_evidence(serialize_run_evidence(failed)) == failed

    session = registry.create_session(
        registry.register_run(baseline.response, baseline.manifest),
        registry.register_run(failed.response, failed.manifest),
    )
    evaluation = registry.evaluate(session)

    assert evaluation.comparability is AssessmentStatus.INCOMPARABLE
    assert evaluation.overall_assessment is AssessmentStatus.INCOMPARABLE
    assert "scan_incomplete" in evaluation.limitation_codes


def test_unknown_limitation_code_is_still_rejected() -> None:
    run = bundle(finding("a"))
    forged = bind_run_evidence(
        run.response, replace(run.manifest, scope_evidence=unavailable_scope_evidence("made_up_reason"))
    )
    with pytest.raises(EvidenceRegistryError):
        deserialize_run_evidence(serialize_run_evidence(forged))


def test_unknown_fields_and_malformed_nested_manifest_are_rejected() -> None:
    run = bundle(finding("a"))
    document = json.loads(serialize_run_evidence(run))
    document["extra"] = "not accepted"
    with pytest.raises(EvidenceRegistryError):
        deserialize_run_evidence(json.dumps(document).encode())
    document = json.loads(serialize_run_evidence(run))
    document["response"]["extra"] = "not accepted"
    with pytest.raises(EvidenceRegistryError):
        deserialize_run_evidence(json.dumps(document).encode())
    document = json.loads(serialize_run_evidence(run))
    document["manifest"]["scope_evidence"]["extra"] = True
    with pytest.raises(EvidenceRegistryError):
        deserialize_run_evidence(json.dumps(document).encode())
    document = json.loads(serialize_run_evidence(run))
    document["manifest"]["contract_version"] = "unknown/v2"
    with pytest.raises(EvidenceRegistryError):
        deserialize_run_evidence(json.dumps(document).encode())
    document = json.loads(serialize_run_evidence(run))
    document["response"]["completed"] = "true"
    with pytest.raises(EvidenceRegistryError):
        deserialize_run_evidence(json.dumps(document).encode())


def test_corrupted_payload_and_oversized_payload_are_not_empty_results() -> None:
    run = bundle(finding("a"))
    with pytest.raises(EvidenceRegistryError):
        deserialize_run_evidence(b"not-json")
    with pytest.raises(EvidenceRegistryError) as error:
        deserialize_run_evidence(b" " * (MAX_RUN_RECORD_BYTES + 1))
    assert error.value.code is RegistryErrorCode.RESOURCE_LIMIT


def test_session_and_run_expiry_are_linked() -> None:
    now = [0.0]
    registry = RunEvidenceRegistry(clock=lambda: now[0], run_ttl_seconds=100, session_ttl_seconds=50)
    a, b = bundle(finding("a")), bundle(finding("b"))
    ah = registry.register_run(a.response, a.manifest)
    bh = registry.register_run(b.response, b.manifest)
    session = registry.create_session(ah, bh)
    now[0] = 50.0
    with pytest.raises(EvidenceRegistryError):
        registry.evaluate(session)


def test_concurrent_evaluation_limit_is_explicit_and_release_is_safe() -> None:
    entered = threading.Event()
    resume = threading.Event()
    registry = RunEvidenceRegistry(evaluation_hook=lambda: (entered.set(), resume.wait(2)))
    a, b = bundle(finding("a")), bundle(finding("b"))
    ah, bh = registry.register_run(a.response, a.manifest), registry.register_run(b.response, b.manifest)
    session = registry.create_session(ah, bh)
    outcome = []
    worker = threading.Thread(target=lambda: outcome.append(registry.evaluate(session)))
    worker.start()
    assert entered.wait(2)
    with pytest.raises(EvidenceRegistryError) as error:
        registry.evaluate(session)
    assert error.value.code is RegistryErrorCode.EVALUATION_BUSY
    with pytest.raises(EvidenceRegistryError):
        registry.release_session(session)
    with pytest.raises(EvidenceRegistryError) as release_error:
        registry.release_run(ah)
    assert release_error.value.code is RegistryErrorCode.EVALUATION_BUSY
    resume.set()
    worker.join(2)
    assert len(outcome) == 1


def test_scan_response_contract_is_not_extended_by_registry() -> None:
    run = bundle(finding("a"))
    restored = deserialize_run_evidence(serialize_run_evidence(run))
    assert set(restored.response.model_dump(mode="json")) == set(ScanResponse.model_fields)


def test_app_factory_owns_an_independent_registry(tmp_path) -> None:
    project, rules = tmp_path / "project", tmp_path / "rules"
    project.mkdir()
    rules.mkdir()
    settings = ApiSettings(project, rules, "t" * 48)
    first, second = create_app(settings), create_app(settings)
    assert first.state.investigation_registry is not second.state.investigation_registry
    assert first.state.investigation_registry.active_run_count == 0


def test_local_launcher_explicitly_uses_one_non_reloading_worker(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(sys, "argv", ["ai-code-security-analyzer-api"])
    monkeypatch.setattr(api_main, "create_app_from_env", lambda **kwargs: captured.update(enabled=kwargs.get("investigation_api_enabled")) or object())
    monkeypatch.setattr(api_main.uvicorn, "run", lambda app, **kwargs: captured.update(kwargs))
    api_main.main()
    assert captured["workers"] == 1
    assert captured["reload"] is False
    assert captured["host"] == "127.0.0.1"
    assert captured["enabled"] is True


def test_expiry_during_evaluation_discards_result() -> None:
    now = [0.0]
    registry = RunEvidenceRegistry(
        clock=lambda: now[0], run_ttl_seconds=10, session_ttl_seconds=10,
        evaluation_hook=lambda: now.__setitem__(0, 10.0),
    )
    a, b = bundle(finding("a")), bundle(finding("b"))
    ah, bh = registry.register_run(a.response, a.manifest), registry.register_run(b.response, b.manifest)
    session = registry.create_session(ah, bh)
    with pytest.raises(EvidenceRegistryError) as error:
        registry.evaluate(session)
    assert error.value.code is RegistryErrorCode.EVIDENCE_UNAVAILABLE


def test_handle_collision_never_overwrites_existing_record() -> None:
    constant = "A" * 43
    values = iter([constant, constant, constant, constant])
    registry = RunEvidenceRegistry(handle_factory=lambda: next(values))
    run = bundle(finding("a"))
    handle = registry.register_run(run.response, run.manifest)
    second = bundle(finding("b"))
    with pytest.raises(EvidenceRegistryError) as error:
        registry.register_run(second.response, second.manifest)
    assert error.value.code is RegistryErrorCode.INTERNAL_UNAVAILABLE
    assert registry.get_run(handle).manifest.scan_ref == run.manifest.scan_ref


def test_stored_bytes_tampering_is_not_returned_as_empty_evaluation() -> None:
    registry = RunEvidenceRegistry()
    run = bundle(finding("a"))
    handle = registry.register_run(run.response, run.manifest)
    record = next(iter(registry._runs.values()))
    registry._runs[record.handle_digest] = type(record)(
        record.scan_ref, record.handle_digest, b"{}", record.target_id,
        record.rule_profile_id, record.created_at, record.expires_at, record.metadata_bytes,
    )
    with pytest.raises(EvidenceRegistryError) as error:
        registry.get_run(handle)
    assert error.value.code is RegistryErrorCode.INTERNAL_UNAVAILABLE


def test_partial_or_omitted_runs_return_evaluator_incomparability() -> None:
    for incomplete in (bundle(finding("b"), status=ScanStatus.PARTIAL), bundle(finding("c"), omitted=1)):
        other = bundle(finding("a"))
        registry = RunEvidenceRegistry()
        ah = registry.register_run(other.response, other.manifest)
        bh = registry.register_run(incomplete.response, incomplete.manifest)
        result = registry.evaluate(registry.create_session(ah, bh))
        assert result.comparability is AssessmentStatus.INCOMPARABLE


def test_real_semgrep_rescan_a_b_to_a_c_registry_flow(tmp_path) -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    project = tmp_path / "synthetic-project"
    project.mkdir()
    (project / "stable.js").write_text("const value = eval(input);\n", encoding="utf-8")
    (project / "firestore.rules").write_text(
        "service cloud.firestore {\n"
        "  match /databases/{database}/documents {\n"
        "    allow write: if true;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    settings = ApiSettings(project, Path(__file__).parents[1] / "rules", "t" * 48)
    semgrep_executions = []

    class CountingAdapter(SemgrepAdapter):
        def _scan_with_evidence(self, target, rules):
            semgrep_executions.append((target, rules))
            return super()._scan_with_evidence(target, rules)

    service = ScanService(settings, adapter_factory=CountingAdapter)
    registry = RunEvidenceRegistry()

    baseline_response, baseline_manifest = service._scan_with_manifest("local-project", "baseline")
    assert baseline_response.scan_status.value == "completed"
    baseline_ids = {item.rule_id: item.finding_id for item in baseline_response.findings}
    assert "baseline.javascript-dynamic-eval" in baseline_ids
    assert "baseline.firestore-unconditional-write" in baseline_ids
    baseline_handle = registry.register_run(baseline_response, baseline_manifest)

    (project / "firestore.rules").unlink()
    (project / "new.jsx").write_text(
        "const node = <div dangerouslySetInnerHTML={{__html: input}} />;\n", encoding="utf-8"
    )
    current_response, current_manifest = service._scan_with_manifest("local-project", "baseline")
    assert current_response.scan_status.value == "completed"
    current_ids = {item.rule_id: item.finding_id for item in current_response.findings}
    assert "baseline.javascript-dynamic-eval" in current_ids
    assert "baseline.react-dangerous-html" in current_ids
    current_handle = registry.register_run(current_response, current_manifest)
    session = registry.create_session(baseline_handle, current_handle)
    result = registry.evaluate(session)
    assert len(semgrep_executions) == 2
    by_id = {item.finding_id: item.category for item in result.findings}
    assert by_id[baseline_ids["baseline.javascript-dynamic-eval"]] is FindingCategory.SHARED
    assert by_id[baseline_ids["baseline.firestore-unconditional-write"]] is FindingCategory.BASELINE_ONLY
    assert by_id[current_ids["baseline.react-dangerous-html"]] is FindingCategory.CURRENT_ONLY
    assert result.overall_assessment is AssessmentStatus.UNDETERMINED
    assert registry.release_session(session)
    assert registry.release_run(baseline_handle)
    assert registry.release_run(current_handle)
