from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import shutil

from ai_code_security_analyzer.api.schemas import ApiFinding, ScanResponse
from ai_code_security_analyzer.evidence_summary import FindingKind
from ai_code_security_analyzer.evidence_sufficiency import ClaimType
from ai_code_security_analyzer.finding_disappearance_evaluator import (
    AssessmentStatus,
    BundleBindingError,
    FindingCategory,
    PathObservation,
    RunEvidenceBundle,
    bind_run_evidence,
    evaluate_finding_disappearance,
)
from ai_code_security_analyzer.models import Severity
from ai_code_security_analyzer.scan_evidence_manifest import (
    EvidenceStatus,
    ExecutionEvidence,
    RuleEvidence,
    ScanEvidenceManifest,
    ScopeEvidence,
    SkippedPathEvidence,
    new_scan_ref,
)
from ai_code_security_analyzer.semgrep_adapter import ScanStatus
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService


def finding(suffix: str, path: str | None = "src/a.js") -> ApiFinding:
    return ApiFinding(
        finding_id=f"semgrep:{suffix * 24}",
        rule_id="baseline.javascript-dynamic-eval",
        severity=Severity.HIGH,
        finding_kind=FindingKind.PATTERN,
        file_path=path,
        line_number=2 if path else None,
        evidence_validation_status="validated",
        supported_claims=(ClaimType.MATCH_REPORTED,),
        restricted_claims=(),
    )


def bundle(
    *items: ApiFinding,
    scanned: tuple[str, ...] = ("src/a.js",),
    skipped: tuple[SkippedPathEvidence, ...] = (),
    scanned_status: EvidenceStatus = EvidenceStatus.OBSERVED,
    skipped_status: EvidenceStatus = EvidenceStatus.NOT_COLLECTED,
    status: ScanStatus = ScanStatus.COMPLETED,
    omitted: int = 0,
    target: str = "target-a",
    profile: str = "baseline",
    version: str | None = "1.182.1",
    invocation: str = "semgrep-json-local-v1",
    rule_file: str = "security-baseline.yml",
    scan_ref: str | None = None,
) -> RunEvidenceBundle:
    run_ref = scan_ref or new_scan_ref()
    response = ScanResponse(
        scan_status=status,
        completed=status is ScanStatus.COMPLETED,
        semgrep_version=version,
        finding_count=len(items) + omitted,
        displayed_finding_count=len(items),
        omitted_finding_count=omitted,
        severity_counts={severity: sum(item.severity is severity for item in items) for severity in Severity},
        issues=(),
        findings=items,
        limitations=(),
    )
    manifest = ScanEvidenceManifest(
        contract_version="scan-evidence-manifest/v1",
        scan_ref=run_ref,
        target_id=target,
        rule_profile_id=profile,
        semgrep_version=version,
        scan_status=status.value,
        finding_count=response.finding_count,
        displayed_finding_count=response.displayed_finding_count,
        omitted_finding_count=response.omitted_finding_count,
        finding_ids=tuple(item.finding_id for item in items),
        execution_evidence=ExecutionEvidence("semgrep", status.value, version, 0, invocation),
        rule_evidence=RuleEvidence(
            profile, rule_file, EvidenceStatus.OBSERVED,
            EvidenceStatus.UNVERIFIED, EvidenceStatus.UNVERIFIED,
        ),
        scope_evidence=ScopeEvidence(
            EvidenceStatus.UNVERIFIED, True, True, scanned_status, scanned, len(scanned),
            skipped_status, skipped, EvidenceStatus.NOT_COLLECTED, None,
            EvidenceStatus.OBSERVED, 0, ("scanned_paths_do_not_prove_complete_analysis",),
        ),
        limitations=("rule_bytes_identity_unverified", "semgrep_loaded_rule_identity_unverified", "source_snapshot_not_collected"),
    )
    return bind_run_evidence(response, manifest)


def test_normal_same_context_comparison_only_compares_finding_id_sets() -> None:
    baseline = bundle(finding("a"), finding("b"), scanned=("src/a.js", "src/b.js"))
    current = bundle(finding("a"), finding("c"), scanned=("src/a.js", "src/c.js"))

    result = evaluate_finding_disappearance(baseline, current)

    assert result.comparability is AssessmentStatus.COMPARABLE
    assert [(item.category, item.finding_id) for item in result.findings] == [
        (FindingCategory.SHARED, "semgrep:" + "a" * 24),
        (FindingCategory.CURRENT_ONLY, "semgrep:" + "c" * 24),
        (FindingCategory.BASELINE_ONLY, "semgrep:" + "b" * 24),
    ]
    assert result.overall_assessment is AssessmentStatus.UNDETERMINED
    assert "source_snapshot_not_collected" in result.limitation_codes


def test_mixed_default_and_investigation_invocations_are_incomparable() -> None:
    baseline = bundle(finding("b"), invocation="semgrep-json-local-v1")
    current = bundle(finding("b"), invocation="semgrep-json-investigation-verbose-v1")
    result = evaluate_finding_disappearance(baseline, current)
    assert result.comparability is AssessmentStatus.INCOMPARABLE
    assert result.overall_assessment is AssessmentStatus.INCOMPARABLE
    assert result.findings == ()
    assert "scan_context_mismatch" in result.limitation_codes


def test_adapter_exclusions_keep_completed_scans_comparable_without_explaining_a_disappearance() -> None:
    policy = (
        SkippedPathEvidence(".git", "adapter_policy_exclusion"),
        SkippedPathEvidence("node_modules", "adapter_policy_exclusion"),
    )
    baseline = bundle(
        finding("a"), finding("b", "src/b.js"), scanned=("src/a.js", "src/b.js"),
        skipped=policy, skipped_status=EvidenceStatus.OBSERVED,
    )
    current = bundle(
        finding("a"), scanned=("src/a.js",), skipped=policy, skipped_status=EvidenceStatus.OBSERVED,
    )
    result = evaluate_finding_disappearance(baseline, current)

    assert result.comparability is AssessmentStatus.COMPARABLE
    assert result.overall_assessment is AssessmentStatus.UNDETERMINED
    gone = next(item for item in result.findings if item.category is FindingCategory.BASELINE_ONLY)
    assert gone.path_observation is PathObservation.PATH_NOT_REPORTED
    assert gone.skip_hypothesis is AssessmentStatus.UNDETERMINED
    assert "scope_completeness_unverified" in result.limitation_codes


@pytest.mark.parametrize(
    "forged",
    [
        SkippedPathEvidence("src/b.js", "adapter_policy_exclusion"),
        SkippedPathEvidence("node_modules", "semgrepignore_patterns_match"),
        SkippedPathEvidence("node_modules", "cli_exclude_flags_match"),
        SkippedPathEvidence("src/b.js", "analysis_failed_parser_or_internal_error"),
    ],
)
def test_non_canonical_skip_reason_is_refused_as_run_evidence(forged: SkippedPathEvidence) -> None:
    with pytest.raises(BundleBindingError):
        bundle(scanned=("src/a.js",), skipped=(forged,), skipped_status=EvidenceStatus.OBSERVED)


def test_explicit_current_skip_supports_only_narrow_procedure_observation() -> None:
    baseline = bundle(finding("b", "src/b.js"), scanned=("src/a.js", "src/b.js"))
    current = bundle(
        scanned=("src/a.js",),
        skipped=(SkippedPathEvidence("src/b.js", "semgrepignore_patterns_match"),),
        skipped_status=EvidenceStatus.OBSERVED,
    )
    result = evaluate_finding_disappearance(baseline, current)
    item = result.findings[0]

    assert item.path_observation is PathObservation.PATH_EXPLICITLY_SKIPPED
    assert item.skip_hypothesis is AssessmentStatus.SUPPORTED
    assert result.overall_assessment is AssessmentStatus.EXPLANATION_SUPPORTED
    assert "path_explicitly_skipped" in result.limitation_codes
    assert not hasattr(result, "resolved")


@pytest.mark.parametrize(
    ("status", "omitted", "expected"),
    [
        (ScanStatus.PARTIAL, 0, AssessmentStatus.INCOMPARABLE),
        (ScanStatus.COMPLETED, 1, AssessmentStatus.INCOMPARABLE),
        (ScanStatus.EXECUTION_FAILED, 0, AssessmentStatus.INCOMPARABLE),
        (ScanStatus.TIMED_OUT, 0, AssessmentStatus.INCOMPARABLE),
        (ScanStatus.OUTPUT_LIMIT_EXCEEDED, 0, AssessmentStatus.INCOMPARABLE),
    ],
)
def test_incomplete_runs_remain_incomparable_even_with_positive_skip_observation(
    status: ScanStatus, omitted: int, expected: AssessmentStatus
) -> None:
    baseline = bundle(finding("b", "src/b.js"), scanned=("src/b.js",))
    current = bundle(
        status=status,
        omitted=omitted,
        scanned=(),
        skipped=(SkippedPathEvidence("src/b.js", "semgrepignore_patterns_match"),),
        skipped_status=EvidenceStatus.OBSERVED,
    )
    result = evaluate_finding_disappearance(baseline, current)
    assert result.overall_assessment is expected
    assert result.findings[0].skip_hypothesis is AssessmentStatus.SUPPORTED


def test_scope_observations_are_conservative() -> None:
    baseline = bundle(finding("b", "src/b.js"), scanned=("src/b.js",))
    scanned = evaluate_finding_disappearance(
        baseline, bundle(scanned=("src/b.js",), skipped_status=EvidenceStatus.OBSERVED)
    )
    not_reported = evaluate_finding_disappearance(
        baseline, bundle(scanned=("src/other.js",), skipped_status=EvidenceStatus.OBSERVED)
    )
    no_skip_data = evaluate_finding_disappearance(
        baseline, bundle(scanned=("src/other.js",), skipped_status=EvidenceStatus.NOT_COLLECTED)
    )
    no_scope = evaluate_finding_disappearance(
        baseline, bundle(scanned=(), scanned_status=EvidenceStatus.UNAVAILABLE)
    )
    bad_skip_scope = evaluate_finding_disappearance(
        baseline,
        bundle(scanned=("src/other.js",), skipped_status=EvidenceStatus.UNAVAILABLE),
    )

    assert scanned.findings[0].path_observation is PathObservation.PATH_REPORTED_SCANNED
    assert scanned.findings[0].skip_hypothesis is AssessmentStatus.CONTRADICTED
    assert not_reported.findings[0].path_observation is PathObservation.PATH_NOT_REPORTED
    assert no_skip_data.findings[0].path_observation is PathObservation.SKIP_EVIDENCE_NOT_COLLECTED
    assert no_scope.findings[0].path_observation is PathObservation.SCOPE_EVIDENCE_UNAVAILABLE
    assert bad_skip_scope.findings[0].path_observation is PathObservation.SCOPE_EVIDENCE_UNAVAILABLE
    assert all(item.source_snapshot_hypothesis is AssessmentStatus.UNDETERMINED for item in no_scope.findings)


def test_scope_conflict_is_not_resolved_by_precedence() -> None:
    baseline = bundle(finding("b", "src/b.js"), scanned=("src/b.js",))
    current = bundle(
        scanned=("src/b.js",),
        skipped=(SkippedPathEvidence("src/b.js", "semgrepignore_patterns_match"),),
        skipped_status=EvidenceStatus.OBSERVED,
    )
    result = evaluate_finding_disappearance(baseline, current)
    assert result.findings[0].path_observation is PathObservation.CONFLICTING
    assert result.findings[0].skip_hypothesis is AssessmentStatus.INCOMPARABLE

    unrelated = bundle(
        finding("a", "src/a.js"),
        scanned=("src/a.js", "src/conflict.js"),
        skipped=(SkippedPathEvidence("src/conflict.js", "semgrepignore_patterns_match"),),
        skipped_status=EvidenceStatus.OBSERVED,
    )
    global_conflict = evaluate_finding_disappearance(bundle(), unrelated)
    assert global_conflict.comparability is AssessmentStatus.INCOMPARABLE
    assert "scanned_skipped_path_conflict" in global_conflict.limitation_codes


@pytest.mark.parametrize(
    "current_overrides",
    [
        {"target": "other-target"},
        {"profile": "other-profile"},
        {"version": "1.183.0"},
        {"version": None},
            {"invocation": "semgrep-json-investigation-verbose-v1"},
        {"rule_file": "other-rules.yml"},
    ],
)
def test_analysis_context_mismatch_blocks_evaluation(current_overrides: dict[str, object]) -> None:
    baseline = bundle(finding("a"))
    current = bundle(**current_overrides)
    result = evaluate_finding_disappearance(baseline, current)
    assert result.comparability is AssessmentStatus.INCOMPARABLE
    assert result.findings == ()
    assert "scan_context_mismatch" in result.limitation_codes


def test_same_scan_reference_and_manifest_version_mismatch_block() -> None:
    shared_ref = new_scan_ref()
    first = bundle(finding("a"), scan_ref=shared_ref)
    same_run = bundle(finding("a"), scan_ref=shared_ref)
    assert "scan_reference_collision" in evaluate_finding_disappearance(first, same_run).limitation_codes

    bad_manifest = replace(first.manifest, contract_version="future/v2")
    bad_bundle = RunEvidenceBundle(first.response, bad_manifest)
    result = evaluate_finding_disappearance(bad_bundle, bundle(finding("b")))
    assert result.comparability is AssessmentStatus.INCOMPARABLE
    assert "manifest_binding_invalid" in result.limitation_codes


def test_response_manifest_count_and_finding_binding_fail_closed() -> None:
    original = bundle(finding("a"))
    changed_response = original.response.model_copy(update={"findings": (finding("b"),)})
    bad_ids = RunEvidenceBundle(changed_response, original.manifest)
    result = evaluate_finding_disappearance(original, bad_ids)
    assert result.comparability is AssessmentStatus.INCOMPARABLE
    assert "response_manifest_binding_invalid" in result.limitation_codes

    bad_count = replace(original.manifest, finding_count=2)
    result = evaluate_finding_disappearance(original, RunEvidenceBundle(original.response, bad_count))
    assert result.comparability is AssessmentStatus.INCOMPARABLE


def test_duplicate_finding_id_and_unsafe_manifest_paths_are_rejected() -> None:
    with pytest.raises(BundleBindingError):
        bundle(finding("a"), finding("a"))

    baseline = bundle(finding("b"))
    bad_scope = replace(baseline.manifest.scope_evidence, scanned_paths=("../secret",))
    bad_manifest = replace(baseline.manifest, scope_evidence=bad_scope)
    result = evaluate_finding_disappearance(
        baseline, RunEvidenceBundle(baseline.response, bad_manifest)
    )
    assert result.comparability is AssessmentStatus.INCOMPARABLE
    assert "manifest_binding_invalid" in result.limitation_codes


def test_duplicate_ids_inside_manifest_and_malformed_bundle_are_rejected() -> None:
    original = bundle(finding("a"))
    duplicate_manifest = replace(original.manifest, finding_ids=(original.manifest.finding_ids[0],) * 2)
    result = evaluate_finding_disappearance(
        original, RunEvidenceBundle(original.response, duplicate_manifest)
    )
    assert result.overall_assessment is AssessmentStatus.INCOMPARABLE
    assert "manifest_binding_invalid" in result.limitation_codes

    result = evaluate_finding_disappearance(object(), object())  # type: ignore[arg-type]
    assert result.overall_assessment is AssessmentStatus.INCOMPARABLE
    assert result.findings == ()


def test_finding_categories_and_rule_limitations_are_independent_of_scope() -> None:
    baseline = bundle(finding("a"), finding("b", "src/b.js"), scanned=("src/a.js", "src/b.js"))
    current = bundle(finding("a"), finding("c", "src/c.js"), scanned=("src/a.js", "src/c.js"))
    result = evaluate_finding_disappearance(baseline, current)

    assert {item.category for item in result.findings} == {
        FindingCategory.SHARED, FindingCategory.CURRENT_ONLY, FindingCategory.BASELINE_ONLY
    }
    assert "rule_bytes_unverified" in result.limitation_codes
    assert "loaded_rule_identity_unverified" in result.limitation_codes
    assert "source_snapshot_not_collected" in result.limitation_codes
    assert result.findings[-1].rule_identity_hypothesis is AssessmentStatus.UNDETERMINED


def test_scope_status_not_collected_is_not_interpreted_as_path_absence() -> None:
    baseline = bundle(finding("b", "src/b.js"), scanned=("src/b.js",))
    current = bundle(
        scanned=(), scanned_status=EvidenceStatus.NOT_COLLECTED,
        skipped=(), skipped_status=EvidenceStatus.NOT_COLLECTED,
    )
    result = evaluate_finding_disappearance(baseline, current)
    assert result.findings[0].path_observation is PathObservation.SCOPE_EVIDENCE_UNAVAILABLE
    assert result.findings[0].skip_hypothesis is AssessmentStatus.UNDETERMINED


def test_manifest_path_unicode_is_safe_and_scope_conflicts_do_not_leak_path() -> None:
    baseline = bundle(finding("b", "src/보안.js"), scanned=("src/보안.js",))
    current = bundle(
        scanned=("src/보안.js",),
        skipped=(SkippedPathEvidence("src/보안.js", "semgrepignore_patterns_match"),),
        skipped_status=EvidenceStatus.OBSERVED,
    )
    result = evaluate_finding_disappearance(baseline, current)
    assert result.findings[0].path_observation is PathObservation.CONFLICTING
    assert "src/보안.js" not in repr(result)


def test_finding_order_does_not_change_evaluation_output() -> None:
    first = evaluate_finding_disappearance(
        bundle(finding("a"), finding("b", "src/b.js")),
        bundle(finding("d"), finding("c", "src/c.js")),
    )
    second = evaluate_finding_disappearance(
        bundle(finding("b", "src/b.js"), finding("a")),
        bundle(finding("c", "src/c.js"), finding("d")),
    )
    assert [(item.category, item.finding_id) for item in first.findings] == [
        (item.category, item.finding_id) for item in second.findings
    ]


def test_finding_without_path_keeps_scope_hypothesis_undetermined() -> None:
    baseline = bundle(finding("b", None), scanned=())
    current = bundle(scanned=(), skipped_status=EvidenceStatus.OBSERVED)
    result = evaluate_finding_disappearance(baseline, current)
    assert result.findings[0].path_observation is PathObservation.FINDING_PATH_UNAVAILABLE
    assert result.findings[0].skip_hypothesis is AssessmentStatus.UNDETERMINED


def test_same_finding_id_does_not_assert_same_code_and_inputs_are_immutable() -> None:
    baseline = bundle(finding("a"))
    current = bundle(finding("a"))
    original = (baseline.response.model_dump(), baseline.manifest)
    result = evaluate_finding_disappearance(baseline, current)
    assert result.findings[0].category is FindingCategory.SHARED
    assert result.findings[0].source_snapshot_hypothesis is None
    assert "source_snapshot_not_collected" in result.limitation_codes
    assert baseline.response.model_dump() == original[0]
    assert baseline.manifest == original[1]


def test_results_are_deterministic_and_do_not_contain_source_or_secrets() -> None:
    baseline = bundle(finding("b", "synthetic-canary/hidden.js"), scanned=("synthetic-canary/hidden.js",))
    current = bundle(scanned=(), skipped_status=EvidenceStatus.OBSERVED)
    first = evaluate_finding_disappearance(baseline, current)
    second = evaluate_finding_disappearance(baseline, current)
    assert first == second
    assert "synthetic-canary" not in repr(first)
    assert "DO_NOT_LEAK_TOKEN" not in repr(first)
    assert "raw_stderr" not in repr(first)


def test_output_limit_fails_closed_without_partial_findings() -> None:
    import ai_code_security_analyzer.finding_disappearance_evaluator as evaluator

    baseline = bundle(finding("b"))
    current = bundle()
    old_limit = evaluator.MAX_EVALUATION_BYTES
    try:
        evaluator.MAX_EVALUATION_BYTES = 1
        result = evaluate_finding_disappearance(baseline, current)
    finally:
        evaluator.MAX_EVALUATION_BYTES = old_limit
    assert result.overall_assessment is AssessmentStatus.INCOMPARABLE
    assert result.findings == ()
    assert "evaluation_output_limit_exceeded" in result.limitation_codes


def test_no_finding_is_not_a_safety_statement_and_empty_difference_is_undetermined() -> None:
    result = evaluate_finding_disappearance(bundle(), bundle())
    assert result.findings == ()
    assert result.overall_assessment is AssessmentStatus.UNDETERMINED
    assert "scan_result_is_not_safety_proof" in result.limitation_codes


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_real_semgrep_same_finding_then_unobserved_stays_undetermined(tmp_path: Path) -> None:
    import subprocess

    version = subprocess.run(
        ["semgrep", "--version"], check=True, capture_output=True, text=True, timeout=10
    ).stdout.strip()
    if version != "1.182.1":
        pytest.skip(f"requires Semgrep 1.182.1, found {version}")

    repository = Path(__file__).resolve().parents[1]
    target = tmp_path / "synthetic-target"
    target.mkdir()
    sample = target / "stable.js"
    sample.write_text('const input = "2 + 2";\neval(input);\n')
    service = ScanService(ApiSettings(target, repository / "rules", "z" * 48))

    first_response, first_manifest = service._scan_with_manifest("local-project", "baseline")
    same_response, same_manifest = service._scan_with_manifest("local-project", "baseline")
    first = bind_run_evidence(first_response, first_manifest)
    same = bind_run_evidence(same_response, same_manifest)
    shared = evaluate_finding_disappearance(first, same)
    assert first_manifest.scan_ref != same_manifest.scan_ref
    assert first_response.findings
    assert shared.findings[0].category is FindingCategory.SHARED
    assert shared.findings[0].source_snapshot_hypothesis is None
    assert "source_snapshot_not_collected" in shared.limitation_codes

    sample.write_text('const parsed = JSON.parse("{\\"ok\\":true}");\n')
    changed_response, changed_manifest = service._scan_with_manifest("local-project", "baseline")
    changed = evaluate_finding_disappearance(first, bind_run_evidence(changed_response, changed_manifest))
    assert changed_response.scan_status is ScanStatus.COMPLETED
    assert any(item.category is FindingCategory.BASELINE_ONLY for item in changed.findings)
    assert changed.overall_assessment is AssessmentStatus.UNDETERMINED
    assert all(item.source_snapshot_hypothesis is AssessmentStatus.UNDETERMINED for item in changed.findings if item.category is FindingCategory.BASELINE_ONLY)
