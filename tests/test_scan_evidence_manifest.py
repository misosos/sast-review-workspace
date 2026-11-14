from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import pytest

from ai_code_security_analyzer.scan_evidence_manifest import (
    ADAPTER_EXCLUDED_NAMES,
    EvidenceStatus,
    ManifestBindingError,
    ScanEvidenceManifest,
    create_scan_evidence_manifest,
    new_scan_ref,
    only_adapter_policy_exclusions,
    parse_scope_evidence,
    stored_skip_is_valid,
    validate_manifest_binding,
)
from ai_code_security_analyzer.semgrep_adapter import ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService


def semgrep_document(*, scanned: object = None, paths: object = None) -> dict[str, object]:
    if paths is None:
        paths = {"scanned": scanned}
    return {"results": [], "errors": [], "paths": paths}


def test_scan_reference_is_unpredictable_and_unique_per_run() -> None:
    first, second = new_scan_ref(), new_scan_ref()
    assert first != second
    assert re.fullmatch(r"[A-Za-z0-9_-]{32,64}", first)


def test_scope_observes_valid_relative_and_unicode_paths(tmp_path: Path) -> None:
    scope = parse_scope_evidence(
        semgrep_document(scanned=["src/a.js", "보안/검토.ts"]), tmp_path
    )
    assert scope.scanned_status is EvidenceStatus.OBSERVED
    assert scope.completeness_status is EvidenceStatus.UNVERIFIED
    assert scope.paths_object_present is True
    assert scope.scanned_field_present is True
    assert scope.reported_scanned_count == 2
    assert scope.scanned_paths == ("src/a.js", "보안/검토.ts")
    assert scope.skipped_status is EvidenceStatus.NOT_COLLECTED


def test_empty_scanned_list_is_observed_not_missing(tmp_path: Path) -> None:
    scope = parse_scope_evidence(semgrep_document(scanned=[]), tmp_path)
    assert scope.scanned_status is EvidenceStatus.OBSERVED
    assert scope.scanned_paths == ()
    assert scope.reported_scanned_count == 0


@pytest.mark.parametrize(
    "document",
    [
        {"results": [], "errors": []},
        {"results": [], "errors": [], "paths": {}},
    ],
)
def test_missing_paths_or_scanned_is_not_collected(document: dict[str, object], tmp_path: Path) -> None:
    scope = parse_scope_evidence(document, tmp_path)
    assert scope.scanned_status is EvidenceStatus.NOT_COLLECTED
    assert scope.scanned_paths == ()
    assert scope.reported_scanned_count is None


@pytest.mark.parametrize(
    "paths",
    [
        [],
        {"scanned": "src/a.js"},
        {"scanned": ["src/a.js", 3]},
        {"scanned": ["../outside.js"]},
        {"scanned": ["/etc/passwd"]},
        {"scanned": ["C:/private/file.js"]},
        {"scanned": ["src\\file.js"]},
        {"scanned": ["src/./file.js"]},
        {"scanned": ["src//file.js"]},
        {"scanned": ["src/\x00file.js"]},
        {"scanned": ["src/\u202efile.js"]},
    ],
)
def test_invalid_scanned_paths_make_whole_evidence_unavailable(paths: object, tmp_path: Path) -> None:
    scope = parse_scope_evidence({"results": [], "errors": [], "paths": paths}, tmp_path)
    assert scope.scanned_status is EvidenceStatus.UNAVAILABLE
    assert scope.scanned_paths == ()
    if isinstance(paths, dict) and isinstance(paths.get("scanned"), list):
        assert scope.reported_scanned_count == len(paths["scanned"])
    else:
        assert scope.reported_scanned_count is None


def test_absolute_path_inside_project_is_reduced_to_relative(tmp_path: Path) -> None:
    scope = parse_scope_evidence(semgrep_document(scanned=[str(tmp_path / "src" / "a.js")]), tmp_path)
    assert scope.scanned_status is EvidenceStatus.OBSERVED
    assert scope.scanned_paths == ("src/a.js",)
    assert str(tmp_path) not in repr(scope)


def test_symlink_scope_path_is_rejected(tmp_path: Path) -> None:
    external = tmp_path.parent / "outside-synthetic.js"
    external.write_text("synthetic only")
    (tmp_path / "link.js").symlink_to(external)
    scope = parse_scope_evidence(semgrep_document(scanned=["link.js"]), tmp_path)
    assert scope.scanned_status is EvidenceStatus.UNAVAILABLE
    assert scope.scanned_paths == ()


def test_duplicate_paths_make_scope_unavailable_instead_of_silent_dedup(tmp_path: Path) -> None:
    scope = parse_scope_evidence(semgrep_document(scanned=["src/a.js", "src/a.js"]), tmp_path)
    assert scope.scanned_status is EvidenceStatus.UNAVAILABLE
    assert "duplicate_scanned_path" in scope.limitations


def test_unicode_normalization_collision_makes_scope_unavailable(tmp_path: Path) -> None:
    composed = "café.js"
    decomposed = unicodedata.normalize("NFD", composed)
    scope = parse_scope_evidence(semgrep_document(scanned=[composed, decomposed]), tmp_path)
    assert scope.scanned_status is EvidenceStatus.UNAVAILABLE
    assert "normalized_path_collision" in scope.limitations


def test_path_count_and_manifest_byte_limits_fail_closed(tmp_path: Path) -> None:
    from ai_code_security_analyzer.scan_evidence_manifest import (
        MAX_SCANNED_PATHS,
        MAX_SCOPE_PATH_BYTES,
    )

    too_many = [f"f/{index}.js" for index in range(MAX_SCANNED_PATHS + 1)]
    count_limited = parse_scope_evidence(semgrep_document(scanned=too_many), tmp_path)
    assert count_limited.scanned_status is EvidenceStatus.UNAVAILABLE
    too_long = "x" * (MAX_SCOPE_PATH_BYTES + 1)
    byte_limited = parse_scope_evidence(semgrep_document(scanned=[too_long]), tmp_path)
    assert byte_limited.scanned_status is EvidenceStatus.UNAVAILABLE


def test_skips_are_not_collected_unless_present_and_allowlisted(tmp_path: Path) -> None:
    absent = parse_scope_evidence(semgrep_document(scanned=[]), tmp_path)
    assert absent.skipped_status is EvidenceStatus.NOT_COLLECTED

    present = parse_scope_evidence(
        semgrep_document(paths={"scanned": [], "skipped": [
            {"path": "ignored.js", "reason": "semgrepignore_patterns_match"}
        ]}), tmp_path
    )
    assert present.skipped_status is EvidenceStatus.OBSERVED
    assert [(item.path, item.reason_code) for item in present.skipped_paths] == [
        ("ignored.js", "semgrepignore_patterns_match")
    ]

    unknown = parse_scope_evidence(
        semgrep_document(paths={"scanned": [], "skipped": [
            {"path": "ignored.js", "reason": "arbitrary message with source"}
        ]}), tmp_path
    )
    assert unknown.skipped_status is EvidenceStatus.UNAVAILABLE
    assert unknown.skipped_paths == ()
    assert "arbitrary message with source" not in repr(unknown)


def _skips(tmp_path: Path, *items: tuple[str, str]) -> object:
    return parse_scope_evidence(
        semgrep_document(paths={"scanned": [], "skipped": [{"path": path, "reason": reason} for path, reason in items]}),
        tmp_path,
    )


def test_adapter_owned_exclusions_are_recorded_under_their_own_reason(tmp_path: Path) -> None:
    scope = _skips(
        tmp_path,
        ("node_modules", "cli_exclude_flags_match"),
        ("packages/a/node_modules", "cli_exclude_flags_match"),
        (".venv", "cli_exclude_flags_match"),
        # Without a project ignore file Semgrep credits its default list for .git.
        (".git", "semgrepignore_patterns_match"),
        ("legacy/old.js", "semgrepignore_patterns_match"),
    )
    assert scope.skipped_status is EvidenceStatus.OBSERVED
    assert [(item.path, item.reason_code) for item in scope.skipped_paths] == [
        ("node_modules", "adapter_policy_exclusion"),
        ("packages/a/node_modules", "adapter_policy_exclusion"),
        (".venv", "adapter_policy_exclusion"),
        (".git", "adapter_policy_exclusion"),
        ("legacy/old.js", "semgrepignore_patterns_match"),
    ]
    assert only_adapter_policy_exclusions(scope) is False
    assert only_adapter_policy_exclusions(_skips(tmp_path, (".git", "cli_exclude_flags_match"))) is True


@pytest.mark.parametrize(
    "path, reason",
    [
        # A CLI exclusion the adapter never asked for.
        ("src", "cli_exclude_flags_match"),
        ("node_modules.js", "cli_exclude_flags_match"),
        ("venv", "cli_exclude_flags_match"),
        ("node_modules/pkg", "cli_exclude_flags_match"),
        # Reasons outside the closed set, even on an excluded name.
        ("node_modules", "analysis_failed_parser_or_internal_error"),
        ("src/big.js", "too_big"),
        (".git", "adapter_policy_exclusion"),
        (".git", ""),
    ],
)
def test_unexpected_skips_stay_unrecognized(tmp_path: Path, path: str, reason: str) -> None:
    scope = _skips(tmp_path, (".venv", "cli_exclude_flags_match"), (path, reason))
    assert scope.skipped_status is EvidenceStatus.UNAVAILABLE
    assert scope.skipped_paths == ()
    assert "skipped_reason_unrecognized" in scope.limitations
    assert only_adapter_policy_exclusions(scope) is False


def test_stored_skip_reasons_have_one_canonical_form() -> None:
    assert stored_skip_is_valid("a/node_modules", "adapter_policy_exclusion")
    assert stored_skip_is_valid("src/old.js", "semgrepignore_patterns_match")
    assert not stored_skip_is_valid("src/old.js", "adapter_policy_exclusion")
    assert not stored_skip_is_valid("a/node_modules", "semgrepignore_patterns_match")
    assert not stored_skip_is_valid("a/node_modules", "cli_exclude_flags_match")
    assert not stored_skip_is_valid(None, "adapter_policy_exclusion")
    assert ADAPTER_EXCLUDED_NAMES == (".git", "node_modules", ".venv")


def test_skipped_paths_are_path_validated_and_bounded(tmp_path: Path) -> None:
    outside = parse_scope_evidence(
        semgrep_document(paths={"scanned": [], "skipped": [{
            "path": "../../secret", "reason": "semgrepignore_patterns_match"
        }]}), tmp_path
    )
    assert outside.skipped_status is EvidenceStatus.UNAVAILABLE
    assert outside.skipped_paths == ()


def test_counts_only_structural_skip_and_error_metadata(tmp_path: Path) -> None:
    scope = parse_scope_evidence({
        "results": [], "errors": [{"message": "DO_NOT_RETAIN_THIS"}],
        "skipped_rules": [{"id": "x"}],
        "paths": {"scanned": []},
    }, tmp_path)
    assert scope.skipped_rules_status is EvidenceStatus.OBSERVED
    assert scope.skipped_rules_count == 1
    assert scope.errors_status is EvidenceStatus.OBSERVED
    assert scope.errors_count == 1
    assert "DO_NOT_RETAIN_THIS" not in repr(scope)


def test_malformed_scope_does_not_invalidate_finding_parse(tmp_path: Path) -> None:
    finding = {
        "check_id": "sample.rule", "path": "src/a.js",
        "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 8},
        "extra": {"message": "synthetic message", "severity": "WARNING"},
    }
    document = {
        "results": [finding], "errors": [], "paths": {"scanned": "wrong-shape"},
    }
    parsed = _parse_semgrep_json_internal(json.dumps(document).encode(), tmp_path)
    assert len(parsed.parsed.findings) == 1
    assert parsed.scope_evidence.scanned_status is EvidenceStatus.UNAVAILABLE


def test_manifest_binds_run_target_profile_rule_and_findings(tmp_path: Path) -> None:
    scan_ref = new_scan_ref()
    scope = parse_scope_evidence(semgrep_document(scanned=["a.js"]), tmp_path)
    manifest = create_scan_evidence_manifest(
        scan_ref=scan_ref,
        target_id="alpha",
        rule_profile_id="baseline",
        semgrep_version="1.182.1",
        exit_code=0,
        scan_status=ScanStatus.COMPLETED.value,
        finding_count=1,
        displayed_finding_count=1,
        omitted_finding_count=0,
        finding_ids=("semgrep:" + "a" * 24,),
        selected_rule_file_id="security-baseline.yml",
        scope_evidence=scope,
    )
    assert manifest.contract_version == "scan-evidence-manifest/v1"
    assert manifest.scan_ref == scan_ref
    assert manifest.target_id == "alpha"
    assert manifest.rule_profile_id == "baseline"
    assert manifest.finding_ids == ("semgrep:" + "a" * 24,)
    assert manifest.rule_evidence.byte_identity_status is EvidenceStatus.UNVERIFIED
    assert manifest.rule_evidence.loaded_identity_status is EvidenceStatus.UNVERIFIED
    validate_manifest_binding(manifest, scan_ref, "alpha", "baseline")
    with pytest.raises(ManifestBindingError):
        validate_manifest_binding(manifest, scan_ref, "beta", "baseline")
    with pytest.raises(ManifestBindingError):
        validate_manifest_binding(manifest, new_scan_ref(), "alpha", "baseline")


def test_manifest_rejects_count_or_finding_reference_mismatch(tmp_path: Path) -> None:
    scope = parse_scope_evidence(semgrep_document(scanned=[]), tmp_path)
    with pytest.raises(ManifestBindingError, match="finding_count_binding_invalid"):
        create_scan_evidence_manifest(
            scan_ref=new_scan_ref(), target_id="alpha", rule_profile_id="baseline",
            semgrep_version="1.182.1", exit_code=0,
            scan_status=ScanStatus.COMPLETED.value,
            finding_count=2, displayed_finding_count=1, omitted_finding_count=0,
            finding_ids=("semgrep:" + "a" * 24,),
            selected_rule_file_id="security-baseline.yml", scope_evidence=scope,
        )


def test_manifest_byte_limit_marks_entire_scope_unavailable(tmp_path: Path) -> None:
    paths = []
    for index in range(1_140):
        prefix = f"f{index}/"
        paths.append(prefix + "x" * (916 - len(prefix)))
    scope = parse_scope_evidence(semgrep_document(scanned=paths), tmp_path)
    assert scope.scanned_status is EvidenceStatus.OBSERVED
    manifest = create_scan_evidence_manifest(
        scan_ref=new_scan_ref(), target_id="alpha", rule_profile_id="baseline",
        semgrep_version="1.182.1", exit_code=0,
        scan_status=ScanStatus.COMPLETED.value,
        finding_count=0, displayed_finding_count=0, omitted_finding_count=0,
        finding_ids=(), selected_rule_file_id="security-baseline.yml", scope_evidence=scope,
    )
    assert manifest.scope_evidence.scanned_status is EvidenceStatus.UNAVAILABLE
    assert manifest.scope_evidence.scanned_paths == ()
    assert "manifest_byte_limit_exceeded" in manifest.scope_evidence.limitations


def test_internal_manifest_has_no_absolute_path_or_raw_payload(tmp_path: Path) -> None:
    scope = parse_scope_evidence(
        {"results": [], "errors": [{"message": "SYNTHETIC_RAW_SECRET"}],
         "paths": {"scanned": [str(tmp_path / "src" / "file.js")] }}, tmp_path
    )
    manifest = create_scan_evidence_manifest(
        scan_ref=new_scan_ref(), target_id="alpha", rule_profile_id="baseline",
        semgrep_version="1.182.1", scan_status=ScanStatus.COMPLETED.value,
        exit_code=0,
        finding_count=0, displayed_finding_count=0, omitted_finding_count=0,
        finding_ids=(), selected_rule_file_id="security-baseline.yml", scope_evidence=scope,
    )
    rendered = repr(manifest)
    assert str(tmp_path) not in rendered
    assert "SYNTHETIC_RAW_SECRET" not in rendered


def test_service_internal_manifest_is_run_scoped_without_changing_api_response(tmp_path: Path) -> None:
    target, rules = tmp_path / "project", tmp_path / "rules"
    target.mkdir()
    rules.mkdir()
    (rules / "security-baseline.yml").write_text("rules: []\n")
    (rules / "experimental").mkdir()
    (rules / "experimental" / "javascript-eval-taint.yml").write_text("rules: []\n")
    (rules / "experimental" / "javascript-command-injection-taint.yml").write_text("rules: []\n")
    calls = 0
    verbose_modes: list[bool] = []

    class Adapter:
        def __init__(self, _root: Path) -> None: pass

        def _scan_with_evidence(self, _target: Path, _rules: Path, *, investigation_verbose: bool = False):
            from types import SimpleNamespace
            nonlocal calls
            calls += 1
            verbose_modes.append(investigation_verbose)
            parsed = parse_scope_evidence(semgrep_document(scanned=["src/a.js"]), target)
            return SimpleNamespace(
                result=SimpleNamespace(
                    status=ScanStatus.COMPLETED, findings=(), issues=(),
                    semgrep_version="1.182.1",
                ),
                taint_evidence=(), scope_evidence=parsed,
            )

    settings = ApiSettings(target, rules, "z" * 48)
    service = ScanService(settings, adapter_factory=Adapter)
    first_response, first_manifest = service._scan_with_manifest("local-project", "baseline")
    second_response, second_manifest = service._scan_with_manifest("local-project", "baseline")
    verbose_response, verbose_manifest = service._scan_with_manifest("local-project", "baseline", investigation_verbose=True)
    assert calls == 3
    assert verbose_modes == [False, False, True]
    assert first_response == second_response
    assert first_manifest.scan_ref != second_manifest.scan_ref
    assert first_manifest.scope_evidence.scanned_paths == ("src/a.js",)
    assert first_manifest.finding_ids == ()
    assert verbose_response == first_response
    assert verbose_manifest.execution_evidence.invocation_id == "semgrep-json-investigation-verbose-v1"
    assert first_manifest.execution_evidence.invocation_id == "semgrep-json-local-v1"
    assert first_manifest.finding_count == first_manifest.displayed_finding_count == first_manifest.omitted_finding_count == 0
    assert str(tmp_path) not in first_response.model_dump_json()
    assert set(first_response.model_dump()) == {
        "scan_status", "completed", "semgrep_version", "finding_count",
        "displayed_finding_count", "omitted_finding_count", "severity_counts",
        "issues", "findings", "limitations",
    }


def test_manifest_invocation_identity_is_closed_and_defaults_remain_compatible(tmp_path: Path) -> None:
    from ai_code_security_analyzer.scan_evidence_manifest import (
        INVESTIGATION_VERBOSE_INVOCATION_ID,
        ManifestBindingError,
        create_scan_evidence_manifest,
    )

    arguments = {
        "scan_ref": "A" * 32, "target_id": "target", "rule_profile_id": "baseline",
        "semgrep_version": "1.182.1", "exit_code": 0, "scan_status": "completed",
        "finding_count": 0, "displayed_finding_count": 0, "omitted_finding_count": 0,
        "finding_ids": (), "selected_rule_file_id": "security-baseline.yml",
        "scope_evidence": parse_scope_evidence(semgrep_document(scanned=[]), tmp_path),
    }
    assert create_scan_evidence_manifest(**arguments).execution_evidence.invocation_id == "semgrep-json-local-v1"
    assert create_scan_evidence_manifest(**arguments, invocation_id=INVESTIGATION_VERBOSE_INVOCATION_ID).execution_evidence.invocation_id == INVESTIGATION_VERBOSE_INVOCATION_ID
    with pytest.raises(ManifestBindingError):
        create_scan_evidence_manifest(**arguments, invocation_id="semgrep-json-user-controlled")
