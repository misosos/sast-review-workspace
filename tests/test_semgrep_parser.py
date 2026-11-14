import json
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.semgrep_parser import InvalidSemgrepJson, parse_semgrep_json


def result(**changes: object) -> dict[str, object]:
    item: dict[str, object] = {
        "check_id": "local.sample-rule",
        "path": "src/example.py",
        "start": {"line": 4, "col": 2},
        "end": {"line": 4, "col": 12},
        "extra": {
            "message": "Synthetic rule message",
            "severity": "ERROR",
            "metadata": {"cwe": "CWE-89: SQL Injection"},
        },
    }
    item.update(changes)
    return item


def output(results: list[object], errors: list[object] | None = None) -> bytes:
    return json.dumps({"results": results, "errors": errors or []}).encode()


def test_one_and_multiple_findings(tmp_path: Path) -> None:
    first = parse_semgrep_json(output([result()]), tmp_path)
    second = parse_semgrep_json(
        output([result(), result(path="src/other.py", start={"line": 9})]), tmp_path
    )

    assert len(first.findings) == 1
    assert len(second.findings) == 2
    assert first.issues == ()
    finding = first.findings[0]
    assert finding.rule_id == "local.sample-rule"
    assert finding.file_path == "src/example.py"
    assert finding.line_number == 4
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-89"
    assert finding.source_tool == "semgrep"
    assert finding.status is FindingStatus.UNVERIFIED
    assert all(item.status is FindingStatus.UNVERIFIED for item in second.findings)


def test_empty_results_are_valid(tmp_path: Path) -> None:
    parsed = parse_semgrep_json(output([]), tmp_path)
    assert parsed.findings == ()
    assert parsed.issues == ()


def _issues_for_skips(tmp_path: Path, skipped: object) -> tuple[str, ...]:
    raw = json.dumps({"results": [], "errors": [], "paths": {"scanned": ["src/app.js"], "skipped": skipped}}).encode()
    return parse_semgrep_json(raw, tmp_path).issues


def test_adapter_owned_exclusions_alone_do_not_make_a_scan_partial(tmp_path: Path) -> None:
    assert _issues_for_skips(tmp_path, [
        {"path": ".git", "reason": "semgrepignore_patterns_match"},
        {"path": "node_modules", "reason": "cli_exclude_flags_match"},
        {"path": "packages/a/.venv", "reason": "cli_exclude_flags_match"},
    ]) == ()


@pytest.mark.parametrize(
    "skipped",
    [
        # A project ignore rule next to the adapter's exclusions.
        [{"path": "node_modules", "reason": "cli_exclude_flags_match"},
         {"path": "legacy/old.js", "reason": "semgrepignore_patterns_match"}],
        # A CLI exclusion on a path the adapter does not exclude.
        [{"path": "src", "reason": "cli_exclude_flags_match"}],
        # A reason outside the closed set.
        [{"path": "src/broken.ts", "reason": "analysis_failed_parser_or_internal_error"}],
        [{"path": "node_modules", "reason": "too_big"}],
        # Malformed entries and structures.
        [{"path": "node_modules"}],
        [{"path": "../node_modules", "reason": "cli_exclude_flags_match"}],
        ["node_modules"],
        {"path": "node_modules", "reason": "cli_exclude_flags_match"},
    ],
)
def test_any_other_skip_still_makes_a_scan_partial(tmp_path: Path, skipped: object) -> None:
    assert _issues_for_skips(tmp_path, skipped) == ("semgrep_skipped_paths",)


def test_skipped_rules_or_paths_are_partial_evidence(tmp_path: Path) -> None:
    raw = json.dumps({
        "results": [], "errors": [], "skipped_rules": [{"id": "local.bad"}],
        "paths": {"scanned": [], "skipped": [{"path": "large.py"}]},
    }).encode()
    parsed = parse_semgrep_json(raw, tmp_path)
    assert parsed.issues == ("semgrep_skipped_rules", "semgrep_skipped_paths", "no_files_scanned")


@pytest.mark.parametrize(
    "raw_severity,expected",
    [
        ("CRITICAL", Severity.CRITICAL), ("HIGH", Severity.HIGH),
        ("ERROR", Severity.HIGH), ("MEDIUM", Severity.MEDIUM),
        ("WARNING", Severity.MEDIUM), ("LOW", Severity.LOW),
        ("INFO", Severity.INFO),
    ],
)
def test_severity_mapping(tmp_path: Path, raw_severity: str, expected: Severity) -> None:
    parsed = parse_semgrep_json(output([result(extra={"message": "Synthetic", "severity": raw_severity})]), tmp_path)
    assert parsed.findings[0].severity is expected


def test_unknown_severity_is_reported_without_guessing(tmp_path: Path) -> None:
    parsed = parse_semgrep_json(output([result(extra={"message": "Synthetic", "severity": "BLOCKER"})]), tmp_path)
    assert parsed.findings == ()
    assert parsed.issues == ("result_0_unknown_severity",)


@pytest.mark.parametrize(
    "metadata,expected_cwe,expected_issue",
    [
        ({"cwe": "CWE-89: SQL Injection"}, "CWE-89", ()),
        ({"cwe": ["CWE-89", "CWE-78: Command Injection"]}, "CWE-89", ("result_0_multiple_cwe_values",)),
        ({}, None, ()),
        ({"cwe": {"id": "CWE-89"}}, None, ("result_0_invalid_cwe_metadata",)),
    ],
)
def test_cwe_metadata(tmp_path: Path, metadata: object, expected_cwe: str | None, expected_issue: tuple[str, ...]) -> None:
    parsed = parse_semgrep_json(output([result(extra={"message": "Synthetic", "severity": "INFO", "metadata": metadata})]), tmp_path)
    assert parsed.findings[0].cwe == expected_cwe
    assert parsed.issues == expected_issue


@pytest.mark.parametrize(
    "changes",
    [
        {"check_id": None}, {"path": "../outside.py"}, {"start": {"line": 0}},
        {"start": {"line": "4"}}, {"extra": {"severity": "INFO"}},
        {"extra": {"message": "Synthetic", "severity": "INFO", "metadata": []}},
    ],
)
def test_invalid_result_is_skipped_with_issue(tmp_path: Path, changes: dict[str, object]) -> None:
    parsed = parse_semgrep_json(output([result(**changes)]), tmp_path)
    assert parsed.findings == ()
    assert parsed.issues == ("result_0_invalid_result",)


@pytest.mark.parametrize("raw", [b"{broken", b"[]", b'{"results": {}}', b'{"results": [], "errors": {}}'])
def test_invalid_document_raises_safe_error(tmp_path: Path, raw: bytes) -> None:
    with pytest.raises(InvalidSemgrepJson, match="invalid Semgrep JSON"):
        parse_semgrep_json(raw, tmp_path)


def test_deterministic_id_uses_relative_path_and_position(tmp_path: Path) -> None:
    relative = parse_semgrep_json(output([result(path="./src/example.py")]), tmp_path).findings[0]
    absolute = parse_semgrep_json(output([result(path=str(tmp_path / "src/example.py"))]), tmp_path).findings[0]
    moved = parse_semgrep_json(output([result(path="src/example.py", start={"line": 5, "col": 2})]), tmp_path).findings[0]

    assert relative.finding_id == absolute.finding_id
    assert relative.finding_id != moved.finding_id
    assert str(tmp_path) not in relative.finding_id


def test_semgrep_errors_and_sensitive_message_are_not_exposed(tmp_path: Path) -> None:
    secret = "synthetic-token-do-not-print"
    item = result(extra={"message": f"Matched {secret}", "severity": "ERROR", "lines": secret})
    parsed = parse_semgrep_json(output([item], [{"message": secret}]), tmp_path)

    assert parsed.issues == ("semgrep_reported_errors",)
    assert secret not in repr(parsed)
    assert secret not in parsed.findings[0].model_dump_json()
