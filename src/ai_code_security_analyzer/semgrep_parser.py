"""Convert bounded Semgrep JSON into the public Finding contract."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_code_security_analyzer.models import Finding, Severity
from ai_code_security_analyzer.scan_evidence_manifest import (
    ScopeEvidence,
    only_adapter_policy_exclusions,
    parse_scope_evidence,
    unavailable_scope_evidence,
)


_CWE_PATTERN = re.compile(r"\bCWE-([1-9][0-9]*)\b", re.IGNORECASE)
_SEVERITIES = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class InvalidSemgrepJson(ValueError):
    """The output is not a usable Semgrep JSON document."""


@dataclass(frozen=True)
class ParsedFindings:
    findings: tuple[Finding, ...]
    issues: tuple[str, ...]


@dataclass(frozen=True)
class _ParsedSemgrepDocument:
    parsed: ParsedFindings
    document: dict[str, Any]
    result_findings: tuple[Finding | None, ...]
    scope_evidence: ScopeEvidence


def _positive_int(value: Any) -> int | None:
    return value if type(value) is int and value > 0 else None


def _nonempty_string(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _relative_path(value: Any, project_root: Path) -> str | None:
    raw = _nonempty_string(value)
    if raw is None:
        return None
    try:
        candidate = Path(raw)
        resolved = (project_root / candidate).resolve()
        relative = resolved.relative_to(project_root).as_posix()
        return relative if relative != "." else None
    except (OSError, ValueError, RuntimeError):
        return None


def _cwe(value: Any) -> tuple[str | None, str | None]:
    """Keep the first distinct CWE; report loss when metadata contains more."""
    if value is None:
        return None, None
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        return None, "invalid_cwe_metadata"
    matches = [f"CWE-{match.group(1)}" for item in values for match in _CWE_PATTERN.finditer(item)]
    unique = list(dict.fromkeys(matches))
    if not unique:
        return None, "invalid_cwe_metadata"
    return unique[0], "multiple_cwe_values" if len(unique) > 1 else None


def _finding_id(rule_id: str, path: str, line: int, column: int, end_line: int, end_column: int) -> str:
    stable_location = json.dumps(
        [rule_id, path, line, column, end_line, end_column], separators=(",", ":"), ensure_ascii=False
    )
    return "semgrep:" + hashlib.sha256(stable_location.encode("utf-8")).hexdigest()[:24]


def _convert(item: Any, project_root: Path) -> tuple[Finding | None, str | None]:
    if not isinstance(item, dict):
        return None, "invalid_result"
    rule_id = _nonempty_string(item.get("check_id"))
    path = _relative_path(item.get("path"), project_root)
    start = item.get("start")
    extra = item.get("extra")
    if not isinstance(start, dict) or not isinstance(extra, dict):
        return None, "invalid_result"
    line = _positive_int(start.get("line"))
    # Semgrep's message is parsed but never copied into the public Finding:
    # rule messages and matched code can contain secrets or source excerpts.
    message = _nonempty_string(extra.get("message"))
    if rule_id is None or path is None or line is None or message is None:
        return None, "invalid_result"
    severity_name = _nonempty_string(extra.get("severity"))
    if severity_name is None or severity_name.upper() not in _SEVERITIES:
        return None, "unknown_severity"
    metadata = extra.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        return None, "invalid_result"
    cwe, cwe_issue = _cwe(metadata.get("cwe") if metadata else None)
    end = item.get("end")
    end = end if isinstance(end, dict) else {}
    column = _positive_int(start.get("col")) or 0
    end_line = _positive_int(end.get("line")) or 0
    end_column = _positive_int(end.get("col")) or 0
    finding = Finding(
        finding_id=_finding_id(rule_id, path, line, column, end_line, end_column),
        rule_id=rule_id,
        title=rule_id,
        description="Semgrep reported a rule match. Review the source locally for context.",
        severity=_SEVERITIES[severity_name.upper()],
        source_tool="semgrep",
        file_path=path,
        line_number=line,
        evidence=f"Rule matched at line {line}.",
        cwe=cwe,
    )
    return finding, cwe_issue


def _parse_semgrep_json_internal(raw: bytes, project_root: Path) -> _ParsedSemgrepDocument:
    """Parse bounded JSON for internal consumers; raw fields stay transient."""
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidSemgrepJson("invalid Semgrep JSON") from None
    if not isinstance(document, dict) or not isinstance(document.get("results"), list) or not isinstance(document.get("errors"), list):
        raise InvalidSemgrepJson("invalid Semgrep JSON structure")

    project_root = project_root.resolve()
    findings: list[Finding] = []
    result_findings: list[Finding | None] = []
    issues: list[str] = []
    if document["errors"]:
        issues.append("semgrep_reported_errors")
    skipped_rules = document.get("skipped_rules")
    if skipped_rules:
        issues.append("semgrep_skipped_rules")
    paths = document.get("paths")
    try:
        scope_evidence = parse_scope_evidence(document, project_root)
    except Exception:
        # Scope capture is supplemental. Never discard parsed findings because
        # an auxiliary path observation could not be represented safely.
        scope_evidence = unavailable_scope_evidence("scope_capture_failed")
    if isinstance(paths, dict):
        # The adapter's own fixed exclusions are part of every scan and are
        # recorded in the scope evidence. Any other skip, and any skip list
        # that could not be validated, still makes the scan partial.
        if paths.get("skipped") and not only_adapter_policy_exclusions(scope_evidence):
            issues.append("semgrep_skipped_paths")
        if paths.get("scanned") == []:
            issues.append("no_files_scanned")
    for index, item in enumerate(document["results"]):
        finding, issue = _convert(item, project_root)
        result_findings.append(finding)
        if finding is not None:
            findings.append(finding)
        if issue is not None:
            issues.append(f"result_{index}_{issue}")
    parsed = ParsedFindings(tuple(findings), tuple(issues))
    return _ParsedSemgrepDocument(parsed, document, tuple(result_findings), scope_evidence)


def parse_semgrep_json(raw: bytes, project_root: Path) -> ParsedFindings:
    """Parse output without exposing raw diagnostics or matched source code."""
    return _parse_semgrep_json_internal(raw, project_root).parsed
