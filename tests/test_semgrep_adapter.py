import json
import os
import sys
from pathlib import Path

import pytest

from ai_code_security_analyzer import semgrep_adapter
from ai_code_security_analyzer.scan_evidence_manifest import EvidenceStatus
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


@pytest.fixture
def paths(tmp_path: Path) -> tuple[SemgrepAdapter, Path, Path]:
    target = tmp_path / "project"
    target.mkdir()
    rules_directory = tmp_path / "trusted-rules"
    rules_directory.mkdir()
    rules = rules_directory / "local.yml"
    rules.write_text("rules: []\n")
    return SemgrepAdapter(rules_directory), target, rules


def finding_json() -> bytes:
    return json.dumps({
        "results": [{
            "check_id": "local.synthetic", "path": "sample.py", "start": {"line": 2},
            "extra": {"message": "Synthetic message", "severity": "WARNING"},
        }],
        "errors": [],
    }).encode()


def fake_semgrep(monkeypatch: pytest.MonkeyPatch, scan_output: bytes, *, exit_code: int = 0) -> list[tuple[list[str], Path]]:
    calls: list[tuple[list[str], Path]] = []
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        calls.append((args, cwd))
        assert "SYNTHETIC_SECRET" not in env
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.160.0\n")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(
                0, b"--json --metrics --disable-version-check --oss-only --no-autofix --no-git-ignore --verbose"
            )
        return semgrep_adapter._ProcessResult(exit_code, scan_output)

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    return calls


def test_scan_uses_local_rules_and_sanitized_environment(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setenv("SYNTHETIC_SECRET", "synthetic-token")
    calls = fake_semgrep(monkeypatch, finding_json())

    scanned = adapter.scan(target, rules)

    assert scanned.status is ScanStatus.COMPLETED
    assert scanned.semgrep_version == "1.160.0"
    assert len(scanned.findings) == 1
    assert scanned.findings[0].status.value == "unverified"
    args, cwd = calls[-1]
    assert args[1:8] == [
        "scan", "--json", "--metrics=off", "--disable-version-check", "--oss-only", "--no-autofix", "--no-git-ignore",
    ]
    assert args[-3:] == [rules.name, "--", str(target)]
    assert cwd == rules.parent
    assert "auto" not in args
    assert "--autofix" not in args


def test_investigation_verbose_option_is_explicit_and_keeps_skip_as_partial(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    (target / "ignored.js").write_text("synthetic only\n", encoding="utf-8")
    (target / "stable.js").write_text("synthetic only\n", encoding="utf-8")
    payload = {
        "results": [], "errors": [], "skipped_rules": [],
        "paths": {
            "scanned": ["stable.js"],
            "skipped": [{"path": "ignored.js", "reason": "semgrepignore_patterns_match"}],
        },
    }
    calls = fake_semgrep(monkeypatch, json.dumps(payload).encode())
    output = adapter._scan_with_evidence(target, rules, investigation_verbose=True)
    args = calls[-1][0]
    assert args[1:10] == [
        "scan", "--verbose", "--json", "--metrics=off", "--disable-version-check", "--oss-only", "--no-autofix",
        "--no-git-ignore", "--config",
    ]
    assert output.result.status is ScanStatus.PARTIAL
    assert output.result.issues == ("semgrep_skipped_paths",)
    assert output.scope_evidence.skipped_status is EvidenceStatus.OBSERVED
    assert [(item.path, item.reason_code) for item in output.scope_evidence.skipped_paths] == [
        ("ignored.js", "semgrepignore_patterns_match")
    ]


def test_investigation_verbose_requires_supported_cli_option(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.182.1")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(
                0, b"--json --metrics --disable-version-check --oss-only --no-autofix --no-git-ignore"
            )
        raise AssertionError("Semgrep scan must not execute when verbose is unsupported")

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    output = adapter._scan_with_evidence(target, rules, investigation_verbose=True)
    assert output.result.status is ScanStatus.EXECUTION_FAILED
    assert output.result.issues == ("verbose_option_unsupported",)


def test_clean_scan_with_zero_findings(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, b'{"results": [], "errors": []}')
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.COMPLETED
    assert scanned.findings == ()


def test_internal_output_records_scanned_paths_without_changing_scan_result(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    target_file = target / "sample.js"
    target_file.write_text("eval('synthetic');\n")
    document = json.loads(finding_json())
    document["paths"] = {"scanned": ["sample.js"]}
    fake_semgrep(monkeypatch, json.dumps(document).encode())
    parse_calls = 0
    original_parser = semgrep_adapter._parse_semgrep_json_internal

    def count_parse(raw: bytes, root: Path):
        nonlocal parse_calls
        parse_calls += 1
        return original_parser(raw, root)

    monkeypatch.setattr(semgrep_adapter, "_parse_semgrep_json_internal", count_parse)

    output = adapter._scan_with_evidence(target, rules)
    assert parse_calls == 1
    public_result = adapter.scan(target, rules)
    assert parse_calls == 2

    assert output.result.status is ScanStatus.COMPLETED
    assert output.scope_evidence.scanned_status is EvidenceStatus.OBSERVED
    assert output.scope_evidence.scanned_paths == ("sample.js",)
    # `scan()` continues to expose the established ScanResult shape.
    assert public_result.status is ScanStatus.COMPLETED
    assert not hasattr(public_result, "scope_evidence")


def test_reported_errors_make_scan_partial(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    payload = json.loads(finding_json())
    payload["errors"] = [{"message": "sensitive source text"}]
    fake_semgrep(monkeypatch, json.dumps(payload).encode())
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.PARTIAL
    assert len(scanned.findings) == 1
    assert scanned.issues == ("semgrep_reported_errors",)


def test_missing_semgrep_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: None)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.NOT_INSTALLED
    assert scanned.findings == ()


def test_no_cli_execution_marks_scope_not_collected(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: None)
    output = adapter._scan_with_evidence(target, rules)
    assert output.scope_evidence.scanned_status is EvidenceStatus.NOT_COLLECTED
    assert output.scope_evidence.paths_object_present is None


def test_nonzero_exit_is_failure_even_with_findings(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, finding_json(), exit_code=2)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.EXECUTION_FAILED
    assert len(scanned.findings) == 1
    assert scanned.exit_code == 2


def test_invalid_json_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, b"{broken")
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.INVALID_JSON
    assert scanned.findings == ()


def test_invalid_json_scope_is_unavailable_not_empty(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, b"{broken")
    output = adapter._scan_with_evidence(target, rules)
    assert output.scope_evidence.scanned_status is EvidenceStatus.UNAVAILABLE
    assert output.scope_evidence.scanned_paths == ()
    assert output.scope_evidence.reported_scanned_count is None


def test_bad_json_with_nonzero_exit_is_execution_failure(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, b"{broken", exit_code=2)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.EXECUTION_FAILED
    assert scanned.issues == ("invalid_json",)


def test_unsupported_required_option_stops_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.160.0")
        return semgrep_adapter._ProcessResult(0, b"--json")

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.EXECUTION_FAILED
    assert scanned.issues == ("required_option_unsupported",)


def test_scan_without_git_ignore_support_fails_closed(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.182.1")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(0, b"--json --metrics --disable-version-check --oss-only --no-autofix")
        raise AssertionError("Semgrep must not scan when it cannot be told to leave Git alone")

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.EXECUTION_FAILED
    assert scanned.issues == ("required_option_unsupported",)


def test_every_semgrep_process_gets_a_git_isolated_environment(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    monkeypatch.setenv("GIT_DIR", str(target / ".git"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(target / "attacker.cfg"))
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")
    environments: list[dict[str, str]] = []
    scan_arguments: list[list[str]] = []

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        environments.append(dict(env))
        git_directory = Path(env["GIT_DIR"])
        assert git_directory.parent == Path(env["HOME"])
        assert not git_directory.exists()
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.182.1")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(
                0, b"--json --metrics --disable-version-check --oss-only --no-autofix --no-git-ignore"
            )
        scan_arguments.append(args)
        return semgrep_adapter._ProcessResult(0, b'{"results": [], "errors": []}')

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    assert adapter.scan(target, rules).status is ScanStatus.COMPLETED

    assert len(environments) == 3
    for env in environments:
        assert sorted(key for key in env if key.startswith("GIT_")) == ["GIT_DIR"]
        assert not Path(env["GIT_DIR"]).is_relative_to(target)
    (arguments,) = scan_arguments
    assert arguments.index("--no-git-ignore") < arguments.index("--")
    assert "--use-git-ignore" not in arguments


def test_timeout_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def timeout(*args: object, **kwargs: object) -> None:
        raise semgrep_adapter._ProcessTimeout

    monkeypatch.setattr(semgrep_adapter, "_run_process", timeout)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.TIMED_OUT
    assert scanned.findings == ()


def test_timeout_scope_is_unavailable_not_observed_empty(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def timeout(*args: object, **kwargs: object) -> None:
        raise semgrep_adapter._ProcessTimeout

    monkeypatch.setattr(semgrep_adapter, "_run_process", timeout)
    output = adapter._scan_with_evidence(target, rules)
    assert output.result.status is ScanStatus.TIMED_OUT
    assert output.scope_evidence.scanned_status is EvidenceStatus.UNAVAILABLE


def test_output_limit_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def too_large(*args: object, **kwargs: object) -> None:
        raise semgrep_adapter._OutputLimitExceeded

    monkeypatch.setattr(semgrep_adapter, "_run_process", too_large)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.OUTPUT_LIMIT_EXCEEDED


def test_output_limit_scope_is_unavailable(
    paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def too_large(*args: object, **kwargs: object) -> None:
        raise semgrep_adapter._OutputLimitExceeded

    monkeypatch.setattr(semgrep_adapter, "_run_process", too_large)
    output = adapter._scan_with_evidence(target, rules)
    assert output.result.status is ScanStatus.OUTPUT_LIMIT_EXCEEDED
    assert output.scope_evidence.scanned_status is EvidenceStatus.UNAVAILABLE


def test_untrusted_or_missing_paths_are_rejected(paths: tuple[SemgrepAdapter, Path, Path], tmp_path: Path) -> None:
    adapter, target, rules = paths
    with pytest.raises(ValueError, match="target"):
        adapter.scan(tmp_path / "missing", rules)
    untrusted = target / "local.yml"
    untrusted.write_text("rules: []\n")
    with pytest.raises(ValueError, match="trusted rules"):
        adapter.scan(target, untrusted)
    nested_target = rules.parent / "untrusted-project"
    nested_target.mkdir()
    with pytest.raises(ValueError, match="separate trusted rules"):
        adapter.scan(nested_target, rules)


def test_runner_enforces_output_limit(tmp_path: Path) -> None:
    with pytest.raises(semgrep_adapter._OutputLimitExceeded):
        semgrep_adapter._run_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2000001)"],
            tmp_path, {"PATH": os.defpath}, 5,
        )


def test_runner_enforces_timeout(tmp_path: Path) -> None:
    with pytest.raises(semgrep_adapter._ProcessTimeout):
        semgrep_adapter._run_process(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            tmp_path, {"PATH": os.defpath}, 1,
        )
