"""Local-only Semgrep execution with bounded output and explicit scan states."""

import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field as dataclass_field
from enum import StrEnum
from pathlib import Path

from ai_code_security_analyzer.code_context import read_regular_file_under_root
from ai_code_security_analyzer.firestore_context import (
    FirestoreContextStatus,
    FirestoreLexicalContext,
    classify_semgrep_span,
    scan_lexical_context,
)
from ai_code_security_analyzer.models import Finding
from ai_code_security_analyzer.scan_evidence_manifest import (
    ADAPTER_EXCLUDED_NAMES,
    ScopeEvidence,
    not_collected_scope_evidence,
    unavailable_scope_evidence,
)
from ai_code_security_analyzer.semgrep_parser import InvalidSemgrepJson, _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import TaintEvidence, build_taint_evidence


MAX_OUTPUT_BYTES = 2_000_000
SCAN_TIMEOUT_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 10
_REQUIRED_OPTIONS = (
    "--json", "--metrics", "--disable-version-check", "--oss-only", "--no-autofix", "--no-git-ignore",
    "--exclude",
)
_VERSION_PATTERN = re.compile(r"\b\d+\.\d+\.\d+\b")
_FIRESTORE_RULE_ID = "baseline.firestore-unconditional-write"
_FIRESTORE_CONTEXT_MAX_BYTES = 1_000_000
_FIRESTORE_SNAPSHOT_MAX_FILES = 512
_FIRESTORE_SNAPSHOT_MAX_BYTES = 16_000_000
_FIRESTORE_SNAPSHOT_WALK_SECONDS = 3
_RULE_CONFIG_MAX_BYTES = 2_000_000


class ScanStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    EXECUTION_FAILED = "execution_failed"
    NOT_INSTALLED = "not_installed"
    INVALID_JSON = "invalid_json"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


@dataclass(frozen=True)
class ScanResult:
    status: ScanStatus
    findings: tuple[Finding, ...] = ()
    issues: tuple[str, ...] = ()
    exit_code: int | None = None
    semgrep_version: str | None = None


@dataclass(frozen=True)
class _ScanOutput:
    result: ScanResult
    taint_evidence: tuple[TaintEvidence, ...] = ()
    scope_evidence: ScopeEvidence = dataclass_field(
        default_factory=lambda: not_collected_scope_evidence("semgrep_json_not_collected")
    )


@dataclass(frozen=True)
class _ProcessResult:
    exit_code: int
    stdout: bytes


class _ProcessTimeout(Exception):
    pass


class _OutputLimitExceeded(Exception):
    pass


def _firestore_match_context(
    finding: Finding,
    item: object,
    project_root: Path,
    source_snapshot: dict[str, tuple[bytes | None, str | None]],
    source_cache: dict[str, tuple[bytes | None, str | None]],
    lexical_cache: dict[str, FirestoreLexicalContext],
) -> FirestoreContextStatus:
    """Check only the exact Semgrep span; inability to check never drops it."""
    if not isinstance(item, dict):
        return FirestoreContextStatus.UNAVAILABLE
    if item.get("check_id") != finding.rule_id:
        return FirestoreContextStatus.UNAVAILABLE
    raw_path = item.get("path")
    if not isinstance(raw_path, str):
        return FirestoreContextStatus.UNAVAILABLE
    try:
        raw_candidate = Path(raw_path)
        raw_resolved = (project_root / raw_candidate).resolve()
        if raw_resolved.relative_to(project_root).as_posix() != finding.file_path:
            return FirestoreContextStatus.UNAVAILABLE
    except (OSError, ValueError, RuntimeError):
        return FirestoreContextStatus.UNAVAILABLE
    parts = finding.file_path.split("/")
    if (
        not parts
        or parts[-1] != "firestore.rules"
        or any(part in {"", ".", ".."} for part in parts)
        or "\\" in finding.file_path
        or "\x00" in finding.file_path
    ):
        return FirestoreContextStatus.UNAVAILABLE
    original, original_issue = source_snapshot.get(finding.file_path, (None, "source_not_snapshotted"))
    if original_issue is not None or original is None:
        return FirestoreContextStatus.UNAVAILABLE
    cached = source_cache.get(finding.file_path)
    if cached is None:
        cached = read_regular_file_under_root(project_root, tuple(parts), _FIRESTORE_CONTEXT_MAX_BYTES)
        source_cache[finding.file_path] = cached
    current, issue = cached
    if issue is not None or current is None or current != original:
        return FirestoreContextStatus.UNAVAILABLE
    source = original
    lexical_context = lexical_cache.get(finding.file_path)
    if lexical_context is None:
        lexical_context = scan_lexical_context(source)
        lexical_cache[finding.file_path] = lexical_context
    start = item.get("start")
    end = item.get("end")
    if not isinstance(start, dict) or not isinstance(end, dict):
        return FirestoreContextStatus.UNAVAILABLE
    return classify_semgrep_span(
        source,
        start_offset=start.get("offset"),
        end_offset=end.get("offset"),
        start_line=start.get("line"),
        start_column=start.get("col"),
        end_line=end.get("line"),
        end_column=end.get("col"),
        expected_line=finding.line_number,
        lexical_context=lexical_context,
    )


def _snapshot_firestore_sources(project: Path, project_root: Path) -> dict[str, tuple[bytes | None, str | None]]:
    """Take a bounded pre-scan byte snapshot; incomplete entries remain unvalidated."""
    candidates: list[Path] = []
    deadline = time.monotonic() + _FIRESTORE_SNAPSHOT_WALK_SECONDS
    if project.is_file():
        if project.name == "firestore.rules":
            candidates.append(project)
    else:
        entries_seen = 0
        for root, directories, files in os.walk(project, followlinks=False):
            directories.sort()
            files.sort()
            root_path = Path(root)
            entries_seen += len(directories) + len(files)
            if entries_seen > 100_000 or time.monotonic() > deadline:
                break
            for filename in files:
                if filename == "firestore.rules":
                    candidates.append(root_path / filename)
                    if len(candidates) >= _FIRESTORE_SNAPSHOT_MAX_FILES:
                        break
            if len(candidates) >= _FIRESTORE_SNAPSHOT_MAX_FILES:
                break

    snapshot: dict[str, tuple[bytes | None, str | None]] = {}
    total_bytes = 0
    for candidate in candidates:
        try:
            relative = candidate.relative_to(project_root).as_posix()
        except ValueError:
            continue
        parts = relative.split("/")
        data, issue = read_regular_file_under_root(project_root, tuple(parts), _FIRESTORE_CONTEXT_MAX_BYTES)
        if data is None or issue is not None:
            snapshot[relative] = (None, issue or "source_unavailable")
            continue
        if total_bytes + len(data) > _FIRESTORE_SNAPSHOT_MAX_BYTES:
            snapshot[relative] = (None, "snapshot_byte_limit")
            continue
        total_bytes += len(data)
        snapshot[relative] = (data, None)
    return snapshot


def _rules_include_firestore_rule(rules: Path) -> bool:
    """Avoid walking project sources for profiles without the Firestore rule."""
    try:
        data, issue = read_regular_file_under_root(rules.parent, (rules.name,), _RULE_CONFIG_MAX_BYTES)
    except (OSError, ValueError, RuntimeError):
        return False
    return issue is None and data is not None and _FIRESTORE_RULE_ID.encode("ascii") in data


def _filter_firestore_comment_matches(
    semgrep_document, project_root: Path, source_snapshot: dict[str, tuple[bytes | None, str | None]]
) -> tuple[Finding, ...]:
    """Filter only candidates proven to lie wholly in a closed comment/string."""
    source_cache: dict[str, tuple[bytes | None, str | None]] = {}
    lexical_cache: dict[str, FirestoreLexicalContext] = {}
    retained: list[Finding] = []
    raw_results = semgrep_document.document.get("results", [])
    if not isinstance(raw_results, list) or len(raw_results) != len(semgrep_document.result_findings):
        return semgrep_document.parsed.findings
    for raw, finding in zip(raw_results, semgrep_document.result_findings):
        if finding is None:
            continue
        if finding.rule_id == _FIRESTORE_RULE_ID:
            context = _firestore_match_context(
                finding, raw, project_root, source_snapshot, source_cache, lexical_cache
            )
            if context in {
                FirestoreContextStatus.CONFIRMED_COMMENT,
                FirestoreContextStatus.CONFIRMED_STRING,
            }:
                continue
        retained.append(finding)
    return tuple(retained)


def _resolve_path(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, ValueError, RuntimeError):
        raise ValueError("invalid local path") from None


def _stop_process(process: subprocess.Popen[bytes], *, force_group: bool = False) -> None:
    running = process.poll() is None
    if os.name == "posix" and (running or force_group):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif running:
        process.kill()
    process.wait()


def _run_process(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> _ProcessResult:
    process = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    assert process.stdout is not None and process.stderr is not None
    output = bytearray()
    total_bytes = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _ProcessTimeout
                for key, _ in selector.select(min(remaining, 0.5)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > MAX_OUTPUT_BYTES:
                        raise _OutputLimitExceeded
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProcessTimeout
        return _ProcessResult(process.wait(timeout=remaining), bytes(output))
    except subprocess.TimeoutExpired:
        _stop_process(process, force_group=True)
        raise _ProcessTimeout from None
    except BaseException:
        _stop_process(process, force_group=True)
        raise
    finally:
        process.stdout.close()
        process.stderr.close()


def _git_isolation_environment(private_directory: Path) -> dict[str, str]:
    """Keep any Git process started below Semgrep away from target-controlled configuration.

    A scan target is untrusted data, and Git runs commands named in a
    repository's own configuration (for example ``core.fsmonitor``).  The scan
    passes ``--no-git-ignore`` so Semgrep does not ask Git for the file list.
    As a second, independent layer, ``GIT_DIR`` names a path that never exists,
    so a Git process that is started anyway cannot discover the target (or a
    parent of it) as a repository and never loads its configuration.
    """
    return {"GIT_DIR": str(private_directory / "git-disabled")}


class SemgrepAdapter:
    """Run a scan with rules from a separately trusted local directory."""

    def __init__(self, trusted_rules_directory: Path) -> None:
        root = _resolve_path(trusted_rules_directory)
        if not root.is_dir():
            raise ValueError("trusted rules directory must exist")
        self.trusted_rules_directory = root

    def scan(self, target: Path, rules_file: Path, *, timeout: int = SCAN_TIMEOUT_SECONDS) -> ScanResult:
        """Run a scan and preserve the established public ScanResult contract."""
        return self._scan_with_evidence(target, rules_file, timeout=timeout).result

    def _scan_with_evidence(
        self, target: Path, rules_file: Path, *, timeout: int = SCAN_TIMEOUT_SECONDS,
        investigation_verbose: bool = False,
    ) -> _ScanOutput:
        """Internal scan path returning derived taint evidence from the same JSON parse."""
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        project = _resolve_path(target)
        if not project.exists() or not (project.is_dir() or project.is_file()):
            raise ValueError("target must be an existing local file or directory")
        project_root = project if project.is_dir() else project.parent
        rules = _resolve_path(rules_file)
        if not rules.is_file() or rules.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError("rules file must be a local YAML file")
        if (
            not rules.is_relative_to(self.trusted_rules_directory)
            or project_root.is_relative_to(self.trusted_rules_directory)
            or self.trusted_rules_directory.is_relative_to(project_root)
        ):
            raise ValueError("rules file must be inside the separate trusted rules directory")

        executable = shutil.which("semgrep")
        if executable is None:
            return _ScanOutput(ScanResult(ScanStatus.NOT_INSTALLED, issues=("semgrep_not_installed",)))

        with tempfile.TemporaryDirectory(prefix="ai-code-semgrep-") as temporary_home:
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": temporary_home,
                "XDG_CACHE_HOME": temporary_home,
                "SEMGREP_SEND_METRICS": "off",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                **_git_isolation_environment(Path(temporary_home)),
            }
            try:
                version_result = _run_process([executable, "--version"], project_root, env, PROBE_TIMEOUT_SECONDS)
                version_match = _VERSION_PATTERN.search(version_result.stdout.decode("utf-8", errors="replace"))
                if version_result.exit_code != 0 or version_match is None:
                    return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("version_check_failed",)))
                version = version_match.group()
                help_result = _run_process([executable, "scan", "--help"], project_root, env, PROBE_TIMEOUT_SECONDS)
                help_text = help_result.stdout.decode("utf-8", errors="replace")
                if help_result.exit_code != 0 or any(option not in help_text for option in _REQUIRED_OPTIONS):
                    return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("required_option_unsupported",), semgrep_version=version))
                if investigation_verbose and "--verbose" not in help_text:
                    return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("verbose_option_unsupported",), semgrep_version=version))
                args = [
                    executable, "scan", "--json", "--metrics=off", "--disable-version-check",
                    "--oss-only", "--no-autofix", "--no-git-ignore",
                    *(f"--exclude={name}" for name in ADAPTER_EXCLUDED_NAMES),
                    "--config", rules.name, "--", str(project),
                ]
                if investigation_verbose:
                    args.insert(2, "--verbose")
                firestore_snapshot = (
                    _snapshot_firestore_sources(project, project_root)
                    if _rules_include_firestore_rule(rules)
                    else {}
                )
                # A relative config name prevents Semgrep from embedding the local
                # rules directory in check_id values exposed by public reports.
                completed = _run_process(args, rules.parent, env, timeout)
            except _ProcessTimeout:
                return _ScanOutput(
                    ScanResult(ScanStatus.TIMED_OUT, issues=("semgrep_timeout",)),
                    scope_evidence=unavailable_scope_evidence("semgrep_timeout_without_json"),
                )
            except _OutputLimitExceeded:
                return _ScanOutput(
                    ScanResult(ScanStatus.OUTPUT_LIMIT_EXCEEDED, issues=("semgrep_output_limit",)),
                    scope_evidence=unavailable_scope_evidence("semgrep_output_limit"),
                )
            except OSError:
                return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("semgrep_launch_failed",)))

        try:
            semgrep_document = _parse_semgrep_json_internal(completed.stdout, project_root)
        except InvalidSemgrepJson:
            if completed.exit_code != 0:
                return _ScanOutput(
                    ScanResult(ScanStatus.EXECUTION_FAILED, issues=("invalid_json",), exit_code=completed.exit_code, semgrep_version=version),
                    scope_evidence=unavailable_scope_evidence("invalid_json_after_failed_execution"),
                )
            return _ScanOutput(
                ScanResult(ScanStatus.INVALID_JSON, issues=("invalid_json",), exit_code=completed.exit_code, semgrep_version=version),
                scope_evidence=unavailable_scope_evidence("invalid_json"),
            )
        parsed = semgrep_document.parsed
        taint_evidence = build_taint_evidence(
            semgrep_document.document,
            semgrep_document.result_findings,
            project_root,
            rules_file=rules,
            trusted_rules_directory=self.trusted_rules_directory,
        )
        findings = _filter_firestore_comment_matches(semgrep_document, project_root, firestore_snapshot)
        if completed.exit_code != 0:
            return _ScanOutput(
                ScanResult(ScanStatus.EXECUTION_FAILED, findings, parsed.issues + ("nonzero_exit",), completed.exit_code, version),
                taint_evidence,
                semgrep_document.scope_evidence,
            )
        status = ScanStatus.PARTIAL if parsed.issues else ScanStatus.COMPLETED
        return _ScanOutput(
            ScanResult(status, findings, parsed.issues, completed.exit_code, version),
            taint_evidence,
            semgrep_document.scope_evidence,
        )
