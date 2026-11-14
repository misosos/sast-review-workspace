"""A scan target's Git configuration must never run commands during a scan.

Every canary here is a harmless shell script that only creates one marker file
under pytest's temporary directory. Nothing outside ``tmp_path`` is touched and
no sample source is executed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer import semgrep_adapter
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.services.scan_service import ApiSettings


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
BASELINE = RULES / "security-baseline.yml"
EVAL_RULE = "baseline.javascript-dynamic-eval"
VULNERABLE = 'const input = "2 + 2";\neval(input);\n'
TOKEN = "synthetic-test-token-" + "x" * 40
GIT_CONFIG_PATHS = (
    "own_config",
    "included_config",
    "parent_repository",
    "git_pointer_file",
    "bare_repository_shape",
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="canary scripts are POSIX shell scripts")


def _require_git() -> str:
    executable = shutil.which("git")
    if executable is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Git is required by this job but not installed")
        pytest.skip("Git is not installed")
    return executable


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    version = subprocess.run(
        ["semgrep", "--version"], check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()
    if version != "1.182.1":
        pytest.skip(f"requires Semgrep 1.182.1, found {version}")


def _plain_environment(home: Path) -> dict[str, str]:
    home.mkdir(exist_ok=True)
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home)}


def _git(git: str, home: Path, *args: str) -> None:
    subprocess.run(
        [git, "-c", "user.name=synthetic", "-c", "user.email=synthetic@example.invalid", *args],
        check=True, capture_output=True, timeout=30, env=_plain_environment(home),
    )


def _canary(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "canary-executed"
    script = tmp_path / "canary.sh"
    script.write_text(f'#!/bin/sh\n: > "{marker}"\n', encoding="utf-8")
    script.chmod(0o755)
    return script, marker


def _write_source(directory: Path) -> None:
    (directory / "src").mkdir(parents=True)
    (directory / "src" / "app.js").write_text(VULNERABLE, encoding="utf-8")


def _build(kind: str, tmp_path: Path, git: str) -> tuple[Path, Path, Path]:
    """Return (scan target, enclosing repository directory, marker)."""
    script, marker = _canary(tmp_path)
    home = tmp_path / "setup-home"
    repository = tmp_path / "repository"
    repository.mkdir()
    target = repository
    command = str(script)
    if kind == "bare_repository_shape":
        # The target root itself looks like a Git directory.
        _write_source(repository)
        _git(git, home, "init", "-q", "--bare", str(repository / "seed"))
        for entry in (repository / "seed").iterdir():
            entry.rename(repository / entry.name)
        (repository / "seed").rmdir()
        config = str(repository / "config")
        _git(git, home, "config", "-f", config, "core.bare", "false")
        _git(git, home, "config", "-f", config, "core.worktree", str(repository))
        _git(git, home, "config", "-f", config, "core.fsmonitor", command)
    else:
        if kind == "parent_repository":
            # The registered target is only a subdirectory of the repository.
            target = repository / "service"
            target.mkdir()
        _write_source(target)
        if kind == "included_config":
            (repository / "extra.cfg").write_text(f"[core]\n\tfsmonitor = {command}\n", encoding="utf-8")
        _git(git, home, "-C", str(repository), "init", "-q")
        _git(git, home, "-C", str(repository), "add", "-A")
        _git(git, home, "-C", str(repository), "commit", "-q", "-m", "synthetic")
        if kind == "included_config":
            _git(git, home, "-C", str(repository), "config", "include.path", str(repository / "extra.cfg"))
        elif kind == "git_pointer_file":
            (repository / ".git").rename(repository / "meta")
            (repository / ".git").write_text(f"gitdir: {repository / 'meta'}\n", encoding="utf-8")
            _git(git, home, "config", "-f", str(repository / "meta" / "config"), "core.fsmonitor", command)
        else:
            _git(git, home, "-C", str(repository), "config", "core.fsmonitor", command)
    assert not marker.exists(), "fixture setup itself must not run the canary"
    return target, repository, marker


def _install_logging_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git: str) -> Path:
    """Put a recording wrapper first in PATH; it logs each call, then runs real Git."""
    log = tmp_path / "git-calls.log"
    wrapper_directory = tmp_path / "logging-bin"
    wrapper_directory.mkdir()
    wrapper = wrapper_directory / "git"
    wrapper.write_text(
        f'#!/bin/sh\nprintf \'%s\\t%s\\n\' "$PWD" "$*" >> "{log}"\nexec "{git}" "$@"\n', encoding="utf-8"
    )
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", f"{wrapper_directory}{os.pathsep}{os.environ.get('PATH', os.defpath)}")
    return log


def _calls_touching(log: Path, directory: Path) -> list[str]:
    if not log.exists():
        return []
    needle = str(directory.resolve())
    return [line for line in log.read_text(encoding="utf-8").splitlines() if needle in line]


def _scanned(output: semgrep_adapter._ScanOutput) -> set[str]:
    return set(output.scope_evidence.scanned_paths)


def _eval_files(output: semgrep_adapter._ScanOutput) -> set[str]:
    return {item.file_path for item in output.result.findings if item.rule_id == EVAL_RULE}


@pytest.mark.parametrize("kind", GIT_CONFIG_PATHS)
def test_git_isolation_environment_stops_the_live_reproducer(kind: str, tmp_path: Path) -> None:
    """Positive control with real Git, then the adapter's environment layer on its own."""
    git = _require_git()
    target, _, marker = _build(kind, tmp_path, git)
    # The listing command Semgrep issued in the target before this hardening.
    listing = [git, "-C", str(target), "ls-files", "-z", "--others", "--exclude-standard"]

    subprocess.run(listing, capture_output=True, timeout=30, env=_plain_environment(tmp_path / "plain-home"))
    assert marker.exists(), "reproducer is not live: Git did not run the configured command"
    marker.unlink()

    private = tmp_path / "private-home"
    isolated = {**_plain_environment(private), **semgrep_adapter._git_isolation_environment(private)}
    completed = subprocess.run(listing, capture_output=True, timeout=30, env=isolated)

    assert completed.returncode != 0
    assert not marker.exists()
    assert not Path(isolated["GIT_DIR"]).exists()


@pytest.mark.parametrize("kind", GIT_CONFIG_PATHS)
def test_real_scan_never_runs_target_git_configuration(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = _require_git()
    _require_semgrep()
    target, repository, marker = _build(kind, tmp_path, git)
    log = _install_logging_git(tmp_path, monkeypatch, git)

    output = SemgrepAdapter(RULES)._scan_with_evidence(target, BASELINE)

    assert not marker.exists()
    # No Git process was started in, or pointed at, the target or its repository.
    assert _calls_touching(log, repository) == []
    # Supported source in the target is still scanned and reported.
    assert output.result.status is ScanStatus.COMPLETED
    assert _eval_files(output) == {"src/app.js"}
    assert "src/app.js" in _scanned(output)


def test_api_scan_of_git_repository_does_not_run_its_configuration(tmp_path: Path) -> None:
    git = _require_git()
    _require_semgrep()
    target, _, marker = _build("own_config", tmp_path, git)
    settings = ApiSettings(
        target_directory=target,
        trusted_rules_directory=RULES,
        api_token=TOKEN,
        allowed_hosts=("testserver", "127.0.0.1", "localhost"),
    )
    with TestClient(create_app(settings)) as client:
        rejected = client.post("/api/v1/scans", json={"target_id": "local-project", "rule_profile_id": "baseline"})
        response = client.post(
            "/api/v1/scans",
            headers={"X-Local-API-Token": TOKEN},
            json={"target_id": "local-project", "rule_profile_id": "baseline"},
        )

    assert rejected.status_code == 401
    assert response.status_code == 200
    body = response.json()
    assert body["scan_status"] == "completed"
    assert [item["file_path"] for item in body["findings"]] == ["src/app.js"]
    assert "scan_result_is_not_safety_proof" in body["limitations"]
    assert not marker.exists()


def test_investigation_scan_reports_the_skipped_git_directory(tmp_path: Path) -> None:
    """Semgrep now walks the folder itself and reports ``.git`` as skipped.

    The verbose investigation run therefore stays ``partial`` for a Git
    repository instead of presenting an unreported omission as completeness.
    """
    git = _require_git()
    _require_semgrep()
    target, _, marker = _build("own_config", tmp_path, git)

    output = SemgrepAdapter(RULES)._scan_with_evidence(target, BASELINE, investigation_verbose=True)

    assert not marker.exists()
    assert _eval_files(output) == {"src/app.js"}
    assert output.result.status is ScanStatus.PARTIAL
    assert output.result.issues == ("semgrep_skipped_paths",)
    assert [(item.path, item.reason_code) for item in output.scope_evidence.skipped_paths] == [
        (".git", "semgrepignore_patterns_match")
    ]


def test_scan_scope_no_longer_depends_on_git_or_gitignore(tmp_path: Path) -> None:
    git = _require_git()
    _require_semgrep()
    home = tmp_path / "setup-home"
    target = tmp_path / "project"
    for relative in ("src/app.js", "local/ignored.js", "node_modules/pkg/index.js"):
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text(VULNERABLE, encoding="utf-8")
    (target / ".gitignore").write_text("local/\nnode_modules/\n", encoding="utf-8")
    _git(git, home, "-C", str(target), "init", "-q")
    _git(git, home, "-C", str(target), "add", "-A")
    _git(git, home, "-C", str(target), "commit", "-q", "-m", "synthetic")
    adapter = SemgrepAdapter(RULES)
    # A gitignored source file is scanned; the dependency folder stays excluded
    # by Semgrep's built-in default ignore list, not by the repository.
    expected = {"src/app.js", "local/ignored.js"}

    first = adapter._scan_with_evidence(target, BASELINE)
    repeated = adapter._scan_with_evidence(target, BASELINE)
    assert first.result.status is ScanStatus.COMPLETED
    assert _scanned(first) == expected
    assert _eval_files(first) == expected
    assert [item.finding_id for item in repeated.result.findings] == [
        item.finding_id for item in first.result.findings
    ]
    assert _scanned(repeated) == expected

    # Rewriting the ignore file to hide everything changes nothing.
    (target / ".gitignore").write_text("*.js\nsrc/\n", encoding="utf-8")
    assert _scanned(adapter._scan_with_evidence(target, BASELINE)) == expected

    # Removing Git metadata and the ignore file changes nothing either.
    (target / ".gitignore").unlink()
    shutil.rmtree(target / ".git")
    assert _scanned(adapter._scan_with_evidence(target, BASELINE)) == expected


def test_project_semgrepignore_still_applies_and_replaces_default_ignores(tmp_path: Path) -> None:
    """Known scope limit: a project's own ``.semgrepignore`` replaces Semgrep's defaults.

    With Git no longer filtering gitignored paths, a dependency folder that the
    project's file does not list is scanned.  The file can only narrow or widen
    coverage; it is never relied on for safety.
    """
    git = _require_git()
    _require_semgrep()
    home = tmp_path / "setup-home"
    target = tmp_path / "project"
    for relative in ("src/app.js", "legacy/old.js", "node_modules/pkg/index.js"):
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text(VULNERABLE, encoding="utf-8")
    (target / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (target / ".semgrepignore").write_text("legacy/\n", encoding="utf-8")
    _git(git, home, "-C", str(target), "init", "-q")
    _git(git, home, "-C", str(target), "add", "-A")
    _git(git, home, "-C", str(target), "commit", "-q", "-m", "synthetic")

    output = SemgrepAdapter(RULES)._scan_with_evidence(target, BASELINE)

    assert output.result.status is ScanStatus.COMPLETED
    assert _scanned(output) == {"src/app.js", "node_modules/pkg/index.js"}


def test_links_to_files_outside_the_target_are_not_followed(tmp_path: Path) -> None:
    git = _require_git()
    _require_semgrep()
    home = tmp_path / "setup-home"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.js").write_text(VULNERABLE, encoding="utf-8")
    target = tmp_path / "project"
    _write_source(target)
    (target / "linked-file.js").symlink_to(outside / "secret.js")
    (target / "linked-directory").symlink_to(outside, target_is_directory=True)
    _git(git, home, "-C", str(target), "init", "-q")
    _git(git, home, "-C", str(target), "add", "-A")
    _git(git, home, "-C", str(target), "commit", "-q", "-m", "synthetic")

    output = SemgrepAdapter(RULES)._scan_with_evidence(target, BASELINE)

    assert output.result.status is ScanStatus.COMPLETED
    assert _scanned(output) == {"src/app.js"}
    assert _eval_files(output) == {"src/app.js"}
