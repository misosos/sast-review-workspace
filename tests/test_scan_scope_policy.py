"""Scan scope policy and investigation compatibility, against the real Semgrep subprocess.

The adapter excludes a fixed set of names (version control metadata and installed
dependency trees) and records them as its own policy. Everything else Semgrep
skips keeps a scan partial. Sources are synthetic and are never executed.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer import semgrep_adapter
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.scan_evidence_manifest import EvidenceStatus
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService
from test_untrusted_git_scan_hardening import (
    BASELINE,
    RULES,
    TOKEN,
    VULNERABLE,
    _eval_files,
    _git,
    _require_git,
    _require_semgrep,
    _scanned,
)


pytestmark = pytest.mark.skipif(os.name != "posix", reason="fixtures use POSIX links and Git")

HEADERS = {"X-Local-API-Token": TOKEN}
SCAN = {"target_id": "local-project", "rule_profile_id": "baseline"}
POLICY = "adapter_policy_exclusion"
IGNORE_FILE = "semgrepignore_patterns_match"
# `local/` is ordinary source that Git ignores; it must still be scanned.
SOURCES = ("src/app.js", "local/ignored.js")
DEPENDENCIES = ("node_modules/pkg/index.js", "packages/a/node_modules/dep/index.js", ".venv/lib/site.js")
GITIGNORE = "node_modules/\n.venv/\nlocal/\ndist/\nbuild/\ncoverage/\n"
NEGATIONS = "!node_modules/\n!node_modules/**\n!**/node_modules/**\n!.venv/\n!.venv/**\n!.git/\n"
# A TypeScript file Semgrep 1.182.1 reports as a partial-parsing error.
UNPARSABLE_TS = "eval(x);\nconst = = = ;\nclass { ]]] \n"
PROJECT_IGNORE_FILES = {
    "no_ignore_file": None,
    "custom_list": "docs/\n",
    "negations": NEGATIONS,
    "negations_included_from_outside": ":include ../outside-negations.txt\n",
}


def _write(base: Path, *relative_paths: str, text: str = VULNERABLE) -> None:
    for relative in relative_paths:
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _commit(git: str, tmp_path: Path, target: Path) -> None:
    home = tmp_path / "setup-home"
    _git(git, home, "-C", str(target), "init", "-q")
    _git(git, home, "-C", str(target), "add", "-A")
    _git(git, home, "-C", str(target), "commit", "-q", "-m", "synthetic")


def _project(tmp_path: Path, git: str, *, ignore_file: str | None, extra: tuple[str, ...] = ()) -> Path:
    """A real Git repository with gitignored dependencies and one gitignored source file."""
    (tmp_path / "outside-negations.txt").write_text(NEGATIONS, encoding="utf-8")
    target = tmp_path / "project"
    _write(target, *SOURCES, *DEPENDENCIES, *extra)
    (target / ".gitignore").write_text(GITIGNORE, encoding="utf-8")
    if ignore_file is not None:
        (target / ".semgrepignore").write_text(ignore_file, encoding="utf-8")
    _commit(git, tmp_path, target)
    return target


def _skips(output: semgrep_adapter._ScanOutput) -> set[tuple[str, str]]:
    return {(item.path, item.reason_code) for item in output.scope_evidence.skipped_paths}


def _scan(target: Path, *, verbose: bool) -> semgrep_adapter._ScanOutput:
    return SemgrepAdapter(RULES)._scan_with_evidence(target, BASELINE, investigation_verbose=verbose)


@pytest.mark.parametrize("ignore_file", PROJECT_IGNORE_FILES)
def test_adapter_exclusions_hold_whatever_the_project_ignore_file_says(ignore_file: str, tmp_path: Path) -> None:
    git = _require_git()
    _require_semgrep()
    target = _project(tmp_path, git, ignore_file=PROJECT_IGNORE_FILES[ignore_file])

    investigated = _scan(target, verbose=True)

    assert investigated.result.status is ScanStatus.COMPLETED
    assert investigated.result.issues == ()
    # Gitignored source is scanned and its finding reported; dependencies are not.
    assert _scanned(investigated) == set(SOURCES)
    assert _eval_files(investigated) == set(SOURCES)
    # The exclusions are recorded, never silently dropped.
    assert investigated.scope_evidence.skipped_status is EvidenceStatus.OBSERVED
    assert _skips(investigated) == {
        (".git", POLICY), ("node_modules", POLICY), ("packages/a/node_modules", POLICY), (".venv", POLICY),
    }
    assert investigated.scope_evidence.completeness_status is EvidenceStatus.UNVERIFIED
    assert "scanned_paths_do_not_prove_complete_analysis" in investigated.scope_evidence.limitations

    plain = _scan(target, verbose=False)

    assert plain.result.status is ScanStatus.COMPLETED
    assert _scanned(plain) == set(SOURCES)
    # The normal invocation does not collect skips and must not claim there were none.
    assert plain.scope_evidence.skipped_status is EvidenceStatus.NOT_COLLECTED
    assert "skip_details_not_collected" in plain.scope_evidence.limitations


def test_large_dependency_tree_is_excluded_and_the_control_shows_what_that_prevents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = _require_git()
    _require_semgrep()
    bulk = tuple(f"node_modules/pkg{index // 40}/lib/module{index}.js" for index in range(400))
    target = _project(tmp_path, git, ignore_file="docs/\n", extra=bulk)

    scanned = _scanned(_scan(target, verbose=False))
    assert scanned == set(SOURCES)

    # Negative control: the same project without the adapter's exclusions. Its own
    # ignore file replaces Semgrep's defaults, so every dependency file is scanned.
    monkeypatch.setattr(semgrep_adapter, "ADAPTER_EXCLUDED_NAMES", ())
    unprotected = _scanned(_scan(target, verbose=False))
    assert set(bulk) <= unprotected
    assert set(DEPENDENCIES) <= unprotected
    assert len(unprotected) == len(scanned) + len(bulk) + len(DEPENDENCIES)


def test_only_the_exact_names_are_excluded(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    similar = (
        "src/app.js", "node_modules.js", ".venv.js", "venv/app.js", "my.venv/app.js",
        "git/app.js", "src/node_modules_helper/app.js",
    )
    _write(target, *similar)

    output = _scan(target, verbose=True)

    assert output.result.status is ScanStatus.COMPLETED
    assert _scanned(output) == set(similar)
    assert _eval_files(output) == set(similar)
    assert output.scope_evidence.skipped_status is EvidenceStatus.OBSERVED
    assert _skips(output) == set()


def test_generated_output_folders_are_not_adapter_exclusions(tmp_path: Path) -> None:
    """`dist/` and `build/` can hold ordinary source, so only Semgrep's ignore rules decide.

    When Semgrep's default list skips them, the investigation run reports that
    as an ignore-file skip and stays partial instead of hiding it.
    """
    git = _require_git()
    _require_semgrep()
    generated = ("dist/bundle.js", "build/out.js", "coverage/report.js")
    target = _project(tmp_path, git, ignore_file=None, extra=generated)

    default_rules = _scan(target, verbose=True)

    assert default_rules.result.status is ScanStatus.PARTIAL
    assert default_rules.result.issues == ("semgrep_skipped_paths",)
    assert _scanned(default_rules) == {*SOURCES, "coverage/report.js"}
    assert {("dist/bundle.js", IGNORE_FILE), ("build/out.js", IGNORE_FILE), (".git", POLICY)} <= _skips(default_rules)

    # The project takes over the ignore list: generated folders are scanned,
    # dependencies still are not.
    (target / ".semgrepignore").write_text("docs/\n", encoding="utf-8")
    project_rules = _scan(target, verbose=True)

    assert project_rules.result.status is ScanStatus.COMPLETED
    assert _scanned(project_rules) == {*SOURCES, *generated}
    assert _eval_files(project_rules) == {*SOURCES, *generated}


def test_real_parser_error_keeps_the_scan_partial_and_its_skip_unrecognized(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    _write(target, "src/app.js", "node_modules/pkg/index.js")
    _write(target, "src/broken.ts", text=UNPARSABLE_TS)

    plain = _scan(target, verbose=False)
    assert plain.result.status is ScanStatus.PARTIAL
    assert plain.result.issues == ("semgrep_reported_errors",)

    investigated = _scan(target, verbose=True)
    assert investigated.result.status is ScanStatus.PARTIAL
    assert investigated.result.issues == ("semgrep_reported_errors", "semgrep_skipped_paths")
    # Semgrep's reason for this skip is outside the closed set: the whole skip
    # list is withheld, including the adapter exclusion reported next to it.
    assert investigated.scope_evidence.skipped_status is EvidenceStatus.UNAVAILABLE
    assert investigated.scope_evidence.skipped_paths == ()
    assert "skipped_reason_unrecognized" in investigated.scope_evidence.limitations


@pytest.mark.parametrize("kind", ["linked_ignore_file", "relative_include", "absolute_include"])
def test_ignore_rules_supplied_from_outside_the_target_only_narrow_a_partial_scan(
    kind: str, tmp_path: Path
) -> None:
    """Semgrep reads these outside files. They can hide source, visibly, and nothing more."""
    _require_semgrep()
    outside = tmp_path / "outside-rules.txt"
    outside.write_text("src/\n" + NEGATIONS, encoding="utf-8")
    target = tmp_path / "project"
    _write(target, "src/app.js", "other/kept.js", "node_modules/pkg/index.js")
    if kind == "linked_ignore_file":
        (target / ".semgrepignore").symlink_to(outside)
    elif kind == "relative_include":
        (target / ".semgrepignore").write_text(":include ../outside-rules.txt\n", encoding="utf-8")
    else:
        (target / ".semgrepignore").write_text(f":include {outside}\n", encoding="utf-8")

    output = _scan(target, verbose=True)

    assert output.result.status is ScanStatus.PARTIAL
    assert output.result.issues == ("semgrep_skipped_paths",)
    assert _scanned(output) == {"other/kept.js"}
    assert _skips(output) == {("src/app.js", IGNORE_FILE), ("node_modules", POLICY)}


def test_service_rejects_a_linked_ignore_file_before_scanning(tmp_path: Path) -> None:
    _require_semgrep()
    outside = tmp_path / "outside-rules.txt"
    outside.write_text("src/\n", encoding="utf-8")
    target = tmp_path / "project"
    _write(target, "src/app.js")
    (target / ".semgrepignore").symlink_to(outside)
    settings = ApiSettings(target, RULES, TOKEN, allowed_hosts=("testserver",))

    with TestClient(create_app(settings)) as client:
        response = client.post("/api/v1/scans", headers=HEADERS, json=SCAN)

    assert response.status_code == 400
    assert response.json() == {"error": "target_not_allowed"}


def _remove_old(target: Path) -> None:
    (target / "src" / "old.js").unlink()


def _move_old_under_dependencies(target: Path) -> None:
    (target / "src" / "old.js").rename(target / "node_modules" / "old.js")


def _ignore_old(target: Path) -> None:
    (target / ".semgrepignore").write_text(NEGATIONS + "src/old.js\n", encoding="utf-8")


def _add_unparsable(target: Path) -> None:
    _write(target, "src/broken.ts", text=UNPARSABLE_TS)


def _add_generated(target: Path) -> None:
    # Semgrep's default ignore list applies once the project file is gone.
    (target / ".semgrepignore").unlink()
    _write(target, "dist/bundle.js")


INVESTIGATIONS = {
    # change between runs: (mutation, current status, comparability, overall, observation for src/old.js, skip hypothesis)
    "nothing_changes": (None, "completed", "COMPARABLE", "UNDETERMINED", None, None),
    "finding_file_removed": (_remove_old, "completed", "COMPARABLE", "UNDETERMINED", "PATH_NOT_REPORTED", "UNDETERMINED"),
    "finding_file_moved_under_excluded_folder": (
        _move_old_under_dependencies, "completed", "COMPARABLE", "UNDETERMINED", "PATH_NOT_REPORTED", "UNDETERMINED",
    ),
    "project_ignore_rule_added": (
        _ignore_old, "partial", "INCOMPARABLE", "INCOMPARABLE", "PATH_EXPLICITLY_SKIPPED", "SUPPORTED",
    ),
    "unparsable_file_added": (_add_unparsable, "partial", "INCOMPARABLE", "INCOMPARABLE", None, None),
    "default_ignored_output_appears": (_add_generated, "partial", "INCOMPARABLE", "INCOMPARABLE", None, None),
}


@pytest.mark.parametrize("case", INVESTIGATIONS)
def test_investigation_compares_only_scans_with_compatible_scope(case: str, tmp_path: Path) -> None:
    git = _require_git()
    _require_semgrep()
    mutate, current_status, comparability, overall, observation, hypothesis = INVESTIGATIONS[case]
    target = _project(tmp_path, git, ignore_file=NEGATIONS, extra=("src/old.js",))
    settings = ApiSettings(target, RULES, TOKEN, allowed_hosts=("testserver",))
    app = create_app(settings, scan_service=ScanService(settings), investigation_api_enabled=True)

    with TestClient(app) as client:
        first = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN)
        assert first.status_code == 200, first.text
        baseline = first.json()
        # A real Git repository with dependencies and a custom ignore file is a complete run.
        assert baseline["scan"]["scan_status"] == "completed"
        assert baseline["scan"]["issues"] == []
        assert "scan_result_is_not_safety_proof" in baseline["scan"]["limitations"]
        old_id = next(
            item["finding_id"] for item in baseline["scan"]["findings"] if item["file_path"] == "src/old.js"
        )
        scope = app.state.investigation_registry.get_run(baseline["run_handle"]).manifest.scope_evidence
        assert set(scope.scanned_paths) == {*SOURCES, "src/old.js"}
        assert {(item.path, item.reason_code) for item in scope.skipped_paths} == {
            (".git", POLICY), ("node_modules", POLICY), ("packages/a/node_modules", POLICY), (".venv", POLICY),
        }

        if mutate is not None:
            mutate(target)
        second = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN)
        assert second.status_code == 200, second.text
        current = second.json()
        assert current["scan"]["scan_status"] == current_status
        assert current["scan"]["completed"] is (current_status == "completed")

        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": baseline["run_handle"], "current_handle": current["run_handle"],
        })
        assert session.status_code == 201, session.text
        evaluated = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })

    assert evaluated.status_code == 200, evaluated.text
    evaluation = evaluated.json()
    assert evaluation["comparability"] == comparability
    assert evaluation["overall_assessment"] == overall
    # No outcome here is allowed to present the disappearance as explained or fixed.
    assert evaluation["overall_assessment"] != "EXPLANATION_SUPPORTED"
    assert "scope_completeness_unverified" in evaluation["limitation_codes"]
    assert ("scan_incomplete" in evaluation["limitation_codes"]) is (current_status != "completed")
    old = next(item for item in evaluation["findings"] if item["finding_id"] == old_id)
    if observation is None:
        assert old["category"] == "shared"
    else:
        assert old["category"] == "baselineOnly"
        assert old["path_observation"] == observation
        assert old["skip_hypothesis"] == hypothesis


def test_timed_out_run_is_evaluated_as_incomparable_not_as_a_server_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = _require_git()
    _require_semgrep()
    target = _project(tmp_path, git, ignore_file=None, extra=("src/old.js",))
    settings = ApiSettings(target, RULES, TOKEN, allowed_hosts=("testserver",))
    app = create_app(settings, scan_service=ScanService(settings), investigation_api_enabled=True)
    real_run = semgrep_adapter._run_process
    timing_out = False

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        # The version and help probes are real; only the scan itself times out.
        if timing_out and args[1] == "scan" and "--help" not in args:
            raise semgrep_adapter._ProcessTimeout
        return real_run(args, cwd, env, timeout)

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    with TestClient(app) as client:
        baseline = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN).json()
        assert baseline["scan"]["scan_status"] == "completed"
        timing_out = True
        second = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN)
        timing_out = False
        assert second.status_code == 200, second.text
        current = second.json()
        assert current["scan"]["scan_status"] == "timed_out"
        assert current["scan"]["completed"] is False
        assert current["scan"]["findings"] == []
        assert "scan_failed" in current["scan"]["limitations"]

        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": baseline["run_handle"], "current_handle": current["run_handle"],
        })
        assert session.status_code == 201, session.text
        evaluated = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })

    assert evaluated.status_code == 200, evaluated.text
    evaluation = evaluated.json()
    assert evaluation["comparability"] == "INCOMPARABLE"
    assert evaluation["overall_assessment"] == "INCOMPARABLE"
    assert evaluation["findings"] == []
