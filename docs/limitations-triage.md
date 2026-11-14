# Limitation triage

Recorded 2026-11-12. This page classifies every item in [Known limitations](known-limitations.md) and the README. An item being listed as a limitation does not make it a bug.

Policy: confirmed bugs and maintenance are allowed; security and reproducibility improvements come first; new feature expansion needs separate evidence and approval; multi-engine SAST support and AI analysis are not approved.

## Classes

| Class | Meaning |
| --- | --- |
| A | Clear defect, fixable with a small change |
| B | Detection-rule defect, needs an independent regression test |
| C | Design constraint, needs a structural change and a security review |
| D | Intended limit, kept as it is |
| E | Validation gap, needs a test or an experiment |
| F | Out of product scope, stated as unsupported |

## Summary

| Limitation | Class | Priority | Status |
| --- | --- | --- | --- |
| CI did not pin uv | A | 1 | Fixed in this change set; the remote CI run must confirm it |
| Product display name still showed the former name | A | 1 | Fixed in this change set |
| Known false negatives of the dynamic-eval rule, including A8 | B | 2 | Open; needs a separate regression experiment |
| Findings are identified by line and column | C | 2 | Open |
| Review state is in browser memory only | C | 3 | Open |
| At most 50 findings per API response; large output rejected | C | 3 | Open |
| Partial scans are `INCOMPARABLE`; scope completeness is coarse | C | 3 | Open |
| Investigation over-abstention (S5a) | C | 4 | Open |
| No Git integration or rename linking | C | 4 | Open |
| No execution sandbox | C | 2 | Open; design exists, nothing built |
| Scan scope ignores Git; default-ignored build outputs make investigation scans of Git repositories `partial` | C | 3 | Open; remaining trade-off of the [A4 hardening](a4-untrusted-scan-git-hardening.md). Dependency folders are handled by adapter exclusions |
| No automatic proof of remediation | D | — | Kept |
| Rescan requires confirmation | D | — | Kept |
| Failed or partial rescans keep the previous result | D | — | Kept |
| Investigation evidence expires after 15 minutes | D | — | Kept |
| SARIF upload to GitHub Code Scanning untested | E | 3 | Open |
| Synthetic evaluation only | E | 4 | Open |
| No demonstrated improvement over Semgrep CLI + Git | E | — | Recorded result, not a defect |
| Semgrep-based scanning, one engine | F | — | Unsupported by decision |
| AI review is not product-integrated | F | — | Unsupported by decision |

## Details

### A. Clear defects

**CI did not pin uv**

- Current behavior: the three `astral-sh/setup-uv` steps passed `uv-version: 0.11.26`.
- Actual problem: the action has no `uv-version` input, so it warned, ignored the value, and installed the latest uv.
- Code evidence: `.github/workflows/ci.yml`; the action's `action.yml` at the pinned commit `07a047e` declares `version`, not `uv-version`.
- User impact: CI could change behavior when a new uv is released, with no change in this repository. Dependency versions were still fixed by `uv.lock`.
- Fixability: one input name in three steps.
- Regression risk: CI now runs uv 0.11.26 instead of the latest. `uv lock --check` and `uv sync --locked` pass locally with 0.11.26.
- Verification: the remote run must show no `Unexpected input(s)` warning and `uv 0.11.26` installed.
- Priority: 1.

**Product display name**

- Current behavior before the fix: the sidebar, tab title, CLI description, report headings and SARIF tool name used the former name.
- Actual problem: the displayed name did not match the repository and README.
- Code evidence: `frontend/src/app/App.tsx`, `frontend/index.html`, `frontend/src/features/scans/*Export.ts`, `src/ai_code_security_analyzer/cli.py`, `markdown_report.py`, `api/app.py`.
- User impact: cosmetic, plus a different `tool.driver.name` in newly exported SARIF.
- Regression risk: low. The SARIF preflight compares only against SARIF produced in the same session. SARIF exported before the rename keeps the old tool name.
- Verification: Python, Vitest and Playwright suites; accessible names checked in `app-shell-d5a.spec.ts`.
- Priority: 1.

### B. Detection-rule defects

**Dynamic-eval false negatives, including A8**

- Current behavior: the rule misses `globalThis.eval`/`window.eval`, destructured aliases, `Reflect.construct(Function, …)`, cross-function wrappers, and a local `const eval = globalThis.eval` binding (A8).
- Actual problem: code that executes dynamic input is not reported.
- Code evidence: `rules/security-baseline.yml`; [R1-P record](r1p-dynamic-eval-rule-integration.md); [rules README](../rules/README.md).
- User impact: missed candidates. A clean result does not mean the code is safe.
- Fixability: rule patterns can be extended.
- Regression risk: high for false positives; the existing 6D/6E results would need to be re-measured.
- Verification: a regression experiment that keeps the cases used to write the rule separate from held-out cases.
- Priority: 2, as a separate task.

### C. Design constraints

**Findings are identified by line and column**

- Current behavior: `_finding_id` hashes rule ID, path, start line and column, end line and column.
- Actual problem: a line shift or rename changes the ID, so comparison reports "disappeared plus new" and review records do not carry over.
- Code evidence: `src/ai_code_security_analyzer/semgrep_parser.py` (`_finding_id`); `frontend/src/features/scans/analystReviewBackup.ts` (`finding_set_mismatch`).
- User impact: review work is lost across ordinary edits. D1: 4 of 30 tracked findings mis-identified.
- Fixability: needs a second, content-based identity. Changing the existing ID would break comparison and the backup format, so the existing ID must stay.
- Minimal improvement: add an optional secondary key (for example rule ID, path and a hash of the matched lines) used only to suggest a match, leaving the ID and backup format unchanged.
- Regression risk: high if the ID itself changes.
- Verification: D1 cases B, C and Da.
- Priority: 2.

**Review state is in browser memory only**

- Current behavior: statuses and notes live in page memory; no `localStorage`, `sessionStorage` or IndexedDB is used.
- Actual problem: a reload loses the work unless a backup was exported.
- Code evidence: `frontend/src/app/App.tsx`; [Phase 8C](phase8c-analyst-review-state.md).
- User impact: data loss on reload. The memory-only default is also a privacy property, because notes can contain sensitive text.
- Minimal improvement: an explicit opt-in to keep state for the browser session, off by default.
- Regression risk: medium; persistence changes what is left on the machine and needs a security review.
- Verification: browser tests for reload, clear, and opt-out.
- Priority: 3.

**At most 50 findings per API response; large output rejected**

- Current behavior: `_MAX_FINDINGS = 50`; Semgrep output over `MAX_OUTPUT_BYTES = 2_000_000` fails with `output_limit_exceeded`.
- Actual problem: larger results are truncated and blocked from comparison, or rejected.
- Code evidence: `src/ai_code_security_analyzer/services/scan_service.py`; `src/ai_code_security_analyzer/semgrep_adapter.py`.
- User impact: unusable on targets with many findings. D2 case Go (5,000 findings) returned nothing.
- Minimal improvement: pagination with the same per-response cap, so the response size limit is kept.
- Regression risk: medium; the caps are part of the API's resource limits.
- Verification: API tests at 51, 500 and 5,000 findings.
- Priority: 3.

**Partial scans are `INCOMPARABLE`; scope completeness is coarse**

- Current behavior: any partial or failed scan is excluded from comparison.
- Actual problem: the product cannot say which part of a partial scan is reliable. In D2 it missed 4 to 8 of 13 incomplete scans depending on mode and wrongly blocked 1 to 2 complete ones.
- Code evidence: `frontend/src/features/scans/compare.ts`; `scan_service.py` (scope evidence); `finding_disappearance_evaluator.py`.
- User impact: either no comparison, or a comparison of a scan that was incomplete without a signal.
- Minimal improvement: treat Semgrep's `paths.skipped` and `errors` as incompleteness signals the way the D2 script does.
- Regression risk: medium; more scans become `INCOMPARABLE`.
- Verification: the D2 case set.
- Priority: 3.

**Investigation over-abstention (S5a)**

- Current behavior: the source-change and rule-change hypotheses are always `UNDETERMINED`.
- Actual problem: no source snapshot or Git diff is collected, so the evaluator cannot support a cause.
- Code evidence: `src/ai_code_security_analyzer/finding_disappearance_evaluator.py`.
- User impact: the investigation mode rarely answers the question it was built for. D1: 15 of 30 exact, against 30 of 30 for a script reading `git diff`.
- Minimal improvement: none that is small. It needs the Git evidence described under "No Git integration".
- Regression risk: high; a less conservative evaluator can make unsupported claims.
- Verification: D1.
- Priority: 4.

**No Git integration or rename linking**

- Current behavior: the scanner sees a directory, not a repository history.
- Code evidence: no Git access anywhere under `src/`.
- User impact: moved or renamed code cannot be followed.
- Fixability: structural. Reading Git metadata widens what the API touches and needs a security review.
- Priority: 4.

**No execution sandbox**

- Current behavior: Semgrep runs with local rules, metrics off and a temporary `HOME`, without OS-level isolation.
- Code evidence: `src/ai_code_security_analyzer/semgrep_adapter.py`; [Phase 7C-1B design](phase7c1b-verifiable-worker-design.md).
- User impact: untrusted repositories must be scanned in a separately isolated environment.
- Fixability: the worker design exists; nothing is built or run.
- Regression risk: high; it changes how every scan is executed.
- Priority: 2 for security, but a large task.

### D. Intended limits

- **No automatic proof of remediation.** A disappeared finding is an observation. This is the product's central safety property.
- **Rescan requires confirmation.** Protects unsaved review work (`frontend/src/app/App.tsx`).
- **Failed or partial rescans keep the previous result.** Protects review records ([P5 record](p5-failure-safe-review-rescan.md)).
- **Investigation evidence expires after 15 minutes.** Bounded memory by design (`RUN_TTL_SECONDS = 900.0` in `investigation_evidence_registry.py`).

### E. Validation gaps

- **SARIF upload untested.** Output validates against the 2.1.0 schema; upload to GitHub Code Scanning was never tried. Verification: one upload to a test repository. Priority 3.
- **Synthetic evaluation only.** Real-world precision and recall are unmeasured. Verification: a labeled real-code corpus. Priority 4.
- **No demonstrated improvement over Semgrep CLI + Git.** This is the recorded result of D1 and D2, not a defect to fix. It stays as recorded.

### F. Out of scope

- **One engine.** Semgrep OSS is the only SAST engine. Multi-engine support is not approved.
- **AI review.** The research modules are not connected to any shipped path. AI analysis is not approved.

## Observed during this review, not yet classified

A dashboard scan of the seven committed fixtures returned Semgrep status "timed out" in 2 of 5 runs on one macOS machine; an immediate rerun completed normally. The cause was not investigated, and it has not been reproduced in CI.
