# Known limitations

The complete list of current limitations. Not every item is a bug: [Limitation triage](limitations-triage.md) classifies each one and says which are fixable defects, which are design constraints, and which are intended limits. Details for the items found during the 2026-11 closing review are in [frozen-state limitations](research/frozen-state-known-limitations.md).

These are current, verified limitations. A missing finding is never evidence that code is safe or fixed.

| Limitation | Detail | Evidence |
| --- | --- | --- |
| Semgrep-based scanning | All detection is performed by the Semgrep 1.182.1 CLI with this repository's rules. There is no independent analysis engine. | `src/ai_code_security_analyzer/semgrep_adapter.py` |
| AI review is not product-integrated | AI review, Ollama provider and code-context modules exist for research but are not called by the CLI, API, or dashboard. | [AI review contract](ai-review-contract.md) |
| Known false negatives, including A8 | The dynamic-eval rule misses `globalThis.eval`/`window.eval`, destructured aliases, `Reflect.construct(Function, …)`, cross-function wrappers, and (A8, verified and unfixed) a local `const eval = globalThis.eval` binding. Other rules have documented scope gaps. | [R1-P record, A8](r1p-dynamic-eval-rule-integration.md), [rules README](../rules/README.md) |
| Partial scans are `INCOMPARABLE` | A partial or failed scan is never treated as a completed comparison. A proposed change to the partial-scan classification contract is deferred. | `frontend/src/features/scans/compare.ts`, `src/ai_code_security_analyzer/finding_disappearance_evaluator.py` |
| Investigation over-abstention (S5a), unresolved | The investigation evaluator is deliberately conservative and often returns `UNDETERMINED`. The over-abstention issue tracked as S5a is not fixed. No evaluation record for S5a is committed in this repository. | [Investigation evidence boundaries](case-studies/investigation-evidence-boundaries.md) |
| No automatic proof of remediation | A finding that disappears between scans is reported as an observation, not a fix. | [ER-D9 differentiation](er-d9-differentiation-assessment.md) |
| No Git integration or rename linking | Source snapshots and Git diffs are not collected. Renamed or moved files are not linked across scans. | [ER-D9 differentiation](er-d9-differentiation-assessment.md) |
| Investigation evidence TTL: 15 minutes | Server-side run and session evidence is held in bounded memory and expires after 900 seconds. | `src/ai_code_security_analyzer/investigation_evidence_registry.py` |
| Review state is in memory only | Review statuses and notes are not saved automatically and are lost on reload unless exported as backup JSON. | [Phase 8C](phase8c-analyst-review-state.md), [Phase 8E](phase8e-analyst-review-backup-restore.md) |
| Rescan requires confirmation | When review work exists, starting a new scan asks for confirmation and points to the backup download. Only a normally completed rescan clears the previous review records. | `frontend/src/app/App.tsx` |
| Failed or partial rescans keep the previous result | If a confirmed rescan fails or returns a partial/failed status, the new result is not applied; the previous scan and its review records are restored and labeled as the previous result. To view that partial result, export a backup, clear results, and rescan. | [P5 record](p5-failure-safe-review-rescan.md) |
| SARIF upload compatibility unverified | SARIF output validates against the official 2.1.0 schema, but upload to GitHub Code Scanning has not been tested. | [Phase 8M](phase8m-sarif-export.md), [Phase 8N](phase8n-github-code-scanning-preflight.md) |
| No improvement over Semgrep CLI + Git, and two comparisons went the other way | No study shows better detection, faster triage, or better decisions than using Semgrep with Git directly. In two synthetic comparisons a short script matched or beat the product. | [ER-D9 differentiation](er-d9-differentiation-assessment.md), [D1](../experiments/d1-finding-disappearance/RESULTS.md), [D2](../experiments/d2-scanner-integrity/RESULTS.md) |
| Findings are identified by line and column | A line shift or file rename changes a finding's ID, so comparison reports it as disappeared and review state does not carry over. | [Frozen-state limitations](research/frozen-state-known-limitations.md) |
| No execution sandbox | Semgrep runs with local rules, metrics off and a temporary `HOME`, but without OS-level network or filesystem isolation. Scan untrusted repositories only inside a separately isolated environment. | [Phase 7C-1B design](phase7c1b-verifiable-worker-design.md) |
| Scan scope ignores Git and `.gitignore` | Git is not consulted during a scan, so a target's Git configuration cannot run commands. In exchange, gitignored files are scanned; a project `.semgrepignore` that replaces Semgrep's default ignore list lets dependency folders such as `node_modules/` be scanned and can lead to `timed_out`; and an investigation scan of a Git repository is `partial` because `.git` is reported as skipped. | [A4 hardening](a4-untrusted-scan-git-hardening.md) |
| Target-controlled suppression | A target's `.semgrepignore` and inline `nosemgrep` comments reduce what is scanned or reported. A `completed` scan does not mean every file or match was considered. | [A4 hardening](a4-untrusted-scan-git-hardening.md) |
| Synthetic evaluation only | Benchmarks use small, author-written synthetic corpora. Real-world precision and recall are not measured. | [Phase 6E](phase6e-heldout-sast-evaluation.md) |

## What CI checks

CI (`.github/workflows/ci.yml`) runs three required jobs on every push and pull request to `main`:

- **Python tests and CLI**: lockfile check, CLI entry points, full `pytest` suite
- **Semgrep 1.182.1 integration**: real local-rule tests and the synthetic benchmark suites (Phases 6A, 6D, 6E)
- **React dashboard**: typecheck, Vitest, production build, Playwright browser smoke test, and a real Chromium–FastAPI–Semgrep end-to-end test (`npm run test:e2e:real`)

The three jobs install uv 0.11.26 through the `version` input of `astral-sh/setup-uv`. Until 2026-11-12 the workflow passed `uv-version`, which the action ignored, so CI ran the latest uv; see [Limitation triage](limitations-triage.md).

Run the core checks locally:

```sh
SEMGREP_REQUIRED=1 uv run --locked python -m pytest -q -rs
(cd frontend && npm ci && npm run typecheck && npm test && npm run build)
```
