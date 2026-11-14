# A4 — Untrusted repository scan hardening

A scan target is untrusted data. Before this change, scanning a folder that was (or sat inside) a Git repository let that repository's own Git configuration run a command on the analyst's machine. This record states the cause, the fix, what the fix changes in scan scope, and what it does not cover.

## Cause

Semgrep 1.182.1 asks Git for the file list of a scan target. During a scan with the adapter's previous options it started five Git processes in or pointed at the target (`git ls-files` with `--cached`, `--others --exclude-standard`, `--deleted`). Git loads the configuration of whatever repository it discovers from that folder, and some configuration keys name a program to run. `core.fsmonitor` is one: `git ls-files --others` executes its value.

Reproduced with a harmless canary (a script that only creates a marker file in a temporary directory). The canary ran when the configuration came from:

| Path | Canary ran before | After |
| --- | --- | --- |
| The target's own `.git/config` | yes | no |
| A file named by `include.path` in that configuration | yes | no |
| A parent repository, when the target is only a subdirectory | yes | no |
| A `.git` file pointing at a directory inside the target | yes | no |
| A target root shaped like a bare repository | yes | no |

Hooks, filter drivers, pager, editor, SSH, credential, alias and external-diff keys were also planted. None ran before or after, because Semgrep's listing commands do not reach them. They were not what the fix relies on.

## Fix

`src/ai_code_security_analyzer/semgrep_adapter.py`, two independent layers:

1. The scan passes `--no-git-ignore`. Semgrep walks the folder itself and starts no Git process for the target. The option is in the adapter's required-option check, so a Semgrep that does not offer it fails closed with `required_option_unsupported` and no scan runs.
2. Every Semgrep process (version probe, help probe, scan) gets `GIT_DIR` set to a path that never exists inside the adapter's private temporary directory. A Git process that is started anyway cannot discover the target or a parent as a repository, so it never loads their configuration.

Each layer was tested on its own against all five paths. Removing Git from the scan avoids a list of "dangerous keys" that could never be shown complete.

Measured with a recording Git wrapper first in `PATH`: before, 5 of 8 Git calls touched the target; after, 0 of 3. The three remaining calls are Semgrep reading a remote URL in its own install folder and in the trusted rules folder; under layer 2 they find no repository.

Rejected alternatives:

| Alternative | Result |
| --- | --- |
| Override `core.fsmonitor` only (`GIT_CONFIG_*`) | Stops the known key; Git still loads the target's configuration, so other or future keys are not covered |
| `--project-root <target>` alone | Canary still ran |
| A failing `git` earlier in `PATH` | Works, but needs an executable written at scan time; `GIT_DIR` gives the same effect with one variable |
| Ignore `.semgrepignore` too (`--x-ignore-semgrepignore-files`) | Internal flag; would break the investigation skip evidence the product reports |

## Scope policy (A4-R1)

Dropping Git removed two things Git used to do silently: hide dependency folders, and keep `.git` out of the reported skips. The adapter now owns that part of the scope explicitly.

**Adapter exclusions.** Every scan passes `--exclude` for exactly three names, at any depth: `.git`, `node_modules`, `.venv`. They are version-control metadata and installed dependency trees. `ADAPTER_EXCLUDED_NAMES` in `scan_evidence_manifest.py` is the single definition. A Semgrep without `--exclude` fails closed.

Verified with Semgrep 1.182.1:

- A project `.semgrepignore` cannot re-include them. Negations (`!node_modules/`, `!node_modules/**`, `!**/node_modules/**`, `!.venv/`, `!.git/`) had no effect, written in the file or pulled in with `:include` from outside the target.
- Only the exact names match. `node_modules.js`, `.venv.js`, `venv/`, `my.venv/`, `git/` and `src/node_modules_helper/` are scanned.
- Source that Git ignores is still scanned. No folder is excluded because of `.gitignore`.

**Not excluded: build outputs.** `dist/`, `build/`, `coverage/` and similar names can hold ordinary source, and an adapter exclusion cannot be undone by the project. They stay under Semgrep's ignore rules: skipped by Semgrep's default list, scanned when the project supplies its own `.semgrepignore` that does not list them.

**How skips are classified.** Semgrep reports skipped paths only in the verbose investigation run. Each one is stored under a closed reason:

| Reported by Semgrep | Stored as | Effect on the scan |
| --- | --- | --- |
| A path named `.git`, `node_modules` or `.venv`, with Semgrep's CLI-exclude or ignore-file reason | `adapter_policy_exclusion` | none; recorded in the scope evidence |
| Any other path with the ignore-file reason | `semgrepignore_patterns_match` | `partial` |
| The CLI-exclude reason on any other path | not stored; skip list `UNAVAILABLE` (`skipped_reason_unrecognized`) | `partial` |
| Any other reason, for example a parser failure | not stored; skip list `UNAVAILABLE` | `partial` |
| Malformed or out-of-root entries | not stored; skip list `UNAVAILABLE` | `partial` |

A scan is `completed` only when every reported skip is a validated adapter exclusion. The stored form is canonical: evidence that pairs an excluded name with another reason, or `adapter_policy_exclusion` with another path, is refused. The public `ScanResponse` and investigation responses are unchanged, and no new public code was added. `adapter_policy_exclusion` exists only in the process-local scope evidence.

`completed` still does not mean every file was inspected. Scope completeness stays `UNVERIFIED`, the normal (non-verbose) scan records that skip details were not collected, and every response carries `scan_result_is_not_safety_proof`.

## Scan scope changes

Compared with scanning through Git (before A4):

- **Nothing previously scanned is lost.**
- **Gitignored files are scanned**, for example a local-only source file or `coverage/`. The result no longer depends on `.gitignore` or on the folder being a Git repository.
- **Dependency folders stay out**, with or without a project `.semgrepignore`.

Measured on a fixture with 728 tracked files, a real 141 MB `node_modules` and built assets:

| Project ignore file | Before A4 | A4 | A4-R1 |
| --- | --- | --- | --- |
| none | 46 files, ~4 s | 47 files, ~5 s | 47 files, ~4 s |
| its own `.semgrepignore` | 452 files, ~4 s | 4,486 files, 28–38 s | 454 files, ~5 s |

The extra files against "before A4" are gitignored build outputs.

## Investigation compatibility

Real HTTP investigation runs on a Git repository with dependency folders and a `.semgrepignore` full of negations:

| Change between the two scans | Current scan | Comparison |
| --- | --- | --- |
| none | `completed` | `COMPARABLE`, `UNDETERMINED` |
| file with a finding removed | `completed` | `COMPARABLE`, `UNDETERMINED`, `PATH_NOT_REPORTED` |
| that file moved under `node_modules/` | `completed` | `COMPARABLE`, `UNDETERMINED`, `PATH_NOT_REPORTED` |
| project ignore rule added for that file | `partial` | `INCOMPARABLE`, `PATH_EXPLICITLY_SKIPPED` |
| unparsable file added | `partial` | `INCOMPARABLE` |
| a default-ignored `dist/` appears | `partial` | `INCOMPARABLE` |
| current scan times out | `timed_out` | `INCOMPARABLE` |

No case reports a disappearance as explained or fixed.

The timed-out row fixes a separate defect found in A3: the registry refused to read back the scope reasons recorded for failed scans (timeout, output limit, unparsable output), so evaluating such a run returned `503 internal_unavailable`. Those reasons were already accepted by the evaluator and are now accepted by the registry. Unknown reasons are still refused.

## Not covered

- Semgrep still has no OS-level isolation. Scan untrusted repositories only inside a separately isolated environment.
- `.semgrepignore` and inline `nosemgrep` comments are controlled by the target and can reduce coverage. In the normal scan this is not visible; in the investigation run an ignore-file skip makes the scan `partial`.
- A `.semgrepignore` can be a link to a file outside the target or pull one in with `:include`. Semgrep reads that file. It can only add ignore rules, with the same effect as rules written in the target. The API rejects a linked ignore file with every other link; `:include` is not rejected.
- A `.semgrepignore` in a parent folder above the target is honoured when that parent is a Git repository. A target that itself sits below a parent repository's `node_modules/` is excluded entirely and returns `partial` with no files scanned.
- Git repositories that have a default-ignored build output on disk (`dist/`, `build/`) and no `.semgrepignore` are `partial` in the investigation run. Before A4, Git hid that folder and the run was `completed`.
- A regular file named exactly `.git`, `node_modules` or `.venv` is excluded like a folder.
- A hard link to a file outside the target is scanned as a normal file.
- The adapter does not enforce Semgrep 1.182.1. The behaviour here was verified on that version only.
- Git configuration keys other than those listed above were not exercised individually. The fix does not depend on the key, since no Git process reads the target's configuration.

## Verification

- `tests/test_untrusted_git_scan_hardening.py` builds each Git-configuration path in a temporary directory and checks, with real Git and the real Semgrep subprocess, that the canary does not run, that no Git call touches the target, and that the vulnerable source file is still scanned and reported. A positive control first proves that plain Git does run the canary for each path.
- `tests/test_scan_scope_policy.py` covers the scope policy and the investigation table above with the real Semgrep subprocess and the real HTTP API, including a control that removes the adapter exclusions and shows the dependency tree being scanned.
- Unit tests in `tests/test_scan_evidence_manifest.py`, `tests/test_semgrep_parser.py`, `tests/test_finding_disappearance_evaluator.py` and `tests/test_investigation_evidence_registry.py` cover skip classification, the `partial` decision, refusal of non-canonical evidence, and failed-scan evidence.
