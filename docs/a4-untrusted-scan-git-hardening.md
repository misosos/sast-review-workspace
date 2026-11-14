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

## Scan scope changes

The public `ScanResponse` and investigation contracts are unchanged. What a scan covers changes for Git repositories:

- **Nothing previously scanned is lost.** In every fixture the new scanned set contained the old one.
- **Gitignored files are now scanned**, for example a local-only source file, `coverage/`, `.next/`, `out/`, `target/`, `tmp/`. Findings there are new and their IDs are stable across repeated scans.
- **The result no longer depends on `.gitignore`.** Deleting it, rewriting it to ignore everything, or removing `.git` gives the same scanned set. A folder scans the same whether or not it is a Git repository.
- **Semgrep's built-in default ignore list still applies** when the project has no `.semgrepignore`: `node_modules/`, `.venv/`, `dist/`, `build/`, `vendor/`, `test/`, `tests/`, `*.min.js`, `.git/`.
- **A project's own `.semgrepignore` still applies and replaces that default list.** If it does not list `node_modules/`, the dependency folder is now scanned, because Git no longer hides it. On a fixture with a real 141 MB `node_modules`, the scan went from 452 files in 4 s to 4,486 files in 38 s. A larger project can reach the 60 s limit and return `timed_out`. This is visible, not silent.
- **Investigation (verbose) scans of a Git repository now return `partial`.** Semgrep reports `.git` as skipped, and it reports default-ignored folders that Git used to hide without a trace. The run is honest about the omission, and a comparison involving it is `INCOMPARABLE`. Before, such a scan returned `completed` while the same folders were unscanned.

Typical project without its own `.semgrepignore` (728 tracked files, real `node_modules`, built assets): 46 files in about 4 s before, 47 files in about 5 s after.

Proposed, not implemented: an explicit adapter-owned exclusion list (`node_modules/`, `.venv/`, `.git/`) passed with `--exclude`, so dependency folders stay out even when a project replaces the default list. It needs a decision first, because it changes which paths the product reports as skipped and adds a skip reason the evidence contract does not accept yet.

## Not covered

- Semgrep still has no OS-level isolation. Scan untrusted repositories only inside a separately isolated environment.
- `.semgrepignore` and inline `nosemgrep` comments are controlled by the target and can reduce coverage. They are not a safety boundary.
- A `.semgrepignore` in a parent folder above the target is honoured when that parent is a Git repository.
- A hard link to a file outside the target is scanned as a normal file.
- The adapter does not enforce Semgrep 1.182.1. The behaviour here was verified on that version only.
- Git configuration keys other than those listed above were not exercised individually. The fix does not depend on the key, since no Git process reads the target's configuration.

## Verification

`tests/test_untrusted_git_scan_hardening.py` builds each path above in a temporary directory and checks, with real Git and the real Semgrep subprocess, that the canary does not run, that no Git call touches the target, and that the vulnerable source file is still scanned and reported. A positive control first proves that plain Git does run the canary for each path. With the fix reverted, 9 of the 15 tests fail.
