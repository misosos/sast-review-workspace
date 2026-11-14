# Documentation index

The project is in maintenance: confirmed defects are fixed, and feature expansion is on hold. This page is the map of what is documented and where. For what the project is and whether it works, start with the [README](../README.en.md).

Language: the pages under "Start here" are in English. Research records and the historical development records are in Korean.

## Start here

| Page | Use it for |
| --- | --- |
| [README](../README.en.md) | One-page summary: what it is, status, results, main limitations |
| [Getting started](getting-started.md) | Setup, CLI, API configuration, dashboard, exports, troubleshooting |
| [Project overview](project-overview.md) | The problem, components, analyst workflow, security controls |
| [Known limitations](known-limitations.md) | Complete limitation list with evidence links, and what CI checks |

## Architecture and implementation

- [Project overview](project-overview.md): component table, architecture diagram, security controls
- [Local API](phase5a-local-api.md) and [React dashboard](phase5b-react-dashboard.md): the contracts the code implements
- [Baseline rule scope and limits](../rules/README.md): what each rule detects and misses
- [Investigation evidence lifecycle](er-c3a-investigation-evidence-lifecycle.md) and [secure investigation API](er-c3c-secure-investigation-api.md): design of the `/api/v2` investigation mode

## Validation and security limits

- [Known limitations](known-limitations.md)
- [Limitation triage](limitations-triage.md): each known limitation classified as defect, rule gap, design constraint, intended limit, validation gap, or out of scope
- [Frozen-state limitations](research/frozen-state-known-limitations.md): defects recorded during the 2026-11 closing review, with a note on what has since been fixed
- Synthetic detection benchmarks: [6A](phase6a-independent-detection-benchmark.md), [6D](phase6d-sast-generalization-evaluation.md), [6E](phase6e-heldout-sast-evaluation.md)
- [Browser security validation](phase5d-browser-security-validation.md)
- [Untrusted repository scan hardening (A4)](a4-untrusted-scan-git-hardening.md): a target's Git configuration can no longer run commands during a scan; scan-scope changes
- Isolation design, not built: [Phase 7C-1B](phase7c1b-verifiable-worker-design.md)

## Research results (D1, D2, U1)

The [research record](research/README.md) is the entry point: verdicts, limits, and how to recompute the scores. Experiment protocols, scripts, and raw outputs are under [`experiments/`](../experiments/).

## Historical development and QA records

These are the working records written while the product was built, kept as they were. They describe decisions and checks at the time and are **not** updated for later changes. Where one of them conflicts with the README or the research record, the README and the research record are current.

Screenshots under `assets/` belong to these records. Several directories there are also written by the Playwright browser tests, so they are not safe to delete without changing those tests.

### Detection rules and evidence model (Phase 3, 4, 6, R1, P6)

How the Semgrep rules were written, hardened, and benchmarked on synthetic corpora, and how per-finding evidence claims are gated.

- [P6-B — Dynamic Eval 오탐 회귀 테스트 강화](p6b-dynamic-eval-negative-regressions.md)
- [Phase 3A-3: Semgrep OSS trace 가용성 검증](phase3a-dataflow-trace-availability.md)
- [Phase 3A-4: Semgrep OSS SARIF Dataflow Evidence 가용성](phase3a-sarif-dataflow-availability.md)
- [Phase 3A-1: Semgrep OSS taint PoC 평가](phase3a-taint-evaluation.md)
- [Phase 3A-2: 내부 TaintEvidence 계약](phase3a-taint-evidence.md)
- [Phase 3B-1: Evidence Sufficiency Gate](phase3b1-evidence-sufficiency.md)
- [Phase 3B-2: EvidenceSummary contract and validation](phase3b2-evidence-summary.md)
- [Phase 3B-3: Validated Evidence Consumer Boundary](phase3b3-evidence-consumer.md)
- [Phase 3B-4: Independent evidence pipeline security validation](phase3b4-independent-security-validation.md)
- [Phase 4A-1 — Node.js command injection taint PoC](phase4a1-command-injection-taint.md)
- [Phase 4A-2 — Command Injection Rule Hardening 평가](phase4a2-command-injection-hardening.md)
- [Phase 4A-3 — Command Injection TaintEvidence 통합](phase4a3-command-injection-evidence.md)
- [Phase 6A — Independent Security Detection Benchmark](phase6a-independent-detection-benchmark.md)
- [Phase 6B — Firestore multi-operation rule hardening](phase6b-firestore-rule-hardening.md)
- [Phase 6C — Firestore semantic context validation](phase6c-firestore-context-validation.md)
- [Phase 6D — SAST generalization and security review relevance](phase6d-sast-generalization-evaluation.md)
- [Phase 6E — Held-out SAST 평가 및 Security Coverage Gap 분석](phase6e-heldout-sast-evaluation.md)
- [Phase 6F — Command Injection 의미 검증 및 제한적 범위 확장](phase6f-command-injection-semantic-validation.md)
- [Phase 6G — React HTML Sink Coverage Pilot](phase6g-react-html-sink-coverage.md)
- [Phase 6H — Eval Taint Source Provenance 및 Framework Context 검증](phase6h-eval-taint-source-context.md)
- [Phase 6I — Semgrep Taint Trace 근거 가능성 및 출처 검증](phase6i-taint-evidence-trace-feasibility.md)
- [Phase 6J — Trace-Free SAST Analyst Review Reliability Pilot](phase6j-analyst-evidence-reliability-pilot.md)
- [R1-P — `baseline.javascript-dynamic-eval` 규칙 품질 수정](r1p-dynamic-eval-rule-integration.md)

### Analyst review output (Phase 3C, analyst review)

The text and Markdown review reports and their small usability pilots.

- [분석가 검토 화면](analyst-review-view.md)
- [Phase 3C-2: Analyst Review 사용성 및 의미 정확성 평가](phase3c2-analyst-review-usability.md)
- [Analyst Review 이해도 질문지 — 참가자용](phase3c2-participant-questionnaire.md)
- [Analyst Review 이해도 채점표 — 진행자용](phase3c2-scoring-key.md)
- [Phase 3C-3: Analyst Review 파일럿 및 정보 밀도 기준선](phase3c3-analyst-review-pilot.md)
- [Analyst Review 형성적 파일럿 기록 양식](phase3c3-pilot-results-template.md)
- [Phase 3C-4: Evidence-Based Markdown Analyst Report](phase3c4-markdown-review-report.md)

### Local API and dashboard (Phase 5, 6K–6L)

The loopback API contract, the first dashboard, and browser security validation.

- [Phase 5A — 로컬 FastAPI 백엔드](phase5a-local-api.md)
- [Phase 5B — React Security Dashboard](phase5b-react-dashboard.md)
- [Phase 5C — Scan Context and UI Review Export](phase5c-analyst-workflow-export.md)
- [Phase 5D — Browser Security Validation](phase5d-browser-security-validation.md)
- [Phase 6K — 초보 사용자용 보안 대시보드 UX](phase6k-beginner-dashboard-ux.md)
- [Phase 6L — 초보 사용자 대시보드 직접 검수](phase6l-beginner-dashboard-acceptance.md)

### Repository intake and isolation design (Phase 7)

Threat model and design for scanning untrusted repositories in an isolated worker. Designed, never built.

- [Phase 7A — 보안 로컬 프로젝트 등록 및 선택 설계](phase7a-secure-local-project-selection.md)
- [Phase 7B — GitHub 저장소 수집 위협 모델 및 아키텍처](phase7b-github-repository-intake-threat-model.md)
- [Phase 7C-0 — 격리 분석 워커 실행 가능성 및 보안 검증](phase7c0-isolated-worker-validation.md)
- [Phase 7C-0Z — Ubuntu ARM64 CI 격리 준비 및 공급망 Gate](phase7c0-ubuntu-ci-readiness.md)
- [Phase 7C-1A — Semgrep 이미지 공급망 신뢰 평가](phase7c1a-supply-chain-trust-assessment.md)
- [Phase 7C-1B — 검증 가능한 Semgrep Worker 이미지 설계](phase7c1b-verifiable-worker-design.md)
- [Phase 7C-1C — Worker 빌드 입력 검증](phase7c1c-worker-build-input-verification.md)

### Comparison, review state, exports (Phase 8, P5)

Scan comparison, in-memory review state, backup and restore, SARIF export, accessibility and Safari checks.

- [P5 — 실패에 안전한 분석가 검토 재검사](p5-failure-safe-review-rescan.md)
- [Phase 8A — 검사 결과 비교](phase8a-scan-comparison.md)
- [Phase 8B — 검사 비교 Markdown 보고서 내보내기](phase8b-comparison-markdown-export.md)
- [Phase 8C — 분석가 Finding 검토 상태](phase8c-analyst-review-state.md)
- [Phase 8D — 분석가 검토 기록 Markdown 내보내기](phase8d-analyst-review-markdown-export.md)
- [Phase 8E — 분석가 검토 기록 JSON 백업 및 안전한 복원](phase8e-analyst-review-backup-restore.md)
- [Phase 8F — 실제 분석가 보안 분석 워크플로 E2E 검증](phase8f-end-to-end-analyst-workflow.md)
- [Phase 8G — 접근성·브라우저 검증 결과](phase8g-accessibility-browser-validation.md)
- [Phase 8G CI Repair — Finding 목록 레이아웃](phase8g-ci-layout-repair.md)
- [Phase 8G CI Repair 2 — Linux Chromium Finding 행 위치](phase8g-ci-layout-repair2.md)
- [Phase 8G — Safari·접근성 사용자 수용 검수표](phase8g-manual-safari-accessibility-acceptance.md)
- [Phase 8H — Safari QA 환경 준비 및 자동 검증](phase8h-safari-qa-environment.md)
- [Phase 8H — Safari 사용자 검수 실행 안내](phase8h-safari-user-acceptance-guide.md)
- [Phase 8H — Safari 사용자 수용 결과 기록](phase8h-safari-user-acceptance-results.md)
- [Phase 8H-UI CI 레이아웃 복구](phase8h-ui-ci-layout-repair.md)
- [Phase 8H-UI CI Repair 2 — 결과 레이아웃 회귀 복구](phase8h-ui-ci-layout-repair2.md)
- [Phase 8H-UI Readability — Finding 중심 결과 화면](phase8h-ui-readability-redesign.md)
- [Phase 8H-UI — 보안 분석가 작업 공간 UX 개선](phase8h-ui-security-analyst-workspace.md)
- [Phase 8J — 실무형 보안 분석 Markdown 보고서](phase8j-practical-security-markdown-report.md)
- [Phase 8K — Finding별 분석가 검토 가이드](phase8k-finding-triage-guidance.md)
- [Phase 8L — 재검사 기반 Finding 후속 검토 워크플로](phase8l-rescan-followup-workflow.md)
- [Phase 8M — SARIF 2.1.0 보안 분석 결과 내보내기](phase8m-sarif-export.md)
- [Phase 8N CI Repair — 320px 가로 넘침 복구](phase8n-ci-320-overflow-repair.md)
- [Phase 8N — GitHub Code Scanning 사전 진단](phase8n-github-code-scanning-preflight.md)

### Finding-disappearance investigation (ER series)

The evidence contract, registry, `/api/v2` flow, and evaluations behind the investigation mode. The D1 experiment later tested this feature against a script and found no advantage.

- [ER-C0 — Finding 소멸 원인 분석 Evidence Contract 설계](er-c0-finding-disappearance-evidence-contract.md)
- [ER-C1 — Scan Evidence Manifest MVP](er-c1-scan-evidence-manifest.md)
- [ER-C2 — Finding Disappearance Evidence Evaluator](er-c2-finding-disappearance-evaluator.md)
- [ER-C3A — Investigation Evidence Lifecycle & Binding Design](er-c3a-investigation-evidence-lifecycle.md)
- [ER-C3B — Bounded Investigation Evidence Registry](er-c3b-bounded-evidence-registry.md)
- [ER-C3C — Secure Investigation API](er-c3c-secure-investigation-api.md)
- [ER-C3D — Investigation Dashboard Integration](er-c3d-investigation-dashboard-integration.md)
- [ER-C3E — Investigation Security Acceptance](er-c3e-investigation-security-acceptance.md)
- [ER-C3E 사용자 수용 점검표](er-c3e-user-acceptance-checklist.md)
- [ER-C3F Safari 조사 수동 QA](er-c3f-safari-investigation-manual-qa.md)
- [ER-C3F 사용자 수용 기록](er-c3f-user-acceptance-record.md)
- [ER-C3G Safari 핵심 조사 흐름 사용자 수용](er-c3g-safari-core-user-acceptance-final.md)
- [Finding 消失の調査を支援する](er-d1-investigation-overview.md)
- [ER-D1 재현성 기록](er-d1-reproducibility-record.md)
- [ER-D10 분석가 수동 수용 결과 기록](er-d10-analyst-acceptance-results.md)
- [ER-D10 후속: 증거 해제 검증과 부분 검사 안내 정합성](er-d10-evidence-revocation-followup.md)
- [ER-D10 Safari 분석가 수동 검수 계획](er-d10-safari-manual-acceptance-plan.md)
- [ER-D10 보안 회귀 및 검수 환경 준비 기록](er-d10-security-regression.md)
- [Finding 변화 조사: 분석가 판단 워크플로](er-d2-analyst-decision-workflow.md)
- [ER-D2 분석가 워크플로 비교 평가 설계](er-d2-analyst-workflow-evaluation-design.md)
- [ER-D2 분석가 워크플로 비교 평가 결과](er-d2-analyst-workflow-evaluation-results.md)
- [ER-D2 재현성 기록](er-d2-reproducibility-record.md)
- [ER-D3 — Evidence Gap Technical Assessment](er-d3-evidence-gap-technical-assessment.md)
- [ER-D3 — Feasibility Experiment Results](er-d3-feasibility-experiment-results.md)
- [ER-D3 — ER-D4 Implementation Decision](er-d3-next-implementation-decision.md)
- [ER-D4 — Investigation Skip Evidence](er-d4-investigation-skip-evidence.md)
- [ER-D4 — Security E2E Acceptance](er-d4-security-e2e-acceptance.md)
- [ER-D5 — 다음 Evidence 개발 결정](er-d5-next-evidence-development-decision.md)
- [ER-D5 재현성 기록](er-d5-reproducibility-record.md)
- [ER-D5 — Skip Evidence 실효성 평가 설계](er-d5-skip-evidence-effectiveness-design.md)
- [ER-D5 — Skip Evidence 실효성 평가 결과](er-d5-skip-evidence-effectiveness-results.md)
- [ER-D6 — 실행 입력 연결 검증](er-d6-execution-binding-validation.md)
- [ER-D6 — 공개 Projection 후속 결정](er-d6-public-projection-decision.md)
- [ER-D6 — 비공개 규칙 바이트 관찰](er-d6-rule-bytes-identity.md)
- [ER-D7 Contract Compatibility](er-d7-contract-compatibility.md)
- [ER-D7 Rule Bytes Evidence Integration](er-d7-rule-evidence-integration.md)
- [ER-D7 Security E2E Acceptance](er-d7-security-e2e-acceptance.md)
- [ER-D8 Security E2E 검증](er-d8-security-e2e-acceptance.md)
- [ER-D8 Evidence Gap 평가](er-d8-security-evidence-gap-evaluation.md)
- [ER-D8 Security Evidence Gap Map](er-d8-security-evidence-gap-map.md)
- [ER-D9 분석가 수동 수용 기록](er-d9-analyst-acceptance-checklist.md)
- [ER-D9 기존 비교와 조사 증거의 차이](er-d9-differentiation-assessment.md)
- [ER-D9 실제 조사 결과](er-d9-real-world-investigation-results.md)
- [ER-D9 실제 대상 선정](er-d9-real-world-target-selection.md)
- [ER-D9 Security E2E 검증 기록](er-d9-security-e2e-acceptance.md)

### AI review research (not shipped)

Experiments with LLM-assisted review and code-context extraction. Never connected to the product.

- [AI 검토 계약과 신뢰 경계](ai-review-contract.md)
- [Phase 2B-3: 로컬 AI 응답 진단과 품질 평가](ai-review-diagnostics.md)
- [Phase 2B-4: 민감정보 및 근거 기반 평가](ai-review-evidence.md)
- [코드 문맥 추출 계약 (Phase 2A)](code-context.md)
- [Phase 2C-2: 제한 문맥과 구문 확장 문맥 비교](context-expansion-evaluation.md)
- [Phase 2D-1: Evidence-first AI Review PoC](evidence-first-review.md)
- [Phase 2D-2: Evidence-first timeout 원인 진단](evidence-first-timeout-diagnostics.md)
- [Phase 2D-3: Ollama 출력 토큰 상한 평가](evidence-first-token-cap-evaluation.md)
- [확장 코드 문맥 계약 (Phase 2C-1)](expanded-code-context.md)
- [Phase 2D-4: Minimal Evidence-first 출력 계약 평가](minimal-evidence-first-evaluation.md)

### UI redesign iterations

Successive dashboard redesign and readability records with before/after screenshots under `assets/`.

- [Phase 36.9B — 사이버펑크 대시보드 사용자 검수 준비](ui-cyberpunk-acceptance-36-9b.md)
- [Phase 36.9B-X — Reference-Driven Cyberpunk Control Deck](ui-cyberpunk-control-deck-36-9b-x.md)
- [Phase 36.9B-V — Cyberpunk / Sci-Fi HUD 시각 개선](ui-cyberpunk-hud-refinement-36-9b-v.md)
- [Phase 36.9A — 사이버펑크 보안 대시보드 리디자인](ui-cyberpunk-redesign-36-9a.md)
- [Phase UI-D2 — 승인된 하이브리드 디자인 구현](ui-d2-approved-design-implementation.md)
- [Phase UI-D3 — Safari 시각 다듬기 및 사용성 검증](ui-d3-visual-polish-safari-acceptance.md)
- [Phase UI-D4B — UI 콘텐츠 간소화 및 기능 필요성 검토](ui-d4b-content-simplification.md)
- [Phase UI-D4C-R — 사용 안내 화면 개선](ui-d4c-r-guide-layout-remediation.md)
- [UI-D5A — 데스크톱 앱 셸 재구성](ui-d5a-desktop-app-shell-redesign.md)
- [UI-D5A-R — 좁은 화면 페이지 헤더 정렬](ui-d5a-r-page-header-alignment.md)
- [Phase 36.9D — 큰 글씨와 화면 가독성 개선](ui-large-scale-readability-36-9d.md)
- [Phase 36.9B-Z — 큰 글씨와 가독성 개선](ui-large-type-readability-36-9b-z.md)

### Case studies

Worked examples of the investigation mode, written before the D1 experiment.

- [再検査で消えた Finding を調べる](case-studies/finding-disappearance-investigation.md)
- [証拠不足と比較拒否](case-studies/investigation-evidence-boundaries.md)

### Known gap in these records

`ui-d2-approved-design-implementation.md` links to five files under `design-exploration/ui-d1/` that were never committed. Those links are broken and were left as they are.
