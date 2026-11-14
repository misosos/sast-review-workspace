# ER-C1 — Scan Evidence Manifest MVP

## 범위와 결론

- 기준 커밋: `9d51434f163f74b0ea69caaffe0c6f4e9cf7e5d0`
- 계약: `scan-evidence-manifest/v1`
- 목적: 한 번의 Semgrep 실행에서 요청 문맥, 결과 Finding ID, 상태, 제한된 Scope 관찰을 내부적으로 연결
- 구현하지 않음: 소멸 원인 분석, 취약점 해결 판단, 공개 API 변경, 영구 저장, UI, 소스 스냅샷, GitHub 연동
- Semgrep 검사 실행 옵션과 기본 규칙은 변경하지 않음. `--verbose`도 추가하지 않음.

ER-C0의 핵심 경계를 따릅니다. Finding ID는 코드 동일성을 증명하지 않고, 같은 Rule Profile ID도 규칙 파일 바이트나 Semgrep의 실제 로딩을 증명하지 않습니다. `paths.scanned`는 Semgrep JSON이 보고한 경로 관찰이며 전체 파일 또는 규칙 분석 완료를 증명하지 않습니다. 수집하지 못한 자료는 “없음”으로 해석하지 않습니다.

## 기존 실행 흐름과 연결

`ScanService.scan()`의 공개 반환형은 계속 `ScanResponse`입니다. 이 메서드는 새 비공개 실행 경계인 `_scan_with_manifest()`를 호출하고 첫 번째 값만 반환합니다. 내부 테스트와 향후 서버 내부 소비자는 `(ScanResponse, ScanEvidenceManifest)` 쌍을 받을 수 있습니다. HTTP route는 기존 `scan()`만 사용하므로 Manifest와 Scan Reference는 API JSON에 들어가지 않습니다.

`SemgrepAdapter._scan_with_evidence()`가 기존과 같은 단일 Semgrep 실행과 단일 JSON 파싱을 수행합니다. `_ParsedSemgrepDocument`는 같은 파싱된 JSON 객체에서 Finding, Taint Evidence 연결 정보, `ScopeEvidence`를 제공합니다. Adapter의 공개 `scan()`은 계속 `ScanResult`만 반환합니다. Manifest 수집은 Semgrep을 재실행하거나 원본 JSON을 다시 파싱하지 않습니다.

ScanService는 요청 allowlist 재검증 후 매 실행마다 `secrets.token_urlsafe(24)`로 새 Reference를 만들고, 해당 실행에서 만든 응답의 Finding ID와 scope 자료를 함께 묶습니다. Profile ID 및 Target ID와도 바인딩합니다. `validate_manifest_binding()`은 다른 Reference, 대상 또는 프로필을 제공하면 `ManifestBindingError`를 발생시킵니다. Reference는 프로세스 메모리의 반환 객체에만 존재하며 registry나 저장소에 보존하지 않습니다.

## 내부 계약

주요 불변 타입은 다음입니다.

- `ScanEvidenceManifest`: 계약 버전, scan_ref, target/profile ID, Semgrep 버전, scan status, 응답 Finding ID, execution/rule/scope evidence, 고정 limitation 코드
- `ExecutionEvidence`: `semgrep`, 결과 상태, 검증된 Semgrep 버전, exit code, 고정 invocation ID
- `RuleEvidence`: 요청 profile ID, 신뢰된 규칙 파일의 상대 식별자, 선택 관찰 상태, bytes identity 및 실제 loaded identity 검증 상태
- `ScopeEvidence`: JSON `paths` 및 `scanned` 존재 여부, scanned/skipped/skipped_rules/errors의 수집 상태와 안전한 요약
- `SkippedPathEvidence`: 검증된 프로젝트 상대 경로와 고정 allowlist reason code만 보유

상태 의미:

| 상태 | 이 MVP에서의 의미 |
| --- | --- |
| `OBSERVED` | JSON에 필드가 있었고 정해진 구조와 경로 제한을 통과한 관찰 |
| `NOT_COLLECTED` | 필드가 없거나 실행이 시작되지 않아 자료를 얻지 못함. 부재나 skip 없음의 증거가 아님 |
| `UNAVAILABLE` | 자료가 잘못되었거나 제한을 넘어서 신뢰 가능한 값으로 사용할 수 없음 |
| `CONFLICTING` | 계약상 표현 가능하지만 현재 MVP는 충돌 증거를 수집하지 않아 생성하지 않음 |
| `NOT_APPLICABLE` | 계약상 표현 가능하지만 현재 MVP는 자동으로 생성하지 않음 |
| `UNVERIFIED` | 관련 항목은 식별했으나 해당 강한 속성은 확인하지 못함. 현재 rule bytes/loaded identity에 사용 |

`UNAVAILABLE`과 `NOT_COLLECTED`는 다릅니다. `ScopeEvidence` 상태와 `scan_status`도 별개입니다. 예를 들어 유효한 JSON에서 scope는 관찰됐지만 Semgrep exit code가 실패일 수 있습니다. 이를 성공적인 전체 검사로 합치지 않습니다. 별도 `completeness_status`는 현재 항상 `UNVERIFIED`입니다. `paths.scanned`가 관찰돼도 전체 범위 완전성을 입증하지 못하기 때문입니다.

## Scope Evidence 수집

현재 실행의 비-verbose JSON에 실제 필드가 있을 때만 기록합니다.

- `paths.scanned`: list 구조와 모든 경로가 유효할 때 상대 경로 전체를 `OBSERVED`로 저장. 빈 배열은 `OBSERVED` + count 0입니다.
- `paths` 누락 또는 `scanned` 누락: `NOT_COLLECTED`.
- `paths`/`scanned` 구조 오류, 부적합 경로, 중복 경로, NFC 정규화 충돌 또는 한도 초과: `UNAVAILABLE`. 유효한 일부 항목만 골라 완전한 목록처럼 표시하지 않습니다. JSON 배열 길이는 구조상 안전한 경우 보고된 count로 남을 수 있습니다.
- 절대경로 입력은 허용된 프로젝트 루트 아래인지 확인한 뒤 상대 식별자로 바꿉니다. 절대 경로는 저장하지 않습니다. 상대 경로의 `.`/`..`, 빈 구간, Windows 역슬래시/drive 형식, 제어문자 및 현재 확인되는 symlink 구성 요소는 거부합니다.
- `paths.skipped`: 필드가 현재 JSON에 실제 있는 경우만 처리합니다. 경로와 reason을 검증하고, 현재 1.182.1 합성 조사에서 확인한 `semgrepignore_patterns_match`만 허용합니다. 알 수 없는 자유형 reason 또는 한 경로 오류가 있으면 skipped 목록 전체를 `UNAVAILABLE`로 처리하고 reason 문구는 버립니다. A4-R1부터 어댑터가 항상 제외하는 이름(`.git`, `node_modules`, `.venv`)은 별도 코드 `adapter_policy_exclusion`으로 기록하며, 이 코드만 있는 실행은 `partial`이 되지 않습니다. 근거와 분류표는 [A4 기록](a4-untrusted-scan-git-hardening.md)에 있습니다.
- `skipped_rules`, `errors`: 원소 내용은 저장하지 않고, 제한된 list 구조의 count만 기록합니다. 오류 메시지, 규칙 본문 및 raw JSON은 Manifest에 복사하지 않습니다.

기본 실행은 기존처럼 `--verbose`를 사용하지 않습니다. 따라서 현재 실행에서 `paths.skipped`가 없으면 `NOT_COLLECTED`이며 “제외된 경로 없음”이 아닙니다. Semgrep 1.182.1 합성 테스트에서 `.semgrepignore`로 제외한 파일은 `paths.scanned`에 없었고 비-verbose JSON에 `paths.skipped`가 없었습니다. 제품은 그 제외 원인을 알아냈다고 주장하지 않습니다.

`paths.scanned`는 Semgrep이 JSON에서 보고한 처리 경로입니다. 이는 파일시스템 전체 manifest, 모든 규칙의 로딩/적용, 각 파일의 모든 규칙 분석 성공 또는 검사 완전성의 증명이 아닙니다. 파일이 목록에 없다는 사실만으로 삭제, ignore, 언어 미지원 또는 다른 원인을 추정하지 않습니다.

### 자원 경계

- Semgrep stdout/stderr 총량: 기존 2,000,000 byte 제한 유지
- 실행 제한 시간: 기존 60초 유지
- scanned 경로: 최대 100,000개
- skipped 경로: 최대 10,000개
- 단일 경로: UTF-8 최대 1,024 byte
- Manifest 경로 요약 합계: 최대 1 MiB
- Manifest 내부 JSON 표현: 최대 1 MiB
- skipped_rules/errors 요약 개수: 각각 최대 10,000개

범위를 넘으면 경로를 부분 저장하지 않고 해당 evidence를 `UNAVAILABLE`로 둡니다. Manifest 크기는 안전한 closed dataclass 자료만 JSON 직렬화해 실제 UTF-8 크기로 확인하며, 초과하면 scope 목록 전체를 비우고 `manifest_byte_limit_exceeded`로 표시합니다. 이 직렬화 바이트를 저장하거나 반환하지 않습니다. 실행 timeout, 출력 제한 또는 JSON 오류도 정상적인 빈 scope로 바꾸지 않습니다.

## Rule 및 실행 문맥

Manifest는 선택된 trusted profile의 상대 파일 식별자와 고정 invocation ID `semgrep-json-local-v1`을 저장합니다. 이 ID는 동적 대상/설정 경로를 포함하지 않는 정규화된 현재 옵션 집합을 가리킵니다. 응답에 유효한 Semgrep 버전과 scan status, 가능한 경우 정수 exit code를 둡니다.

`RuleEvidence.selected_status=OBSERVED`는 ScanService가 allowlist profile에서 규칙 파일을 선택해 기존 adapter에 전달했다는 뜻입니다. `byte_identity_status`와 `loaded_identity_status`는 `UNVERIFIED`입니다. 규칙 파일 digest를 수집하지 않으며 Semgrep이 어떤 bytes를 실제 로딩했는지도 검증하지 않습니다. 같은 profile ID가 같은 rule contents를 의미하지 않습니다. Scan start/end timestamp, 전체 argv, 환경, rule inventory 또한 기록하지 않습니다.

## 개인정보 및 API 보존

Manifest는 새 파일이나 DB에 저장하지 않고 일반 로그/보고서/CLI/SARIF/API로 출력하지 않습니다. 소스 원문·match excerpt·raw Semgrep JSON·자유형 메시지·stdout/stderr·환경변수·절대 경로·Git 정보·인증정보·digest를 수집하지 않습니다. target ID와 Finding ID는 내부 객체의 실행 연결용입니다.

공개 `ScanResponse`, FastAPI endpoint, Finding ID, Claims/Reasons 및 기존 분석 결과는 변경하지 않았습니다. Manifest를 만들 수 없는 보조 수집 예외는 scope evidence를 고정 limitation이 붙은 `UNAVAILABLE`로 대체하며 기존 유효한 ScanResponse는 반환합니다. 요청/대상 검증이나 scan 실행 자체의 실패 처리는 기존대로 유지됩니다.

## ER-C0의 18개 합성 시나리오 지원 범위

이 표는 **근거 수집 지원**만 평가합니다. 원인 정확도, 원인 판정 또는 취약점 해결 여부를 측정하지 않았습니다.

| # | 수집 상태 | 현재 가능한 관찰과 제한 |
|---:|---|---|
| 1 | 일부 가능 | 실행별 Ref, 버전/status, 보고 Finding ID 및 scanned 목록. 코드 동일성은 확인 불가. |
| 2 | 부분 수집 | 현재 경로 목록 차이는 볼 수 있지만 코드 bytes가 없어 코드 변경 증거/인과 판단 불가. |
| 3 | 일부 가능 | 현재 scanned 목록의 부재만 관찰. 삭제 원인은 판단 불가. |
| 4 | 미구현 | 파일 rename 및 byte identity 수집이 없음. |
| 5 | 미구현 | 이동된 Finding을 연결하는 association evidence가 없음. |
| 6 | 가능 | 요청 Rule Profile ID 차이는 각 Manifest에서 구별. 원인 판정 없음. |
| 7 | 미구현 | 동일 ID의 rule content digest와 loaded identity를 수집하지 않음. |
| 8 | 가능 | 유효한 Semgrep version 차이를 관찰할 수 있음. 원인 판정 없음. |
| 9 | 제한적 | JSON에서 명시적 allowlist skip이 검증되면 경로와 이유를 관찰. 기본 비-verbose는 보통 skip 자료를 주지 않음. |
| 10 | 제한적 | `paths.skipped`가 제공된 경우만 allowlist 이유 수집. 누락은 `NOT_COLLECTED`. |
| 11 | 가능 | `partial` status와 고정 errors/skip count를 관찰. 파일별 실패 연결은 미구현. |
| 12 | 일부 가능 | Manifest가 finding/displayed/omitted count를 보존. 생략 Finding의 개별 ID는 추정하지 않으며 부재 비교 차단은 ER-C2 범위. |
| 13 | 미구현 | 실행 중 소스 전후 snapshot 또는 in-engine byte identity가 없음. |
| 14 | 부분 수집 | 경로/요약 상한 초과는 `UNAVAILABLE`; 전체 source snapshot은 없음. |
| 15 | 미구현 | Finding ID와 bytes를 연결/비교할 snapshot evidence가 없음. |
| 16 | 미구현 | 원인 가설 생성/비교 로직이 없음. |
| 17 | 가능 | 누락·오류는 `NOT_COLLECTED`/`UNAVAILABLE`과 limitation으로 남김. 해석은 UNDETERMINED여야 함. |
| 18 | 가능 | 정상 status와 0건을 관찰. 안전/취약점 부재를 추론하지 않음. |

## 검증 결과

- Manifest 경계 테스트: `uv run --locked --group dev pytest -q tests/test_scan_evidence_manifest.py` — **30 passed** (직렬화 크기 상한 포함)
- 변경 영향 집중 회귀(parser/adapter/ScanService/API contract/실제 Semgrep 포함) — **98 passed**
- Semgrep: 실제 1.182.1 + 저장소 baseline 규칙 + 합성 JavaScript 실행에서 Finding 및 `paths.scanned` 관찰. `.semgrepignore` 제외 사유는 현재 비-verbose 실행에서 제공되지 않아 `NOT_COLLECTED`.
- 공개 API: 기존 contract tests와 응답 필드 집합 검사 통과. Manifest에 scan_ref가 포함되지 않음.
- 전체 Python: `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs` — **579 passed, 28 skipped**, 1 warning, 246.64초. Skip은 Ollama 기반 선택 합성 테스트이며 실행을 요구하는 환경변수가 설정되지 않음.
- Lock: `uv lock --check` — 통과. Python **3.12.7**, Semgrep **1.182.1**.
- Frontend: Node **24.22.2**. TypeScript typecheck 통과, Vitest **180 passed**, production build 통과.
- Chromium: CI 모드 + 고유 preview port에서 **49 passed**. axe 검사 포함. 1440×900 Finding 목록 Y=724.44px, 첫 행 Y=784px.
- WebKit: **2 passed**. Playwright WebKit 결과이며 실제 Safari 검수가 아님.
- 실제 FastAPI–Semgrep–Chromium E2E: **2 passed**. Safari QA 회귀: **7 passed**.
- `git diff --check`: 최종 검사에서 통과.
- 실제 Safari 및 VoiceOver 사용자 검수: 수행하지 않음.

## ER-C2 진입 조건과 미구현

후속 단계 전에 Manifest 보존/retention과 소멸 후 소비자 수명을 정해야 합니다. 부재를 해석하려면 omissions와 completeness를 run-bound로 연결하고, Semgrep 버전별 scanned/skipped 의미를 고정 fixture로 유지해야 합니다. File snapshot, rule byte identity, 파일별 오류, 실제 loaded rule inventory, 저장/삭제, MAC/HMAC 및 개인정보 정책은 별도 검토가 필요합니다. `--verbose`는 분석 옵션 변화, 출력 및 시간 영향의 별도 승인/검증 전까지 추가하지 않습니다.

현재는 원인 판단기나 `EXPLANATION_SUPPORTED` 결과를 구현하지 않았습니다. 경로가 보고됐거나 Finding이 현재 목록에 없다는 이유로 “삭제됨”, “수정됨”, “해결됨”을 추론하지 않습니다. ER-C1의 결과는 제한된 실행 증거 수집 MVP이며 완전한 검사 manifest가 아닙니다.
