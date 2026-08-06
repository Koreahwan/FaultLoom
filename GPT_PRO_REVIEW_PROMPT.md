# FaultLoom 공개 저장소 읽기 전용 리뷰 요청

다음 공개 저장소를 실제 코드·테스트·문서·Git 이력·CI 기준으로 리뷰해 주세요.

- Repository: https://github.com/Koreahwan/FaultLoom
- Review branch: `rebuild/r0001`. 공개 `main`은 아직 릴리스 승격 전의 최소
  브랜치이므로 이번 코드 리뷰 대상이 아닙니다.
- 리뷰 시작 시 `rebuild/r0001`의 실제 HEAD SHA를 먼저 기록하세요. 이
  프롬프트를 준비한 기준 SHA는
  `c1ca65aec33adceb7a888db2eb3604bcc896698c`이지만 공개 브랜치는 이동할 수
  있으므로, 다르면 그 차이를 먼저 밝히고 이후 판단이 어느 HEAD에 대한
  것인지 명시하세요.
- 저장소를 수정하거나 PR을 만들거나 외부 표적에 요청을 보내지 말고 읽기 전용으로 확인하세요.

## 제품 의도

FaultLoom은 한 명의 소유자가 실제 허가를 받은 유료 보안 업무와 버그바운티 연구에 사용하는 개인용 시스템입니다. 기업용 SaaS, 원격 fleet 관제, 무인 공격 서비스, 과장된 제로데이 탐지 제품이 목표는 아닙니다.

최종적으로 의도한 작업 흐름은 다음과 같습니다.

1. 각 engagement마다 별도의 명시적 허가와 정확한 범위를 입력하고 서명한다.
2. 서명된 범위 안에서만 자산·공격면을 찾고 취약점 가설을 우선순위화한다.
3. 모델과 도구가 exploit/PoC 후보를 만든다.
4. 범위·시간·요청 수·예산·위험 정책이 허용하는 검증만 자동 또는 감독형으로 실행한다.
5. 재현과 negative control로 오탐을 줄인다.
6. 정확한 요청·응답·도구 결과·실행 provenance를 증거로 묶는다.
7. 사람이 검토할 수 있는 보고서 초안을 만든다.
8. 외부 제출은 사용자가 최종 검토 후 직접 한다.

따라서 최종 의도에는 **허가된 범위 안의 자동 탐색, 취약점 발견, exploit/PoC 생성, 제한된 실행 검증, 재현, 증거화, 보고서 초안 생성**이 포함됩니다. 다만 이 문장만으로 현재 구현이 끝났다고 가정하지 말고, 공개 HEAD의 실제 코드와 테스트로 증명하세요.

## 권한·도구·모델 경계

- 개발 작업에 대한 포괄적인 사용자 승인은 실제 표적에 대한 권한이 아닙니다. 모든 engagement에는 별도 signed scope가 필요합니다.
- 모델이 스스로 범위를 넓히거나 권한을 부여해서는 안 됩니다. 상태 변경·고위험 작업·민감 데이터 처리·외부 제출에는 적절한 operator checkpoint가 필요합니다.
- exploit/PoC 후보 **생성**과 실행 권한은 분리되어야 합니다. 허가된 검증을 불필요하게 전면 차단하는지와, 반대로 범위 탈출·무제한 재시도·증거 위조·자격증명 유출을 막는지 모두 평가하세요.
- 공개 Core에는 개인용 supervised HTTP/1.1 triad 경로가 있습니다. `campaign prepare-http1-triad`가 오프라인 자동화 result/receipt의 한 admitted candidate를 operator-authored v1 template과 정확한 raw request digest에 묶고, 모델 출력이 path/header/body나 negative control을 바꿀 수 없으며 provider/target I/O 없이 review-required v2 spec만 만드는지 확인하세요. result/receipt/candidate/plan-authority/template/request digest가 정확히 검증되고 run/finalize 전에 다시 검증되는지도 보세요. `campaign run-http1-triad`의 strict spec, start-before-I/O 기록, effect 재사용(reproduction), request-target만 다른 negative control, 정확히 3회 순차 전송, ambiguous 시 `unresolved_no_retry`를 확인하세요. `campaign finalize-http1-triad`는 명시적인 non-sensitive 응답 검토 확인 뒤에만 오프라인에서 3개 교환을 보관하고 `exact_body_digest_v1`만 적용합니다. effect/reproduction body digest가 같고 control이 다를 때도 결과는 `draft_unverified`일 뿐이며, 그 외에는 `negative_campaign`입니다. 이 경로가 독립 검증·취약점 증명·자동 제출로 과장되지 않았는지 점검하세요.
- Burp는 선택적인 수동 분석 경로입니다. 사용자가 직접 열어 둔 경우에만 선택된 정확한 경로를 검토하고, FaultLoom이 Burp를 자동 실행·종료·재시작한다고 가정하지 마세요.
- GPT뿐 아니라 Kimi/Kimi K3 계열, GLM, Grok 및 향후의 미지 모델도 공식 API, 공식 CLI, 공식 OAuth/SDK 또는 합법적인 구독형 인터페이스로 연결할 수 있어야 합니다. 실제 모델 설치나 로그인이 완료됐다고 가정하지 말고, OpenAI-compatible 경로와 비호환 공식 인터페이스용 thin adapter 경계를 분리해 평가하세요.
- 모델 중립성은 최저 공통분모에 기능을 맞춘다는 뜻이 아닙니다. 공통 권한·증거 계약은 유지하면서 native tool schema, 구조화 출력, context/token budget, reasoning 옵션, capability negotiation이 모델별 장점을 보존하는지 확인하세요.
- KISS/YAGNI를 적용하세요. 한 명이 실제 사용하는 가장 작은 수직 기능과 실제 trust boundary는 엄격하게 보고, 개인 사용을 막는 기업용 fleet/RBAC/서비스 설치/과도한 릴리스 의식을 핵심 완료 조건으로 만들지 마세요.

## 공개 저장소의 한계

이 저장소는 공개 Core만 포함하는 정제본입니다. 비공개 Ops/Eval, 읽기 전용 legacy, targets, submissions, 원본 evidence 및 비공개 formal ledger는 공개 대상이 아닙니다.

예제 식별자, 테스트의 synthetic secret marker, vendored upstream test key는 fixture이며 실제 자격증명이 아닙니다. 문서의 T40 파일 경로와 서비스 경로도 배치된 비공개 Ops 데이터가 아니라 공개 아키텍처 예시입니다.

그러므로 공개 저장소만으로 비공개 Ops/Eval/ledger의 **존재나 부재를 증명할 수 없습니다**. 공개 트리에 없다는 이유만으로 원본 시스템에 없다고 추론하지 말고, 공개 Core가 실제로 보여 주는 범위와 공개만으로 미확인인 범위를 분리해 기록하세요. 반대로 문서의 PASS 주장도 코드·테스트·CI 산출물로 직접 확인하지 않은 이상 사실로 취급하지 마세요.

## 리뷰 방법과 반드시 답할 질문

다음 순서로 진행하세요.

1. 정확한 HEAD를 고정하고 공개 트리, 커밋 이력, 테스트, CI 설정과 최근 실행 결과를 읽습니다.
2. 제품 의도와 현재 공개 구현을 별도 표로 비교합니다.
3. 각 주장에 파일 경로, 심볼/함수, 테스트 이름 또는 커밋 근거를 붙입니다.
4. 확인하지 못한 사실은 `미확인`, 소스에서 직접 도출되지 않은 판단은 `추론`으로 표시합니다.

반드시 다음을 답하세요.

1. 의도와 충돌하는 코드·정책·문서는 무엇인가?
2. 현재 공개 구현으로 실제 수행 가능한 개인 유료 업무/버그바운티 작업과 불가능한 작업은 각각 무엇인가?
3. 최종 자동화(탐색→PoC 후보→검증→재현/negative control→증거→보고서 초안)까지의 가장 작은 핵심 수직 기능 격차는 무엇인가?
4. 현재 권한·예산·증거 계약이 richer Web/API 흐름과 controlled exploit 실행으로 확장 가능한가?
5. 모델별 성능을 보존하면서 새로운 공식 API/CLI/구독형 모델을 얇게 연결할 수 있는가?
6. 공유 맥락·기억이 공급자별 채팅 기록과 분리되어 있고 비밀·고객·표적 데이터가 공개 저장소에 새지 않는가? Triad의 authorization reference/digest와 private response/evidence 경계도 확인하세요.
7. 실제 안전 blocker와 단순한 형식적/비공개 영역 미완료를 구분했는가?
8. KISS/YAGNI 관점에서 삭제·단순화·연기할 것은 무엇이며 반드시 유지할 trust boundary는 무엇인가?
9. 지금 바로 사용할 운영 방식과 다음 3~6개 구현 milestone은 무엇인가?

## 출력 형식

한국어로 다음 순서로 작성하세요.

1. **한 줄 최종 판정**: 개인 실전 투입 가능 / 제한적 가능 / 불가 중 하나와 근거
2. **의도 충실도 표**: 의도, 현재 공개 구현, 근거 파일/심볼, 격차, 판단
3. **현재 가능한 작업과 불가능한 작업**
4. **실제 blocker**: 심각도, 재현 조건, 영향, 최소 수정안
5. **가장 짧은 다음 구현 순서**
6. **보안·정확성 결함**: 재현 조건과 관련 테스트
7. **KISS/YAGNI 정리**
8. **모델·맥락·기억 평가**
9. **최종 권고**

가장 중요한 원칙은 두 가지입니다.

> 현재 공개 코드로 증명된 bounded capability와 최종 제품 의도를 혼동하지 말 것.
>
> 허가된 실전 자동화의 길은 열어 두되, 실제 범위·증거·자격증명 trust boundary는 약화하지 말 것.
