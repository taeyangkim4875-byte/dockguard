# dockguard

> Docker 호스트 통합 보안 진단 도구 — **"무엇이 위험한지"뿐 아니라 "고치면 무엇이 깨지는지"까지** 알려줍니다.

`dockguard`는 Docker 데몬 설정(`daemon.json`), docker-compose 파일, 컨테이너 네트워크 격리를 한 번에 점검하고,
각 취약점에 대해 **왜 위험한지 / 어떻게 고치는지 / 고치면 어떤 부작용이 있는지**를 한글로 설명하는 CLI 도구입니다.

```bash
dockguard scan
```

> 🚧 개발 중 — 현재 **Phase 1** (코어 엔진 + daemon 룰 3종) 완료 상태입니다. 로드맵은 아래를 참고하세요.

---

## 왜 만들었나

RabbitMQ 보안 조치(기본 `guest` 계정 제거) 작업 중 정전으로 서버가 재부팅되면서, 며칠에 걸쳐 이런 문제들을 겪었습니다.

- `docker compose down`으로 RabbitMQ 볼륨이 초기화되어 계정·큐가 사라짐
- 서비스 매니저와 백엔드의 RabbitMQ 접속 비밀번호 불일치
- **`daemon.json`의 `icc: false` + 커스텀 네트워크 격리로, 백엔드가 RabbitMQ에 접속하지 못함** ← 가장 찾기 어려웠던 문제
- 백엔드가 `RABBITMQ_HOST`를 호스트 외부 IP로 설정해 컨테이너 간 통신 실패

보안 설정 자체는 옳았지만, **그 설정이 서비스 간 통신에 미치는 영향**을 알려주는 도구는 없었습니다.
dockguard는 이 경험에서 출발해, 보안 권고와 함께 **부작용(tradeoff)**과 **서비스 의존성 통신 검증**을 제공합니다.

## 설치

Python 3.10 이상이 필요합니다.

```bash
git clone <this-repo> dockguard && cd dockguard
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## 사용법

```bash
# daemon.json 진단 (플랫폼별 표준 위치 자동 탐색)
dockguard scan --category daemon

# daemon.json 경로 직접 지정
dockguard scan -c daemon --daemon-config /etc/docker/daemon.json

# 위험 이유 · 수정 방법 · 부작용까지 상세 출력
dockguard scan -c daemon --explain
```

`daemon.json`이 없으면 **Docker 기본값 기준으로** 점검합니다. 파일이 없다고 안전한 것이 아니기 때문입니다
(예: `icc`의 기본값은 `true`, `no-new-privileges`의 기본값은 `false`).

### 출력 예시

```
┌──────────────────────────────────────────────┐
│  전체 점수: 67/100    등급 C                  │
│  ████████████████████░░░░░░░░░░               │
│   CRITICAL 0   HIGH 1   MEDIUM 1   LOW 1      │
│  통과 0 · 취약 3 · 주의 0 · 건너뜀 0          │
└──────────────────────────────────────────────┘
 심각도   ID           제목                       상태   현재값                     권장값
 HIGH     DAEMON-002   no-new-privileges 기본 활성화  취약   미설정 (Docker 기본값 false)  "no-new-privileges": true
 MEDIUM   DAEMON-001   ICC(컨테이너 간 통신) 제한     취약   미설정 (Docker 기본값 true)   "icc": false
 LOW      DAEMON-004   live-restore 활성화          취약   미설정 (Docker 기본값 false)  "live-restore": true
```

## 구현된 룰

| ID | 제목 | 심각도 | 근거 |
|----|------|--------|------|
| DAEMON-001 | ICC(컨테이너 간 통신) 제한 | MEDIUM | CIS 2.1 |
| DAEMON-002 | no-new-privileges 기본 활성화 | HIGH | CIS 2.18 |
| DAEMON-004 | live-restore 활성화 | LOW | CIS 2.14 |

## 보안 점수

100점에서 시작해 취약(FAIL) 항목마다 심각도별로 감점합니다 (CRITICAL 40 / HIGH 20 / MEDIUM 10 / LOW 3, 하한 0).
등급: 90+ **A**, 75+ **B**, 60+ **C**, 40+ **D**, 그 외 **F**.

## 아키텍처

```
CLI (scan) → Collector → ScanContext → Engine(Rule.check × N) → Finding[] → Scoring → Reporter
```

- **플러그인 룰 시스템**: `dockguard/rules/<카테고리>/` 아래에 파일 하나를 추가하고 `@register`를 붙이면 자동 등록됩니다.
- 룰은 Docker나 파일 시스템에 직접 접근하지 않고 `ScanContext`만 보므로, 실제 Docker 없이 테스트할 수 있습니다.
- 룰 하나에서 예외가 나도 전체 진단은 계속되고, 오류는 별도로 보고됩니다.

```python
@register
class NoNewPrivilegesRule(BooleanDaemonRule):
    id = "DAEMON-002"
    title = "no-new-privileges 기본 활성화"
    severity = Severity.HIGH
    key = "no-new-privileges"
    recommended_value = True
    docker_default = False
    why = "..."       # 왜 위험한가
    how_to_fix = "..." # 어떻게 고치나
    tradeoff = "..."  # 고치면 무엇이 깨지는가
```

## 개발

```bash
pytest                          # 전체 테스트
pytest --cov=dockguard          # 커버리지
```

## 로드맵

- [x] **Phase 1** — 코어 엔진, 플러그인 룰 레지스트리, daemon 룰 3종, 터미널 리포트, 점수
- [ ] **Phase 2** — daemon 룰 완성(10종), 안전한 자동 수정(`dockguard fix daemon`, 백업/dry-run), `dockguard rules`
- [ ] **Phase 3** — docker-compose 스캐너 (룰 12종, 자동 탐색)
- [ ] **Phase 4** — 네트워크 격리 + **서비스 의존성 통신 검증** (`--deps`)
- [ ] **Phase 5** — HTML/JSON 리포트, `dockguard learn` 보안 학습 기능
- [ ] **Phase 6** — 문서화, CI, 데모 시나리오
