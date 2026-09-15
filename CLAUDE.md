# CLAUDE.md — dockguard 프로젝트 지침서

> 이 문서는 Claude Code가 **dockguard** 프로젝트를 처음부터 끝까지 만들 때 따르는 마스터 설계서입니다.
> 작업을 시작하기 전에 이 문서 전체를 읽고, 항상 여기 정의된 아키텍처·규칙·원칙을 지켜 주세요.
> 이 문서는 프로젝트 소유자(백엔드/인프라 엔지니어)의 실제 운영 경험에서 나온 요구사항을 담고 있습니다.

---

## 0. 이 프로젝트는 무엇인가

**dockguard**는 Docker 호스트의 보안 취약점을 자동으로 진단하고, 각 취약점에 대해
"왜 위험한지 / 어떻게 고치는지 / 고치면 어떤 부작용이 있는지"를 설명해 주는 **통합 보안 진단 도구**(CLI)입니다.

세 영역을 한 번에 점검합니다:
1. **Docker 데몬 설정** (`/etc/docker/daemon.json`)
2. **docker-compose 파일** (privileged, root 실행, 평문 시크릿, docker.sock 마운트 등)
3. **네트워크 격리 및 서비스 간 의존성** (컨테이너들이 서로 통신 가능한지)

### 만든 배경 (중요 — 이 프로젝트의 정체성)

이 도구는 실제 운영 사고에서 탄생했습니다. 소유자는 RabbitMQ 보안 조치(기본 guest 계정 제거) 작업 중,
정전으로 서버가 재부팅되면서 다음 문제들을 며칠에 걸쳐 겪었습니다:

- `docker compose down`으로 RabbitMQ 볼륨이 초기화되어 계정/큐가 사라짐
- 서비스 매니저와 백엔드의 RabbitMQ 접속 비밀번호가 불일치
- **daemon.json의 `icc: false` + 커스텀 네트워크 격리로, 백엔드(브리지 네트워크)가 RabbitMQ에 접속하지 못함** ← 가장 찾기 어려웠던 문제
- 백엔드가 `RABBITMQ_HOST`를 호스트 외부 IP로 설정해 컨테이너 간 통신이 안 됨

이 경험이 dockguard의 **킬러 기능(네트워크 의존성 검증)**과 **부작용 설명(tradeoff)** 기능의 근거입니다.
단순히 "이 설정을 켜라"가 아니라, "이 설정을 켜면 이런 통신 문제가 생길 수 있다"까지 알려주는 것이 이 도구의 차별점입니다.

### 목표
- **사용성**: 설치 후 `dockguard scan` 한 줄로 즉시 진단 결과 확인
- **교육성**: 각 취약점마다 상세한 한글 설명 → 소유자가 보안을 학습할 수 있게
- **안전성**: 자동 수정은 위험하므로 기본은 "진단 + 제안", 수정은 명시적 승인 + 백업 필수
- **포트폴리오 품질**: 확장 가능한 설계, 테스트 코드, 문서화, HTML 리포트

---

## 1. 기술 스택

- **언어**: Python 3.10+
- **핵심 라이브러리**:
  - `docker` (Docker SDK for Python) — 컨테이너/네트워크 정보 수집. 없거나 실패 시 `subprocess`로 `docker` CLI 폴백
  - `PyYAML` — compose 파일 파싱
  - `click` 또는 `typer` — CLI (typer 권장, 타입 힌트 기반이라 깔끔)
  - `rich` — 터미널 컬러 출력, 테이블, 진행 표시 (사용성 핵심)
  - `jinja2` — HTML 리포트 템플릿
  - `pytest` — 테스트
- **패키징**: `pyproject.toml` 기반, `pip install -e .`로 개발 설치, `dockguard` 콘솔 스크립트 등록
- **의존성 최소화**: 위 목록 외 무거운 의존성은 지양

---

## 2. 아키텍처 (플러그인 룰 시스템)

핵심 설계 사상: **룰(Rule)을 플러그인처럼 독립 파일로** 만든다.
새 취약점 점검을 추가할 때 파일 하나만 추가하면 자동 등록되도록 한다. 이것이 확장성의 핵심이다.

```
dockguard/
├── pyproject.toml
├── README.md
├── CLAUDE.md                      # 이 문서
├── dockguard/
│   ├── __init__.py
│   ├── cli.py                     # typer 기반 CLI 진입점
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py              # Finding, Severity, RuleResult 등 데이터 모델
│   │   ├── rule.py                # Rule 베이스 클래스 + 자동 등록(registry)
│   │   ├── context.py             # ScanContext: 수집된 모든 데이터를 담는 객체
│   │   ├── collector.py           # Docker 데이터 수집 (daemon/컨테이너/네트워크)
│   │   ├── engine.py              # 룰 실행 엔진
│   │   └── scoring.py             # 보안 점수 계산
│   ├── rules/
│   │   ├── __init__.py            # rules 디렉토리 자동 스캔 → 룰 등록
│   │   ├── daemon/                # daemon.json 룰
│   │   ├── compose/               # docker-compose 룰
│   │   └── network/               # 네트워크/의존성 룰
│   ├── remediators/
│   │   ├── __init__.py
│   │   └── daemon_remediator.py   # daemon.json 안전 수정 (백업/dry-run)
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── terminal.py            # rich 기반 터미널 리포트
│   │   ├── html.py                # jinja2 HTML 리포트
│   │   └── json_reporter.py       # JSON 출력
│   ├── templates/
│   │   └── report.html.j2
│   └── knowledge/                 # 보안 교육 콘텐츠 (학습용)
│       └── explanations.py        # 각 취약점의 상세 설명(배경지식) 저장소
├── config/
│   ├── ruleset.yaml               # 룰 on/off, 심각도 커스터마이즈
│   └── dependencies.example.yaml  # 서비스 의존성 정의 예시
└── tests/
    ├── conftest.py
    ├── fixtures/                  # 테스트용 가짜 daemon.json, compose 파일
    ├── test_daemon_rules.py
    ├── test_compose_rules.py
    ├── test_network_rules.py
    └── test_engine.py
```

### 데이터 흐름

```
CLI (scan 명령)
   ↓
Collector: daemon.json + docker inspect + docker network 수집 → ScanContext
   ↓
Engine: 등록된 모든 Rule.check(context) 실행 → Finding 리스트
   ↓
Scoring: Finding들로 보안 점수 산출
   ↓
Reporter: 터미널/HTML/JSON 출력
   ↓
(선택) Remediator: 사용자가 승인한 Finding만 수정 (백업 + dry-run)
```

---

## 3. 핵심 데이터 모델 (core/models.py)

```python
from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"   # 즉시 조치 (호스트 장악 가능 등)
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        # 점수 계산용 가중치
        return {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}[self.value]

class Status(Enum):
    PASS = "pass"       # 통과
    FAIL = "fail"       # 취약점 발견
    WARN = "warn"       # 주의
    SKIP = "skip"       # 점검 불가(대상 없음)

@dataclass
class Finding:
    rule_id: str            # 예: "DAEMON-001"
    title: str              # 짧은 제목
    category: str           # daemon / compose / network
    severity: Severity
    status: Status
    target: str             # 발견 위치 (파일 경로, 컨테이너명 등)
    current_value: str      # 현재 상태
    recommended: str        # 권장 상태
    why: str                # 왜 위험한가 (교육용, 상세하게)
    how_to_fix: str         # 어떻게 고치나 (구체적 명령/설정)
    tradeoff: str = ""      # 고쳤을 때 부작용/주의 (dockguard의 차별점!)
    reference: str = ""     # 근거 (CIS Docker Benchmark 항목 번호 등)
    auto_fixable: bool = False
    learn_more: str = ""    # 심화 학습 링크/설명 (knowledge 연결)
```

**중요**: `why`, `tradeoff`, `learn_more`는 반드시 충실하게 채운다. 이 도구의 교육적 가치가 여기서 나온다.
설명은 한글로, 실무자가 바로 이해할 수 있게 구체적으로 작성한다.

---

## 4. Rule 베이스 클래스와 자동 등록 (core/rule.py)

```python
from dockguard.core.models import Finding
from dockguard.core.context import ScanContext

_REGISTRY: list[type["Rule"]] = []

def register(cls):
    """룰 클래스 데코레이터 — import되면 자동 등록"""
    _REGISTRY.append(cls)
    return cls

def all_rules() -> list["Rule"]:
    return [cls() for cls in _REGISTRY]

class Rule:
    id: str = ""
    category: str = ""       # daemon / compose / network
    title: str = ""

    def check(self, context: ScanContext) -> list[Finding]:
        raise NotImplementedError

    def remediate(self, finding: Finding, context: ScanContext, dry_run: bool = True):
        """수정 로직 (선택 구현). 기본은 미지원."""
        raise NotImplementedError(f"{self.id}는 자동 수정을 지원하지 않습니다.")
```

`rules/__init__.py`에서 `rules/daemon`, `rules/compose`, `rules/network` 하위의 모든 모듈을
자동 import 하여 `@register`가 실행되도록 한다 (importlib + pkgutil 사용).

---

## 5. 룰 명세 (구현할 취약점 목록)

각 룰은 CIS Docker Benchmark 및 실무 베스트프랙티스에 근거한다.
아래는 **반드시 구현할 룰 목록**이며, `why`/`tradeoff`는 예시 수준으로 적어두었으니 Claude Code가 더 풍부하게 확장할 것.

### 5.1 Daemon 룰 (rules/daemon/)

| ID | 제목 | 권장값 | 심각도 | CIS |
|----|------|--------|--------|-----|
| DAEMON-001 | ICC(컨테이너 간 통신) 제한 | `icc: false` | MEDIUM | 2.1 |
| DAEMON-002 | no-new-privileges 활성화 | `no-new-privileges: true` | HIGH | 2.18 |
| DAEMON-003 | userland-proxy 비활성화 | `userland-proxy: false` | MEDIUM | 2.16 |
| DAEMON-004 | live-restore 활성화 | `live-restore: true` | LOW | 2.14 |
| DAEMON-005 | 로그 드라이버/크기 제한 | `log-driver` + `max-size` 설정 | LOW | 2.6 |
| DAEMON-006 | user namespace remapping | `userns-remap: default` | HIGH | 2.8 |
| DAEMON-007 | daemon.json 파일 권한 | 소유자 root, 권한 0644 이하 | MEDIUM | 3.x |
| DAEMON-008 | 기본 seccomp 프로파일 유지 | seccomp 비활성화 안 함 | HIGH | 5.21 |
| DAEMON-009 | iptables 관리 활성화 | `iptables: true`(또는 미설정) | MEDIUM | - |
| DAEMON-010 | insecure-registry 미사용 | `insecure-registry` 비어있음 | HIGH | - |

**DAEMON-001 (ICC) 설명 작성 지침 — 소유자의 실제 사고를 반영:**
- why: 기본 브리지의 모든 컨테이너가 서로 통신 가능하면, 한 컨테이너가 침해됐을 때 다른 컨테이너로 측면 이동(lateral movement)이 쉬워진다.
- tradeoff: **`icc: false`로 설정하면 기본 브리지의 컨테이너 간 통신이 차단된다. 통신이 필요한 서비스(예: 백엔드↔메시지큐)는 반드시 같은 커스텀 네트워크에 두어야 하며, 그렇지 않으면 서비스 연결이 끊긴다. 실제로 이 설정 때문에 메시지큐 소비가 중단되는 사고가 흔하다.** ← 이 부작용 설명이 dockguard의 핵심 가치다.

**DAEMON-006 (userns-remap) 주의:** 이 설정을 켜면 기존 볼륨의 파일 소유권(uid/gid)이 리매핑되어 권한 문제가 생길 수 있음을 tradeoff에 명시.

### 5.2 Compose 룰 (rules/compose/)

compose 파일을 파싱해 각 서비스(service)를 검사한다. 여러 compose 파일을 대상으로 할 수 있어야 함.

| ID | 제목 | 조건 | 심각도 |
|----|------|------|--------|
| COMPOSE-001 | privileged 모드 사용 금지 | `privileged: true` 발견 | CRITICAL |
| COMPOSE-002 | non-root 사용자 지정 | `user:` 미지정 (root 실행) | HIGH |
| COMPOSE-003 | no-new-privileges 설정 | `security_opt`에 no-new-privileges 없음 | MEDIUM |
| COMPOSE-004 | docker.sock 마운트 경고 | volumes에 `/var/run/docker.sock` | CRITICAL |
| COMPOSE-005 | 평문 시크릿 금지 | environment에 password/secret/key 평문 | HIGH |
| COMPOSE-006 | 읽기전용 루트 FS | `read_only: true` 미설정 | LOW |
| COMPOSE-007 | 리소스 제한 | cpu/memory 제한 없음 | MEDIUM |
| COMPOSE-008 | 호스트 네트워크 모드 경고 | `network_mode: host` | MEDIUM |
| COMPOSE-009 | 호스트 PID/IPC 공유 금지 | `pid: host` 또는 `ipc: host` | HIGH |
| COMPOSE-010 | Capabilities 최소화 | `cap_add`에 위험 권한(SYS_ADMIN 등) | HIGH |
| COMPOSE-011 | latest 태그 금지 | 이미지가 `:latest` 또는 태그 없음 | LOW |
| COMPOSE-012 | 특권 포트 매핑 경고 | 호스트 1024 미만 포트 바인딩 | LOW |

**COMPOSE-005 (평문 시크릿) 설명 — 소유자 경험 반영:**
- why: docker-compose.yml은 보통 git으로 관리되므로, 평문 비밀번호가 저장소에 노출되면 유출된다. 실제로 모의해킹에서 자주 지적되는 항목.
- how_to_fix: `.env` 파일로 분리하고 `chmod 600` 적용, `.gitignore`에 `.env` 추가. compose에서는 `${VAR}` 참조.
- tradeoff: `.env` 파일과 compose가 같은 디렉토리에 있어야 `${VAR}` 치환이 됨. `env_file`로 지정한 경로와 변수 치환용 `.env`는 다르다는 점 주의.

**COMPOSE-008 (host 네트워크):** 이건 CRITICAL이 아니라 MEDIUM. 실무에서 정당하게 쓰는 경우(예: GPU 서비스, 성능)가 많으므로, "위험하니 무조건 제거"가 아니라 "필요성을 검토하라"는 톤으로 작성.

### 5.3 Network 룰 (rules/network/) — dockguard의 킬러 기능

| ID | 제목 | 설명 | 심각도 |
|----|------|------|--------|
| NET-001 | 서비스 의존성 통신 검증 | dependencies.yaml에 정의된 A→B가 같은 네트워크에 있는지 | CRITICAL |
| NET-002 | 고아 컨테이너 네트워크 점검 | 어떤 커스텀 네트워크에도 안 붙은 컨테이너 | LOW |
| NET-003 | 기본 브리지 사용 경고 | 커스텀 네트워크 대신 기본 bridge 사용 | MEDIUM |
| NET-004 | 외부 노출 포트 점검 | 0.0.0.0으로 바인딩된 민감 포트(5672, 15672, 3306 등) | HIGH |

**NET-001 (의존성 검증) — 이 룰이 dockguard의 정체성:**

`config/dependencies.yaml`에 사용자가 서비스 간 의존성을 선언한다:

```yaml
dependencies:
  - from: "backend-container"
    to: "rabbitmq"
    port: 5672
    reason: "백엔드가 RabbitMQ 큐를 소비"
  - from: "service-manager"
    to: "rabbitmq"
    port: 5672
    reason: "서비스 매니저가 메시지 발행"
```

룰은 각 의존성에 대해:
1. `from`과 `to` 컨테이너가 실제로 존재하는지
2. 둘이 공유하는 Docker 네트워크가 있는지 (없으면 통신 불가)
3. (가능하면) `to`가 해당 포트를 리스닝하는지

를 검사한다. 공유 네트워크가 없으면 CRITICAL Finding 생성:
- why: "{reason} — 하지만 두 컨테이너가 공유하는 네트워크가 없어 통신이 불가능하다. 정전/재기동 후 네트워크가 분리되면 이런 상황이 발생한다."
- how_to_fix: "`docker network connect <공통네트워크> {to}` 또는 compose에 두 서비스를 같은 네트워크로 명시."
- tradeoff: "네트워크 연결은 신중히. 임시로 `docker network connect`한 것은 재기동 시 풀리므로, compose에 영구 반영해야 한다."

**이 룰의 시나리오**: 정전 후 재기동 → `dockguard scan` → "backend → rabbitmq 통신 불가"를 즉시 발견.
README와 데모에서 이 스토리를 반드시 부각할 것.

**NET-004 (외부 노출 포트) — 소유자 경험:** RabbitMQ의 5672/15672가 0.0.0.0으로 열려 외부에서 guest 계정으로 접속당한 실제 모의해킹 사례가 근거. 민감 포트 목록(5672, 15672, 3306, 6379, 27017 등)을 knowledge에 정의.

---

## 6. 보안 교육 콘텐츠 (knowledge/explanations.py)

소유자가 **공부할 수 있도록**, 각 취약점의 배경지식을 별도로 정리한다.
Finding의 짧은 설명과 별개로, "이 개념이 무엇이고 왜 중요한지"를 깊이 있게 담는다.

각 항목 구조:
```python
EXPLANATIONS = {
    "icc": {
        "concept": "ICC(Inter-Container Communication)란 무엇인가",
        "detail": "Docker 기본 브리지 네트워크(docker0)에서... (문단 단위 상세 설명)",
        "attack_scenario": "공격자가 웹 컨테이너를 침해한 뒤, 같은 브리지의 DB 컨테이너에 접근하는 측면 이동 시나리오...",
        "best_practice": "서비스별로 커스텀 네트워크를 분리하고, 필요한 통신만 명시적으로 허용...",
        "real_world": "이 프로젝트 소유자는 icc:false 환경에서 백엔드가 메시지큐에 못 붙는 사고를 겪었다. 보안과 가용성의 균형이 중요하다는 교훈.",
    },
    # rootless, userns-remap, seccomp, capabilities, docker.sock, lateral-movement 등
}
```

`dockguard learn <주제>` 명령으로 이 내용을 터미널에서 읽을 수 있게 한다 (교육 기능).
최소 다음 주제를 포함: `icc`, `rootless`, `userns-remap`, `seccomp`, `capabilities`,
`docker-sock`, `lateral-movement`, `privileged`, `network-isolation`, `secrets-management`.

---

## 7. CLI 설계 (cli.py) — 사용성 핵심

typer + rich로 구현. 명령 체계:

```bash
# 전체 진단 (가장 많이 쓸 명령) — 즉시 실행 가능해야 함
dockguard scan                          # daemon + compose(자동탐색) + network 전부
dockguard scan --category daemon        # 특정 카테고리만
dockguard scan --compose ./docker-compose.yml   # 특정 compose 파일
dockguard scan --deps ./config/dependencies.yaml  # 의존성 검증 포함

# 상세 설명 포함 출력
dockguard scan --explain                # 각 Finding의 why/tradeoff 전부 표시

# 리포트 생성
dockguard scan --output report.html     # HTML 리포트
dockguard scan --format json            # JSON 출력 (파이프/연동용)

# 보안 학습
dockguard learn                         # 학습 주제 목록
dockguard learn icc                     # 특정 주제 상세 설명

# 수정 (안전장치 필수)
dockguard fix daemon --dry-run          # 수정 미리보기 (기본)
dockguard fix daemon --apply            # 실제 적용 (백업 자동, 재확인 프롬프트)

# 룰 목록
dockguard rules                         # 등록된 모든 룰과 심각도 표시
```

### 사용성 요구사항 (반드시 지킬 것)
- `dockguard scan`을 인자 없이 실행해도 **똑똑하게 동작**: 현재 디렉토리와 하위에서 compose 파일 자동 탐색, daemon.json 자동 점검
- **rich로 컬러 출력**: CRITICAL은 빨강, HIGH 주황, 요약 테이블, 진행 스피너
- **보안 점수 표시**: `전체 점수: 62/100` 형태로 상단에 크게
- Docker 데몬에 접근 못 하면(권한 없음 등) 친절한 안내 메시지 (크래시 금지)
- `--explain` 없이는 요약만, 붙이면 상세 — 정보 과부하 방지

---

## 8. 리포트 (reporters/)

### 터미널 (terminal.py)
rich Table로 심각도별 요약 + Finding 목록. 상단에 점수와 심각도별 개수 배지.

### HTML (html.py + templates/report.html.j2) — 포트폴리오의 얼굴
- 상단: 서버명, 날짜, 보안 점수(원형 게이지 느낌), 심각도별 카운트
- 각 Finding 카드: 제목, 심각도 뱃지, 현재값→권장값, why, how_to_fix, tradeoff, 근거
- 카테고리별 그룹핑, 심각도순 정렬
- 깔끔한 CSS (외부 의존 없이 인라인). 스크린샷이 포트폴리오에 잘 나오도록 디자인
- 수정 명령은 복사하기 쉽게 코드 블록으로

### JSON (json_reporter.py)
Finding 리스트를 구조화된 JSON으로. CI/CD나 다른 도구 연동용.

---

## 9. 점수 계산 (core/scoring.py)

```
시작 점수 100점
각 FAIL Finding마다 severity.weight 만큼 감점 (하한 0)
CRITICAL=40, HIGH=20, MEDIUM=10, LOW=3
점수대별 등급: 90+ A, 75+ B, 60+ C, 40+ D, else F
```
개선 전후 비교가 가능하도록 점수와 등급을 리포트에 명확히 표시.
(포트폴리오 스토리: "이 도구로 보안 점수를 X→Y로 개선")

---

## 10. 수정 기능 (remediators/) — 안전이 최우선

**절대 원칙:**
1. 수정 전 **반드시 백업** (`daemon.json.bak.<타임스탬프>`)
2. 기본은 **dry-run** (미리보기), `--apply` 플래그가 있어야 실제 수정
3. 적용 전 사용자에게 **재확인 프롬프트** (특히 "Docker 재시작 시 모든 컨테이너 재기동됨" 경고)
4. compose 파일 자동 수정은 **하지 않는다** — 서비스 의존성이 복잡해 위험. 대신 수정 예시(diff)만 제시
5. daemon.json도 네트워크 관련 설정(icc 등)은 자동 적용 시 **강력한 경고** 표시
6. 적용 후 **검증** (JSON 파싱 성공 여부 등)

수정은 daemon.json의 명백히 안전한 항목(no-new-privileges, live-restore, log-opts 등)에 한해 지원.
`icc`, `userns-remap` 같이 부작용이 큰 항목은 자동 수정 대상에서 제외하거나 별도 강경고.

---

## 11. 테스트 (tests/) — 포트폴리오 품질의 증거

- `fixtures/`에 다양한 가짜 daemon.json, docker-compose.yml 배치 (취약/안전 케이스)
- 각 룰마다 최소 2개 테스트: 취약점 있는 경우(FAIL), 없는 경우(PASS)
- 엔진 테스트: 룰 자동 등록, 실행, Finding 수집
- 점수 계산 테스트
- Docker SDK는 mock 처리 (실제 Docker 없이 테스트 가능하게)
- 목표 커버리지: 80% 이상
- `pytest`로 전부 통과해야 함

---

## 12. 개발 로드맵 (Phase별 — 이 순서로 진행)

Claude Code는 아래 Phase를 **순서대로** 완성한다. 각 Phase 끝에서 실행 가능한 상태를 유지한다.

### Phase 1 — 코어 + 프로젝트 뼈대 (실행 가능한 최소 제품)
- pyproject.toml, 디렉토리 구조, README 초안
- core/models.py, core/rule.py(자동등록), core/context.py, core/collector.py(daemon.json 읽기), core/engine.py, core/scoring.py
- daemon 룰 3개: DAEMON-001(icc), DAEMON-002(no-new-privileges), DAEMON-004(live-restore)
- reporters/terminal.py (rich)
- cli.py: `dockguard scan --category daemon`
- tests: 위 3개 룰 + 엔진
- **완료 기준**: `dockguard scan --category daemon` 실행 시 터미널에 진단 결과와 점수가 나온다

### Phase 2 — Daemon 룰 완성 + 수정 기능
- 나머지 daemon 룰 (005~010)
- remediators/daemon_remediator.py (백업/dry-run/apply)
- cli: `dockguard fix daemon --dry-run/--apply`, `dockguard rules`
- 해당 테스트

### Phase 3 — Compose 스캐너
- compose 파일 파싱 (여러 파일, 자동 탐색)
- compose 룰 001~012
- cli: `dockguard scan --compose`, 자동 탐색 통합
- 해당 테스트 + fixtures

### Phase 4 — 네트워크 + 의존성 (킬러 기능)
- collector에 컨테이너/네트워크 수집 추가 (docker SDK + CLI 폴백)
- network 룰 001~004
- config/dependencies.example.yaml
- cli: `dockguard scan --deps`
- 해당 테스트 (네트워크 정보 mock)

### Phase 5 — 리포트 고도화 + 교육 기능
- reporters/html.py + 템플릿 (포트폴리오용, 예쁘게)
- reporters/json_reporter.py
- knowledge/explanations.py + `dockguard learn`
- --explain, --output, --format 옵션 완성

### Phase 6 — 마무리 (포트폴리오 완성도)
- README 완성: 프로젝트 소개, 배경 스토리(RabbitMQ 사고), 설치법, 사용 예시, 스크린샷 자리, 아키텍처 다이어그램, 기존 도구와 차별점
- GitHub Actions CI (pytest 자동 실행)
- 데모 시나리오 문서 (docs/demo.md): 정전 후 의존성 검증 시나리오 재현
- 전체 통합 테스트, 커버리지 확인

---

## 13. 코딩 컨벤션 / 원칙

- 타입 힌트 필수 (typer/dataclass와 잘 맞음)
- 함수/클래스에 docstring (한글 가능)
- 사용자 대면 메시지는 **한글**, 코드 주석도 한글 허용
- 예외 처리: Docker 접근 실패, 파일 없음 등은 크래시 대신 친절한 안내
- 룰 추가가 쉬워야 함 — 새 룰은 파일 하나 추가로 끝나게
- 하드코딩 지양: 심각도, 포트 목록 등은 설정/상수로 분리
- 커밋은 Phase 단위로 의미 있게 (git 쓴다면)

---

## 14. 이 프로젝트가 특별한 이유 (README에 녹일 것)

기존 도구(docker-bench-security, trivy, hadolint)와의 차별점:
1. **네트워크 의존성 검증** — 서비스 간 통신 가능 여부를 선언적으로 점검 (기존 도구엔 거의 없음)
2. **부작용(tradeoff) 설명** — "이 설정을 켜면 이런 통신 문제가 생긴다"까지 알려줌
3. **통합 진단** — daemon + compose + network를 한 번에
4. **교육 기능** — `dockguard learn`으로 보안 개념 학습
5. **실무 사고 기반** — 실제 운영 장애(정전 후 네트워크 격리로 인한 서비스 중단)에서 출발

정직하게: 기존 도구들을 조사했고, 그것들이 다루지 못하는 "서비스 간 통신 검증"과
"설정 변경의 부작용 설명"에 집중해 차별화했다고 README에 명시할 것.

---

## 15. Claude Code에게 주는 시작 지시

1. 이 문서를 끝까지 읽었으면, **Phase 1부터** 시작한다.
2. Phase 1 완료 후, `dockguard scan --category daemon`이 실제로 동작하는지 직접 실행해 확인한다.
3. 각 Phase 완료 시 무엇을 만들었는지 요약하고, 다음 Phase로 넘어가도 될지 사용자에게 확인한다.
4. 막히거나 설계상 판단이 필요하면, 이 문서의 원칙(안전 우선, 확장성, 교육성)을 기준으로 결정한다.
5. 항상 실행 가능한 상태를 유지한다. 큰 변경 후에는 테스트를 돌린다.

준비되면 Phase 1을 시작하세요.
