# dockguard

**Docker 호스트 통합 보안 진단 도구** — "무엇이 위험한지"뿐 아니라 **"고치면 무엇이 깨지는지"까지** 알려줍니다.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-511%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)
![CIS](https://img.shields.io/badge/CIS%20Docker%20Benchmark-v1.6.0-orange)

```bash
dockguard scan                      # 진단 — daemon.json + 현재 폴더의 compose 파일, 점수와 취약 항목을 한눈에
dockguard scan --explain            # 왜 위험한지 · 어떻게 고치는지 · 고치면 무엇이 깨지는지
dockguard fix daemon                # 안전한 항목만 수정 미리보기 (파일은 건드리지 않음)
dockguard fix daemon --apply        # 백업 → 검증 → 적용 → 실패 시 자동 롤백
```

dockguard는 Docker 데몬 설정(`daemon.json`), docker-compose 파일, 컨테이너 네트워크 격리를 한 번에 점검하고,
각 취약점마다 **왜 위험한지 / 어떻게 고치는지 / 고치면 어떤 부작용이 있는지**를 한글로 설명하는 CLI 도구입니다.

> **개발 현황** — Phase 3 완료: daemon.json 룰 10종 + 안전한 자동 수정, docker-compose 룰 12종. 네트워크 의존성 점검은 [로드맵](#로드맵) 참고.

---

## 목차

- [왜 만들었나](#왜-만들었나)
- [기존 도구와 무엇이 다른가](#기존-도구와-무엇이-다른가)
- [설치](#설치)
- [빠른 시작](#빠른-시작)
- [명령어 레퍼런스](#명령어-레퍼런스)
- [점검 항목](#점검-항목)
- [자동 수정은 어떻게 안전한가](#자동-수정은-어떻게-안전한가)
- [보안 점수](#보안-점수)
- [아키텍처](#아키텍처)
- [새 룰 추가하기](#새-룰-추가하기)
- [설계 결정 기록](#설계-결정-기록)
- [개발과 테스트](#개발과-테스트)
- [현재 한계](#현재-한계)
- [로드맵](#로드맵)

---

## 왜 만들었나

이 도구는 실제 운영 장애에서 시작됐습니다.

RabbitMQ 보안 조치(기본 `guest` 계정 제거) 작업을 하던 중 **정전으로 서버가 재부팅**됐고, 서비스가 올라오지 않는 문제를
며칠에 걸쳐 하나씩 풀어야 했습니다.

| # | 겪은 문제 | 원인 |
|---|-----------|------|
| 1 | RabbitMQ의 계정과 큐가 전부 사라짐 | `docker compose down`으로 컨테이너를 지우면서 볼륨이 새로 만들어짐 |
| 2 | 서비스 매니저 ↔ 백엔드가 RabbitMQ에 인증 실패 | 두 서비스의 접속 비밀번호가 서로 달랐음 |
| 3 | **백엔드가 RabbitMQ에 아예 접속하지 못함** | **`daemon.json`의 `icc: false` + 커스텀 네트워크 격리** — 백엔드(기본 브리지)와 RabbitMQ(커스텀 네트워크)가 공유하는 네트워크가 없었음 |
| 4 | 네트워크를 맞춘 뒤에도 연결이 불안정 | 백엔드가 `RABBITMQ_HOST`를 호스트의 외부 IP로 잡고 있었음 |

가장 오래 걸린 건 3번이었습니다. `icc: false`는 CIS 벤치마크가 권장하는 **올바른 보안 설정**이었지만,
에러는 `Connection refused`뿐이었고 그 원인이 데몬 설정이라는 걸 알려주는 도구는 없었습니다.

기존 보안 점검 도구들은 **"이 설정을 켜라"**까지만 말해 줍니다. 하지만 운영자에게 정말 필요한 건 그다음 문장입니다.

> **"이 설정을 켜면 기본 브리지 위의 컨테이너 간 통신이 끊긴다. 백엔드↔메시지큐처럼 통신이 필요한 서비스는 반드시 같은 커스텀 네트워크에 두어라."**

dockguard는 모든 권고에 이 **부작용(tradeoff)**을 붙이고, 서비스 간 통신 가능 여부를 **선언적으로 검증**하는 것을 목표로 합니다.
위 사고에서 나온 교훈은 각 룰의 설명에 그대로 들어가 있습니다.

| 사고에서 얻은 교훈 | dockguard에 반영된 곳 |
|--------------------|------------------------|
| 보안 설정이 서비스 통신을 끊을 수 있다 | DAEMON-001(icc) 부작용 설명, 자동 수정 시 **강경고 + 이중 확인** |
| 재부팅 후 네트워크 분리를 빨리 찾아야 한다 | NET-001 서비스 의존성 통신 검증 *(Phase 4)* |
| `compose down`은 익명 볼륨 데이터를 잃게 한다 | 재생성 안내를 `up -d --force-recreate`로 통일, named volume 권고 |
| 서비스마다 비밀번호를 따로 적어 두면 한쪽만 바뀐다 | COMPOSE-005 평문 시크릿 점검 — 한 곳(.env / secrets)에서 관리하도록 안내 |
| live-restore는 정전(호스트 재부팅)을 막아 주지 않는다 | DAEMON-004 부작용에 명시, `restart:` 정책 안내 |
| 호스트 외부 IP로 컨테이너끼리 접속하면 불안정하다 | DAEMON-001/003 부작용에 서비스 이름 접속 권고 |
| RabbitMQ 포트가 0.0.0.0에 열려 guest로 접속당했다 | NET-004 외부 노출 포트 점검 *(Phase 4)*, DAEMON-009의 UFW 우회 경고 |

---

## 기존 도구와 무엇이 다른가

dockguard를 만들기 전에 널리 쓰이는 도구들을 먼저 살펴봤습니다. 각 도구는 자기 영역에서 훌륭하지만,
**"서비스 간 통신 검증"**과 **"설정 변경의 부작용 설명"**을 다루는 도구는 찾지 못했습니다. dockguard는 이 두 가지에 집중합니다.

| | docker-bench-security | trivy | hadolint | **dockguard** |
|---|:---:|:---:|:---:|:---:|
| 주 용도 | CIS 벤치마크 전 항목 점검 | 이미지 취약점(CVE) · IaC 스캔 | Dockerfile 린트 | Docker 호스트 통합 진단 |
| daemon.json 점검 | ✅ | — | — | ✅ |
| docker-compose 파일 점검 | 실행 중 컨테이너 기준 | — | — | ✅ |
| **서비스 간 통신 가능 여부 검증** | — | — | — | ✅ *(Phase 4)* |
| **수정 시 부작용(tradeoff) 설명** | — | — | — | ✅ |
| 안전한 자동 수정 (백업 · 검증 · 롤백) | — | — | — | ✅ |
| 한글 보안 학습 콘텐츠 | — | — | — | ✅ |

> 각 도구의 주 용도를 기준으로 비교했습니다. dockguard는 이 도구들을 **대체하지 않고 보완**합니다.
> 이미지 CVE 스캔은 trivy, Dockerfile 품질은 hadolint, CIS 전 항목 감사는 docker-bench-security를 함께 쓰는 것을 권장합니다.

---

## 설치

**요구 사항**: Python 3.10 이상. 점검 대상은 Linux Docker 호스트이며, macOS · Windows(Docker Desktop)에서도 동작합니다.

```bash
git clone https://github.com/taeyangkim4875-byte/dockguard.git
cd dockguard

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

pip install -e .                     # 사용만 할 경우
pip install -e ".[dev]"              # 테스트까지 돌릴 경우
```

설치하면 `dockguard` 명령이 등록됩니다. `python -m dockguard`로도 실행할 수 있습니다.

> `/etc/docker/daemon.json`은 보통 누구나 읽을 수 있어서 `scan`에는 sudo가 필요 없습니다.
> `fix --apply`로 파일을 수정할 때는 sudo가 필요합니다: `sudo .venv/bin/dockguard fix daemon --apply`

---

## 빠른 시작

### 1. 진단

```bash
dockguard scan --category daemon
```

`daemon.json`은 플랫폼별 표준 위치에서 자동으로 찾습니다.

| 플랫폼 | 탐색 순서 |
|--------|-----------|
| Linux | `/etc/docker/daemon.json` → `~/.config/docker/daemon.json` (rootless) |
| macOS | `~/.docker/daemon.json` (Docker Desktop) |
| Windows | `%USERPROFILE%\.docker\daemon.json` (Docker Desktop) → `%ProgramData%\docker\config\daemon.json` |

**파일이 없어도 "안전"으로 판정하지 않습니다.** Docker는 `daemon.json`이 없으면 모든 항목을 기본값으로 동작하는데,
`icc`의 기본값은 `true`, `no-new-privileges`는 `false`처럼 기본값 대부분이 보안 권고와 반대이기 때문입니다.
dockguard는 이 경우 **Docker 기본값을 기준으로** 점검합니다.

아래는 취약한 설정 예시(`tests/fixtures/daemon/insecure.json`)를 점검한 실제 출력입니다 (터미널에서는 심각도별 색상으로 표시됩니다).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  전체 점수: 0/100    등급 F                                                 │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                                             │
│                                                                             │
│   CRITICAL 0   HIGH 4   MEDIUM 3   LOW 2                                    │
│  통과 0 · 취약 9 · 주의 0 · 건너뜀 1   (룰 10개 실행)                        │
└─────────────────────────────────────────────────────────────────────────────┘
 심각도   ID           제목                          상태   현재값
 ─────────────────────────────────────────────────────────────────────────────
 HIGH     DAEMON-002   no-new-privileges 기본 활성화  취약   false
 HIGH     DAEMON-006   user namespace remapping       취약   미설정 (컨테이너 root = 호스트 root)
 HIGH     DAEMON-008   기본 seccomp 프로파일 유지      취약   "unconfined" — 모든 컨테이너의 seccomp 보호 해제
 HIGH     DAEMON-010   insecure-registry 미사용        취약   insecure-registries ["10.0.0.5:5000"], HTTP 미러 [...]
 MEDIUM   DAEMON-001   ICC(컨테이너 간 통신) 제한      취약   true
 MEDIUM   DAEMON-003   userland-proxy 비활성화         취약   true
 MEDIUM   DAEMON-009   iptables 관리 활성화            취약   false
 LOW      DAEMON-004   live-restore 활성화             취약   false
 LOW      DAEMON-005   로그 드라이버 / 크기 제한       취약   json-file, max-size 미설정 (로그 무제한 증가)

  TIP 각 항목의 위험 이유 · 수정 방법 · 부작용은 --explain 옵션으로 확인하세요.
```

### 2. 상세 설명 보기

```bash
dockguard scan --category daemon --explain
```

취약 항목마다 네 가지를 보여줍니다.

- **■ 왜 위험한가** — 개념과 공격 시나리오 (예: 측면 이동, 컨테이너 탈출)
- **■ 어떻게 고치나** — 복사해서 바로 쓸 수 있는 설정과 명령
- **■ 부작용 / 주의사항** — 고쳤을 때 깨질 수 있는 것과 대비책 ← **dockguard의 핵심**
- **근거 / 참고** — CIS Docker Benchmark 항목 번호와 Docker 공식 문서

<details>
<summary><b>예시: DAEMON-001(icc)의 부작용 설명</b></summary>

> **`icc: false`는 기본 브리지 위의 모든 컨테이너 간 통신을 끊는다.** 백엔드↔메시지큐, 앱↔DB처럼 서로 통신해야 하는 서비스가
> 기본 브리지에 있었다면, 데몬 재시작 직후부터 연결이 실패한다. 에러는 보통 `Connection refused`나 타임아웃으로만 나타나서,
> 원인이 데몬 설정이라는 걸 떠올리기 어렵다.
>
> - 통신이 필요한 서비스는 **반드시 같은 커스텀 네트워크**에 두어야 한다. 커스텀 브리지 네트워크 안에서는 `icc` 설정과
>   무관하게 통신이 허용되고, 컨테이너 이름으로 DNS 조회도 된다.
> - 한 서비스는 기본 브리지에, 다른 서비스는 커스텀 네트워크에 있으면 두 컨테이너는 **공유하는 네트워크가 없어** 통신할 수 없다.
> - `docker network connect`로 임시 연결한 것은 컨테이너를 재생성하면 풀린다. compose 파일의 `networks:`에 영구 반영해야 한다.
> - 컨테이너끼리 호스트의 외부 IP로 접속하는 방식(예: `RABBITMQ_HOST=<서버 IP>`)은 재기동 후 갑자기 끊길 수 있다.
>   같은 네트워크에 두고 서비스 이름(`rabbitmq`)으로 접속하는 것이 안전하다.

</details>

### 3. 안전하게 수정하기

```bash
dockguard fix daemon                 # 미리보기(dry-run) — 기본 동작, 파일은 건드리지 않음
```

```
 ID           제목                          변경 내용                              반영     위험도
 ─────────────────────────────────────────────────────────────────────────────────────────────
 DAEMON-002   no-new-privileges 기본 활성화  "no-new-privileges": true              재시작   안전
 DAEMON-004   live-restore 활성화            "live-restore": true                   리로드   안전
 DAEMON-005   로그 드라이버 / 크기 제한      "log-opts": {"max-file": "3", ...}     재시작   안전

변경 미리보기 (diff)
 --- daemon.json (현재)
 +++ daemon.json (수정 후)
 @@ -1,11 +1,15 @@
  {
    "icc": true,
 -  "no-new-privileges": false,
 -  "live-restore": false,
 +  "no-new-privileges": true,
 +  "live-restore": true,
    "userland-proxy": true,
    ...
 +  "log-opts": {
 +    "max-file": "3",
 +    "max-size": "10m"
 +  }
  }

수동 조치 필요 (자동 수정 대상 아님)
 DAEMON-006   user namespace remapping   켜는 순간 Docker가 별도 데이터 디렉터리를 사용해 기존 이미지·컨테이너·
                                         볼륨이 보이지 않게 되고, 바인드 마운트 권한 문제가 생깁니다. ...
 DAEMON-001   ICC(컨테이너 간 통신) 제한  부작용이 커서 기본 수정 대상에서 제외했습니다. 영향을 확인했다면
                                         `--rule DAEMON-001`로 명시해 포함할 수 있습니다.

  미리보기입니다. 파일은 변경되지 않았습니다. 적용하려면: dockguard fix daemon --apply
```

미리보기를 확인했으면 적용합니다. 적용 전에 재시작 영향을 경고하고 **y/N 확인**을 받습니다.

```bash
sudo dockguard fix daemon --apply
```

적용 후에는 백업 경로, 검증 결과, 그리고 **지금 상태에 맞는 다음 단계**를 안내합니다.

```
╭──────────────────────────────────────────────────────────╮
│ 수정 완료  /etc/docker/daemon.json                       │
│ 백업      /etc/docker/daemon.json.bak.20260915-103000    │
│ 검증      dockerd --validate 통과                        │
╰──────────────────────────────────────────────────────────╯
다음 단계
  • 1) live-restore를 먼저 활성화 (리로드, 컨테이너 영향 없음)
      sudo systemctl reload docker
  • 2) 데몬 재시작 — live-restore 덕분에 실행 중인 컨테이너는 유지됩니다
      sudo systemctl restart docker
  • 기존 컨테이너에 새 기본값 반영 (named volume이 아닌 데이터는 사라질 수 있으니 `down`은 쓰지 마세요)
      docker compose up -d --force-recreate
  • 결과 확인
      dockguard scan --category daemon
  • 문제가 생기면 원래대로 되돌리기 (이후 Docker 재시작)
      sudo cp /etc/docker/daemon.json.bak.20260915-103000 /etc/docker/daemon.json
```

> **리로드 → 재시작 순서를 안내하는 이유**: `live-restore`는 리로드(SIGHUP)만으로 켜집니다. 먼저 리로드로 live-restore를 켠 뒤
> 재시작하면, 나머지 설정을 반영하는 재시작에서도 **실행 중인 컨테이너가 유지**됩니다.
> dockguard는 수정 계획을 보고 이 순서를 자동으로 판단해 안내합니다.

### 4. docker-compose 파일 점검

```bash
dockguard scan -c compose                        # 현재 폴더와 하위 3단계에서 compose 파일 자동 탐색
dockguard scan -f ./docker-compose.yml           # 파일 지정 (docker compose -f 와 같은 의미)
dockguard scan -f ./deploy -f ./infra            # 폴더 지정 — 그 안을 탐색, 여러 번 지정 가능
```

- 한 폴더에서는 `docker compose`와 같은 우선순위(`compose.yaml` > `compose.yml` > `docker-compose.yaml` > `docker-compose.yml`)로 파일 하나만 봅니다.
- 자동 탐색 · 폴더 지정 시에는 같은 폴더의 `*.override.yml`을 **병합해서** 판단합니다. override에만 `user:`를 넣어 둔 경우를 취약으로 잘못 판정하지 않기 위해서입니다. 파일을 직접 지정하면 `docker compose -f`처럼 그 파일만 봅니다.
- `node_modules`, `.git`, `.venv` 같은 폴더는 탐색하지 않습니다.

compose 룰은 **파일(프로젝트) 하나당 룰 하나의 결과**로 묶고, 영향받는 서비스를 나열합니다.

```
 심각도     ID            제목                          상태   현재값
 ────────────────────────────────────────────────────────────────────────────────────────────────────
 CRITICAL   COMPOSE-001   privileged 모드 사용 금지     취약   1/2개 서비스 — backend: privileged: true
 CRITICAL   COMPOSE-004   docker.sock 마운트 금지       취약   1/2개 서비스 — backend: /var/run/docker.sock 마운트
                                                                (읽기 전용이어도 API 호출 가능)
 HIGH       COMPOSE-002   non-root 사용자로 실행        취약   2/2개 서비스 — backend, rabbitmq: user 미지정 (이미지 기본값, 대개 root)
 HIGH       COMPOSE-005   평문 시크릿 금지              취약   2/2개 서비스 — backend: RABBITMQ_PASSWORD (평문 값);
                                                                backend: JWT_SECRET (기본값에 평문); rabbitmq: RABBITMQ_DEFAULT_PASS (평문 값)
 HIGH       COMPOSE-010   위험한 capability 추가 금지   취약   1/2개 서비스 — backend: cap_add SYS_ADMIN, NET_ADMIN
 MEDIUM     COMPOSE-008   호스트 네트워크 모드 검토     주의   1/2개 서비스 — backend: network_mode: host — 필요성 검토
 ...
```

compose 파일은 **자동으로 수정하지 않습니다.** 대신 `--explain`에서 **영향받는 서비스 이름을 넣은 수정 예시**를 보여줍니다.
시크릿 값은 리포트 어디에도 출력하지 않고 변수 이름만 보여줍니다.

```yaml
# dockguard scan -c compose --explain 의 COMPOSE-005 수정 예시
services:
  backend:
    environment:
      RABBITMQ_PASSWORD: ${RABBITMQ_PASSWORD}
      JWT_SECRET: ${JWT_SECRET}
  rabbitmq:
    environment:
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_DEFAULT_PASS}

# .env (chmod 600, .gitignore에 추가) — 값은 여기에만
# RABBITMQ_PASSWORD=...
```

### 5. 룰 목록 보기

```bash
dockguard rules
```

---

## 명령어 레퍼런스

### `dockguard scan`

| 옵션 | 설명 |
|------|------|
| `-c`, `--category [daemon\|compose\|network]` | 점검할 영역. 여러 번 지정 가능. 기본: 전체 |
| `--daemon-config PATH` | `daemon.json` 경로 직접 지정. 기본: 자동 탐색 |
| `-f`, `--compose PATH` | compose 파일 또는 폴더. 여러 번 지정 가능. 지정하면 compose 영역이 자동으로 포함됨. 기본: 현재 폴더 자동 탐색 |
| `-e`, `--explain` | 취약 항목마다 위험 이유 · 수정 방법 · 부작용 · 근거를 상세 표시 |

### `dockguard fix daemon`

| 옵션 | 설명 |
|------|------|
| `--dry-run` / `--apply` | 기본은 `--dry-run`(미리보기). `--apply`를 붙여야 백업 후 실제로 수정 |
| `-r`, `--rule ID` | 수정할 룰만 선택. 여러 번 지정 가능. **부작용이 큰 항목(예: DAEMON-001)은 여기 명시해야만 포함** |
| `--daemon-config PATH` | `daemon.json` 경로 직접 지정 |

종료 코드: `0` 성공 · `1` 사용자가 취소했거나 적용 실패 · `2` 잘못된 입력(없는 파일, 알 수 없는 룰 ID, 파싱 불가한 JSON)

### `dockguard fix compose`

compose 파일을 자동 수정하지 않는 이유와, 수정 예시를 보는 방법(`scan -c compose --explain`)을 안내합니다.

### `dockguard rules`

등록된 모든 룰의 ID · 영역 · 심각도 · 자동 수정 지원 여부 · 근거를 표로 보여줍니다. `-c`로 영역을 거를 수 있습니다.

### `dockguard --version`

---

## 점검 항목

모든 근거는 **CIS Docker Benchmark v1.6.0** 번호로 통일했습니다 ([docker-bench-security](https://github.com/docker/docker-bench-security)와 같은 기준).

### Daemon — `daemon.json` (10종, 구현 완료)

| ID | 점검 내용 | 권장 | 심각도 | 근거 | 자동 수정 |
|----|-----------|------|:------:|------|:---------:|
| DAEMON-001 | ICC(컨테이너 간 통신) 제한 | `"icc": false` | MEDIUM | CIS 2.2 | ⚠️ 명시 시 (강경고) |
| DAEMON-002 | no-new-privileges 기본 활성화 | `"no-new-privileges": true` | HIGH | CIS 2.14 | ✅ |
| DAEMON-003 | userland-proxy 비활성화 | `"userland-proxy": false` | MEDIUM | CIS 2.16 | — |
| DAEMON-004 | live-restore 활성화 | `"live-restore": true` | LOW | CIS 2.15 | ✅ |
| DAEMON-005 | 로그 드라이버 / 크기 제한 | `max-size` 설정 또는 local/원격 드라이버 | LOW | CIS 2.13 (연관) | ✅ |
| DAEMON-006 | user namespace remapping | `"userns-remap": "default"` 또는 rootless | HIGH | CIS 2.9 | — |
| DAEMON-007 | daemon.json 파일 권한 | `root:root`, `0644` 이하 | MEDIUM | CIS 3.17 / 3.18 | — |
| DAEMON-008 | 기본 seccomp 프로파일 유지 | `seccomp-profile`을 `unconfined`로 두지 않음 | HIGH | CIS 5.22 / 2.17 | — |
| DAEMON-009 | iptables 관리 활성화 | `"iptables": true` (기본값) | MEDIUM | CIS 2.4 | — |
| DAEMON-010 | insecure-registry 미사용 | `insecure-registries` 비움, 미러는 https | HIGH | CIS 2.5 | — |

<details>
<summary><b>룰별 판정 로직 자세히 보기</b></summary>

- **공통** — 키가 없으면 Docker 기본값으로 판정합니다. `"false"`(문자열)처럼 타입이 잘못된 값은 dockerd가 시작에 실패할 수 있어 **주의(WARN)**로 표시합니다. JSON 파싱에 실패하면 몇 행 몇 열이 문제인지 알려주고 해당 룰은 건너뜁니다.
- **DAEMON-005 로그** — `json-file`(기본값)이면 `max-size`가 있어야 통과합니다(`max-file`만으로는 크기가 제한되지 않음). `local`은 내장 로테이션이 있어 통과, `journald` · `syslog` · `fluentd` 같은 원격 드라이버도 통과, `none`은 사고 조사가 불가능해 주의로 표시합니다.
- **DAEMON-006 userns** — rootless 모드 설정 파일(`~/.config/docker/daemon.json`)이면 이미 사용자 네임스페이스로 격리된 상태라 통과로 봅니다.
- **DAEMON-007 파일 권한** — 내용이 깨져 있어도 권한은 점검합니다. rootless · Docker Desktop처럼 홈 디렉터리 아래의 설정 파일은 사용자 소유가 정상이므로 소유자 대신 쓰기 권한만 봅니다. Windows에서는 POSIX 권한이 없어 건너뜁니다.
- **DAEMON-008 seccomp** — `unconfined`(대소문자 무관)는 취약, `builtin`/미설정은 통과, 커스텀 프로파일은 파일이 실제로 있는지까지 확인합니다(없으면 데몬 기동 실패 위험으로 주의).
- **DAEMON-009 iptables** — `iptables: false`면 `icc: false` 차단 규칙도 생성되지 않는다는 **룰 간 상호작용**을 설명합니다. 켜 둘 때는 Docker 규칙이 **UFW보다 먼저 적용되어 공개 포트가 방화벽을 우회**한다는 함정도 함께 알려줍니다.
- **DAEMON-010 레지스트리** — `localhost` · `127.0.0.0/8` · `::1`은 Docker가 원래 insecure로 허용하므로 제외하고, `registry-mirrors`의 `http://` 주소도 같은 위험으로 봅니다.

</details>

### Compose — docker-compose 파일 (12종, 구현 완료)

| ID | 점검 내용 | 판정 기준 | 심각도 | 근거 |
|----|-----------|-----------|:------:|------|
| COMPOSE-001 | privileged 모드 사용 금지 | `privileged: true` | CRITICAL | CIS 5.5 |
| COMPOSE-002 | non-root 사용자로 실행 | `user:` 미지정 또는 root | HIGH | CIS 4.1 |
| COMPOSE-003 | no-new-privileges 설정 | `security_opt`에 없음 (데몬 기본값 켜져 있으면 통과) | MEDIUM | CIS 5.26 |
| COMPOSE-004 | **docker.sock 마운트 금지** | volumes에 `docker.sock` (`:ro`여도 취약) | CRITICAL | CIS 5.32 |
| COMPOSE-005 | **평문 시크릿 금지** | PASSWORD · SECRET · TOKEN · API_KEY 등에 값이 직접 적힘 | HIGH | 베스트 프랙티스 |
| COMPOSE-006 | 읽기 전용 루트 파일시스템 | `read_only: true` 없음 | LOW | CIS 5.13 |
| COMPOSE-007 | 리소스(CPU/메모리) 제한 | 메모리 제한 없음 → 취약, CPU만 없음 → 주의 | MEDIUM | CIS 5.11 / 5.12 |
| COMPOSE-008 | 호스트 네트워크 모드 검토 | `network_mode: host` → **주의** (정당한 사용처가 많음) | MEDIUM | CIS 5.10 |
| COMPOSE-009 | 호스트 PID/IPC 공유 금지 | `pid: host`, `ipc: host` | HIGH | CIS 5.16 / 5.17 |
| COMPOSE-010 | 위험한 capability 추가 금지 | `cap_add`에 SYS_ADMIN · SYS_MODULE · SYS_PTRACE · NET_ADMIN · ALL 등 | HIGH | CIS 5.4 |
| COMPOSE-011 | latest 태그 금지 | 태그 없음 또는 `:latest` (다이제스트 고정은 통과) | LOW | 베스트 프랙티스 |
| COMPOSE-012 | 특권 포트 매핑 검토 | 호스트 포트 1024 미만 → **주의** (80/443 제외) | LOW | CIS 5.8 |

<details>
<summary><b>오탐을 줄이기 위한 판정 로직 자세히 보기</b></summary>

- **룰 간 교차 확인** — compose 점검 시에도 `daemon.json`을 함께 읽습니다. 데몬 기본값으로 `no-new-privileges`가 켜져 있으면 COMPOSE-003을 통과로 보고, `userns-remap`이 켜져 있으면 COMPOSE-002를 취약이 아닌 주의로 낮춥니다(컨테이너 root가 호스트 root가 아니므로). 반대로 서비스에서 `no-new-privileges:false`로 명시적으로 끈 경우는 데몬 기본값과 무관하게 취약입니다.
- **COMPOSE-002** — `build:`를 쓰는 서비스는 로컬 Dockerfile을 읽어 **마지막 스테이지의 `USER`**를 확인합니다(멀티 스테이지에서 `FROM`마다 초기화). postgres · mysql · mariadb · redis · mongo 공식 이미지는 엔트리포인트에서 스스로 권한을 내리므로(gosu) 주의로만 표시합니다. `bitnami/postgresql` 같은 비공식 이미지는 해당하지 않습니다.
- **COMPOSE-005** — `${VAR}` · `$VAR` · `${VAR:?에러}` 참조와 `/run/secrets/...` 경로, `*_FILE` 변수는 안전으로 봅니다. 반대로 `${VAR:-기본값}`의 **기본값**은 평문으로 판정하고, `$$`(리터럴 `$` 이스케이프)는 변수 참조가 아니므로 평문입니다. `PASSWORD_MIN_LENGTH`, `TOKEN_URL`, `JWT_TOKEN_TTL`, `PWD`처럼 시크릿 *관련 설정*은 제외합니다.
- **COMPOSE-011** — `registry.internal:5000/app`의 콜론은 포트이지 태그가 아닙니다. `app:${TAG}`는 배포 시 값에 달려 있어 통과, `${TAG:-latest}`처럼 기본값이 latest면 취약입니다.
- **COMPOSE-012** — 컨테이너 포트가 아니라 **호스트 포트**가 기준입니다(`8080:80`은 통과). 짧은 문법(`127.0.0.1:53:53/udp`, `[::1]:8080:80`, 범위)과 긴 문법(`published:`)을 모두 해석합니다.

</details>

### Network — 네트워크 격리와 서비스 의존성 (4종, Phase 4 예정)

| ID | 점검 내용 |
|----|-----------|
| **NET-001** | **서비스 의존성 통신 검증** — `dependencies.yaml`에 선언한 A→B 통신이 실제로 가능한지(같은 네트워크 공유 여부) |
| NET-002 | 어떤 커스텀 네트워크에도 붙지 않은 컨테이너 |
| NET-003 | 커스텀 네트워크 대신 기본 bridge 사용 |
| NET-004 | `0.0.0.0`으로 바인딩된 민감 포트 (5672, 15672, 3306, 6379, 27017 …) |

```yaml
# config/dependencies.yaml — "정전 후 재기동했더니 backend → rabbitmq 통신 불가"를 즉시 발견하기 위한 선언
dependencies:
  - from: "backend-container"
    to: "rabbitmq"
    port: 5672
    reason: "백엔드가 RabbitMQ 큐를 소비"
```

---

## 자동 수정은 어떻게 안전한가

설정 파일을 자동으로 고치는 기능은 편리한 만큼 위험합니다. dockguard는 다음 원칙을 **코드 구조로** 강제합니다.

```mermaid
flowchart TD
    A["룰: 수정 계획(ConfigPatch)만 선언"] --> B["수정 계획 + diff 미리보기 (dry-run, 기본)"]
    B -->|"--apply + y/N 확인"| C["임시 파일에 새 내용 쓰기"]
    C --> D{"JSON 검증 + dockerd --validate"}
    D -- 실패 --> X["중단 — 원본은 전혀 변경되지 않음"]
    D -- 통과 --> E["원본 백업 daemon.json.bak.시각"]
    E --> F["원자적 교체 (os.replace)"]
    F --> G{"다시 읽어서 계획과 일치하는지 검증"}
    G -- 불일치 --> H["백업으로 자동 롤백"]
    G -- 일치 --> I["다음 단계 안내 (리로드/재시작 순서, 롤백 명령)"]
```

1. **룰은 파일을 직접 고치지 못합니다.** 룰은 "무엇을 바꿀지"(`ConfigPatch`)만 반환하고, 파일 I/O · 백업 · 검증 · 롤백은
   `DaemonRemediator` 한 곳에서만 합니다. 그래서 새 룰을 추가해도 안전 절차를 건너뛸 수 없습니다.
2. **기본은 dry-run입니다.** `--apply`가 없으면 파일에 쓰는 코드 경로 자체를 타지 않습니다.
3. **적용 전에 반드시 확인을 받습니다.** 재시작하면 컨테이너가 재기동된다는 경고를 먼저 보여줍니다.
4. **부작용 등급을 나눕니다.**
   - `안전` — no-new-privileges, live-restore, 로그 로테이션: 기본 수정 대상
   - `주의` — icc: `--rule DAEMON-001`로 **명시해야만** 포함되고, 빨간 경고 패널과 **이중 확인**을 거칩니다
   - `미지원` — userns-remap(데이터 디렉터리 전환), seccomp, 레지스트리 등: 이유와 수동 조치 방법만 안내합니다
5. **원본 형식을 존중합니다.** 기존 키 순서와 들여쓰기(2칸/4칸/탭)를 유지하고, 짧은 배열은 한 줄로 두어 diff에 **실제 변경분만** 나타나게 합니다.
   이미 설정해 둔 `log-opts`의 `max-file` 같은 값은 덮어쓰지 않습니다.
6. **원본 권한을 유지합니다.** 새 파일에 원본의 권한과 소유자를 복사해서, 수정 때문에 DAEMON-007(파일 권한)이 깨지지 않게 합니다.
7. **Docker를 직접 재시작하지 않습니다.** 재시작 시점은 운영자가 정해야 하므로, dockguard는 필요한 명령과 순서만 안내합니다.
8. **compose 파일은 자동 수정하지 않습니다.** 네트워크 · 볼륨 소유권 · 기동 순서가 얽혀 있어 한 줄만 바꿔도 다른 서비스가
   끊길 수 있기 때문입니다. 대신 영향받는 서비스 이름을 넣은 수정 예시 YAML을 보여줍니다 (`dockguard fix compose` 참고).

---

## 보안 점수

```
시작 점수 100점
취약(FAIL) 항목마다 심각도만큼 감점 (하한 0)
  CRITICAL 40 · HIGH 20 · MEDIUM 10 · LOW 3 · INFO 0
등급  A: 90 이상 · B: 75 이상 · C: 60 이상 · D: 40 이상 · F: 그 외
```

주의(WARN) · 건너뜀(SKIP)은 감점하지 않습니다. 점수와 등급은 리포트 상단에 게이지와 함께 표시되며,
수정 전후 점수를 비교해 개선 효과를 확인할 수 있습니다.

---

## 아키텍처

```mermaid
flowchart LR
    CLI["CLI<br/>scan · fix · rules"] --> COL["Collector<br/>daemon.json · compose · network"]
    COL --> CTX[("ScanContext")]
    REG[["rules/**<br/>@register 자동 등록"]] --> ENG
    CTX --> ENG["Engine<br/>Rule.check() × N<br/>예외 격리"]
    ENG --> FND["Finding 목록"]
    FND --> SC["Scoring<br/>점수 · 등급"]
    FND --> REP["Reporter<br/>터미널 · HTML · JSON"]
    SC --> REP
    FND -.->|"fix"| REM["Remediator<br/>백업 · 검증 · 롤백"]
```

- **Collector**는 수집 실패를 예외로 터뜨리지 않고 `ScanContext`에 사유를 기록합니다. "권한이 없어서 못 읽었다"도 사용자에게 유용한 진단 결과이기 때문입니다.
- **룰은 `ScanContext`만 봅니다.** Docker나 파일 시스템에 직접 접근하지 않으므로, 실제 Docker 없이 가짜 컨텍스트로 모든 룰을 테스트할 수 있습니다.
- **Engine**은 룰 하나에서 예외가 나도 나머지 룰을 계속 실행하고, 오류는 리포트에 따로 표시합니다.
- **Reporter**는 `Finding` 모델만 보고 출력을 만듭니다. 출력 형식을 추가해도 룰은 바뀌지 않습니다.

```
dockguard/
├── cli.py                     # typer CLI (scan · fix · rules)
├── core/
│   ├── models.py              # Finding · Severity · Status · ConfigPatch · FixRisk
│   ├── rule.py                # Rule 베이스 + @register 레지스트리
│   ├── context.py             # ScanContext · DaemonConfig
│   ├── collector.py           # 수집 오케스트레이션 · daemon.json (플랫폼별 탐색, rootless 감지, 파일 권한)
│   ├── compose_loader.py      # compose 탐색 · YAML 파싱 · override 병합
│   ├── engine.py              # 룰 실행 (카테고리 필터, 예외 격리)
│   └── scoring.py             # 점수 · 등급
├── rules/
│   ├── __init__.py            # 하위 모듈 재귀 자동 import
│   ├── daemon/                # DAEMON-001 ~ 010 (+ _base.py 공통 베이스)
│   ├── compose/               # COMPOSE-001 ~ 012 (+ _base.py: 서비스 순회, 포트/볼륨/이미지 파서)
│   └── network/               # (Phase 4)
├── remediators/
│   └── daemon_remediator.py   # 계획 · diff · 백업 · 검증 · 롤백 · 다음 단계 안내
├── reporters/
│   ├── terminal.py            # rich 리포트 (점수 게이지, --explain)
│   └── remediation.py         # fix / rules 화면
└── knowledge/
    ├── references.py          # CIS 근거 표기 (v1.6.0 기준)
    └── compose_facts.py       # 위험 capability, 시크릿 이름 규칙 등 보안 지식 상수
```

---

## 새 룰 추가하기

**파일 하나만 추가하면 됩니다.** 등록 코드를 따로 고칠 필요가 없습니다.

`daemon.json`의 불리언 키 하나를 보는 룰이라면 `BooleanDaemonRule`을 상속해서 선언만 하면 됩니다.

```python
# dockguard/rules/daemon/experimental.py
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import BooleanDaemonRule


@register
class ExperimentalRule(BooleanDaemonRule):
    id = "DAEMON-011"
    title = "실험 기능 비활성화"
    severity = Severity.LOW
    reference = cis("2.18", "Ensure that experimental features are not implemented in production")

    key = "experimental"
    recommended_value = False
    docker_default = False

    why = "..."          # 왜 위험한가 — 개념과 공격 시나리오
    how_to_fix = "..."   # 어떻게 고치나 — 복사 가능한 설정/명령 (Markdown)
    tradeoff = "..."     # 고치면 무엇이 깨지는가 — 반드시 채울 것
    learn_more = "https://docs.docker.com/..."
```

더 복잡한 판정이 필요하면 `DaemonRule`을 상속해 `evaluate(daemon)`을 구현합니다 (예: `log_limit.py`, `insecure_registry.py`).

compose 룰은 `ComposeRule`을 상속해 **서비스 하나를 보는 함수**만 구현하면 됩니다. 프로젝트 순회, 서비스별 결과 묶기,
수정 예시 붙이기는 베이스가 처리합니다.

```python
@register
class HealthcheckRule(ComposeRule):
    id = "COMPOSE-013"
    title = "헬스체크 설정"
    severity = Severity.LOW
    reference = cis("5.27", "Ensure that container health is checked at runtime")

    def check_service(self, name, service, project, context):
        if "healthcheck" in service:
            return []
        return [ServiceIssue(name, "healthcheck 없음")]

    def fix_example(self, issues):  # 선택: 영향받는 서비스 이름을 넣은 수정 예시
        return yaml_snippet({i.service: ["healthcheck:", "  test: [CMD, curl, -f, http://localhost/health]"] for i in issues})
```
자동 수정을 지원하려면 `fix_risk`를 지정하고 `plan_fix()`에서 `ConfigPatch`를 반환하면 됩니다. 백업 · 검증 · 롤백은 자동으로 적용됩니다.

`tests/test_daemon_rules.py`의 공통 테스트가 **새 룰의 설명 필드(why · how_to_fix · tradeoff · 근거)가 충분히 채워졌는지**까지 검사합니다.

---

## 설계 결정 기록

| 결정 | 이유 |
|------|------|
| `daemon.json`이 없으면 Docker 기본값으로 판정 | 파일이 없는 호스트가 가장 흔하고, 그 상태의 기본값 대부분이 취약합니다. "파일 없음 = 통과"는 거짓 안심을 줍니다. |
| 룰은 `ConfigPatch`만 선언, 파일 I/O는 Remediator 전담 | 룰이 늘어나도 백업 · 검증 · 롤백을 우회하는 경로가 생기지 않습니다. 계획이 순수 데이터라 테스트도 쉽습니다. |
| 임시 파일 검증 → 백업 → `os.replace` | 검증에 실패하면 원본을 전혀 건드리지 않은 상태로 끝나고, 교체는 원자적이라 중간에 끊겨도 파일이 반쯤 쓰인 상태가 되지 않습니다. |
| Docker를 직접 재시작하지 않음 | 재시작은 모든 컨테이너에 영향을 줄 수 있습니다. 시점 판단은 운영자 몫이고, 도구는 올바른 순서를 안내합니다. |
| CIS 근거를 v1.6.0 번호로 통일 | CIS 벤치마크는 버전마다 항목 번호가 바뀝니다(icc: 이전 버전의 2.1 → v1.6.0의 2.2). 교육용 도구의 근거는 검증 가능해야 합니다. |
| 잘못된 타입은 FAIL이 아닌 WARN | `"icc": "false"`는 취약하다기보다 **dockerd가 시작되지 않을 수 있는** 설정 오류입니다. 성격이 달라 따로 표시합니다. |
| 설명 텍스트를 Markdown으로 작성 | 터미널(rich)과 HTML 리포트(Phase 5)에서 같은 원문을 렌더링하고, 코드 블록을 복사하기 쉽게 보여줄 수 있습니다. |
| compose 결과는 "파일 × 룰" 단위로 묶음 | 서비스 10개에 `read_only`가 없다고 감점이 10번 되면 점수가 의미를 잃습니다. 룰 단위로 한 번 감점하고 영향받는 서비스는 목록으로 보여줍니다. |
| host 네트워크 · 특권 포트는 '취약'이 아닌 '주의' | 성능 · 멀티캐스트 · 웹 표준 포트처럼 정당한 사용처가 많습니다. 금지가 아니라 검토를 요청하는 것이 실무에 맞습니다. |
| override 병합은 `docker compose` 규칙을 따름 | 자동 탐색에서는 override를 병합하고, `-f`로 파일을 지정하면 병합하지 않습니다. 실제 배포 동작과 판정이 어긋나지 않게 하기 위해서입니다. |
| 시크릿 값은 절대 출력하지 않음 | 보안 점검 리포트가 새로운 유출 경로가 되면 안 됩니다. 변수 이름만 보여주고, 테스트로 값이 출력되지 않음을 검증합니다. |

---

## 개발과 테스트

```bash
pip install -e ".[dev]"
pytest                                        # 전체 테스트
pytest --cov=dockguard --cov-report=term-missing
```

- **테스트 511개, 커버리지 98%** — 실제 Docker 없이 실행됩니다.
- 각 룰마다 **통과 · 취약 · 파일 없음(기본값) · 파싱 실패 · 잘못된 타입** 케이스를 공통 테스트로 검사하고, 룰별 경계 조건을 따로 검사합니다.
- compose 룰은 안전 · 취약 fixture 전체에 대한 공통 테스트와, 오탐 방지 로직(변수 참조, 이스케이프, 레지스트리 포트, 멀티 스테이지 Dockerfile 등)에 대한 경계 테스트를 갖추고 있습니다.
- Remediator는 **백업 내용이 원본과 같은지, 검증 실패 시 원본과 디렉터리가 그대로인지, 적용 후 검증 실패 시 롤백되는지**를 테스트합니다.
- CLI는 `typer.testing.CliRunner`로 **y/N 입력까지 흉내 내어** 확인 · 취소 · 이중 확인 흐름을 테스트합니다.

| 파일 | 내용 |
|------|------|
| `tests/test_daemon_rules.py` | DAEMON-001 ~ 010 판정 로직과 설명 필드 품질 |
| `tests/test_compose_rules.py` | COMPOSE-001 ~ 012 판정 로직, 파서, 시크릿 비노출, 수정 예시 |
| `tests/test_compose_loader.py` | compose 탐색 우선순위 · 깊이 제한 · override 병합 · YAML 오류 위치 |
| `tests/test_remediator.py` | 계획 · diff · 백업 · 검증 · 롤백 · 직렬화 · 다음 단계 안내 |
| `tests/test_collector.py` | 플랫폼별 탐색, BOM · 빈 파일 · 권한 오류, rootless 감지 |
| `tests/test_engine.py` | 자동 등록 · 중복 ID 거부 · 카테고리 필터 · 예외 격리 |
| `tests/test_cli.py` | scan · rules · fix 명령 통합 테스트 |
| `tests/test_scoring.py` | 감점 · 하한 · 등급 경계값 |
| `tests/fixtures/daemon/` | 안전 · 취약 · 빈 객체 · 깨진 JSON · 잘못된 타입 예시 |
| `tests/fixtures/compose/` | 안전 · 취약(제작 배경 사고의 RabbitMQ 구성 재현) · 깨진 YAML 예시 |

---

## 현재 한계

정직하게 적어 둡니다.

- **`daemon.json`만 봅니다.** `dockerd` 명령행 플래그나 systemd drop-in(`/etc/systemd/system/docker.service.d/`)으로 준 설정은 아직 반영하지 않습니다. Phase 4에서 `docker info` 수집을 추가해 실제 적용 상태와 교차 확인할 예정입니다.
- **rootless 모드는 설정 파일 경로로 판별합니다.** `docker info`의 보안 옵션으로 확인하는 방식은 Phase 4에서 추가합니다.
- **Windows에서는 파일 권한(DAEMON-007)을 점검하지 않습니다.** POSIX 권한 개념이 없기 때문입니다.
- `dockerd --validate`는 Docker 23.0 이상에서만 동작합니다. 그보다 오래된 버전이나 dockerd가 없는 환경에서는 JSON 문법 검증만 하고, 그 사실을 결과에 표시합니다.
- **compose의 `extends:` · `include:`는 아직 따라가지 않습니다.** YAML 앵커(`<<: *common`)는 지원합니다.
- `docker-compose.prod.yml` 같은 **부분 파일은 자동 탐색하지 않습니다.** 단독으로 보면 base 설정이 빠져 오탐이 많기 때문입니다. 필요하면 `-f`로 직접 지정하세요.
- 시크릿 판정은 **환경변수 이름 규칙**에 기반합니다. 이름이 평범한 변수(예: `DB_CONN=postgres://user:pass@...`)에 들어간 비밀번호는 아직 잡지 못합니다.
- COMPOSE-002는 원격 이미지의 `USER`를 알 수 없어, 이미지가 내부적으로 non-root로 실행되더라도 compose에 `user:`가 없으면 취약으로 표시할 수 있습니다. Phase 4에서 로컬 이미지 정보(`docker image inspect`)로 보완할 예정입니다.

---

## 로드맵

- [x] **Phase 1** — 코어 엔진, 플러그인 룰 레지스트리, 터미널 리포트, 보안 점수
- [x] **Phase 2** — daemon 룰 10종, 안전한 자동 수정(`fix daemon`), `rules` 명령
- [x] **Phase 3** — docker-compose 스캐너 (룰 12종, 자동 탐색 + override 병합, 서비스별 수정 예시)
- [ ] **Phase 4** — 네트워크 격리 + **서비스 의존성 통신 검증** (`--deps`), Docker SDK/CLI 수집
- [ ] **Phase 5** — HTML · JSON 리포트, `dockguard learn` 보안 학습 기능
- [ ] **Phase 6** — GitHub Actions CI, 데모 시나리오(정전 후 의존성 검증 재현), 스크린샷
