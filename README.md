# dockguard

**Docker 호스트 통합 보안 진단 도구** — "무엇이 위험한지"뿐 아니라 **"고치면 무엇이 깨지는지"까지** 알려줍니다.

[![CI](https://github.com/taeyangkim4875-byte/dockguard/actions/workflows/ci.yml/badge.svg)](https://github.com/taeyangkim4875-byte/dockguard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20~%203.13-blue)
![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)
![CIS](https://img.shields.io/badge/CIS%20Docker%20Benchmark-v1.6.0-orange)

```bash
dockguard scan                      # 진단 — daemon.json · compose · 실행 중인 컨테이너 네트워크를 한 번에
dockguard scan --explain            # 왜 위험한지 · 어떻게 고치는지 · 고치면 무엇이 깨지는지
dockguard scan -o report.html       # 공유하기 좋은 HTML 리포트 (JSON도 가능)
dockguard fix daemon --apply        # 안전한 항목만 백업 → 검증 → 적용 → 실패 시 자동 롤백
dockguard learn icc                 # 보안 개념 학습 (11개 주제)
```

dockguard는 Docker 데몬 설정(`daemon.json`), docker-compose 파일, 컨테이너 네트워크 격리를 한 번에 점검하고,
각 취약점마다 **왜 위험한지 / 어떻게 고치는지 / 고치면 어떤 부작용이 있는지**를 한글로 설명하는 CLI 도구입니다.

![정전 후 서비스 의존성 진단 결과](docs/images/terminal-network.png)

<p align="center"><sub>정전으로 재부팅된 서버 진단 — 백엔드와 RabbitMQ가 공유하는 네트워크가 없고, Redis는 재시작 정책이 없어 올라오지 않았다는 것을 한 번에 찾아냅니다.<br>
<b><a href="docs/demo.md">▶ 이 시나리오를 처음부터 따라 해 보기 (docs/demo.md)</a></b></sub></p>

**룰 26종**(daemon 10 · compose 12 · 네트워크/서비스 의존성 4) · 안전한 자동 수정 · 터미널 / HTML / JSON 리포트 · 보안 학습 11개 주제 ·
테스트 834개 + 실제 Docker E2E(CI)

---

## 목차

- [왜 만들었나](#왜-만들었나)
- [dockguard의 장점](#dockguard의-장점)
- [설치](#설치)
- [서버에서 실행하기](#서버에서-실행하기)
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

보안 점검 도구의 결과는 대개 **"이 설정을 켜라"**에서 끝납니다. CIS 벤치마크 문서에는 각 항목의 영향(Impact)이 적혀 있지만,
장애 한가운데서 그 문서를 찾아 읽기는 어렵습니다. 운영자에게 정말 필요한 건 권고 바로 옆에 붙은 그다음 문장입니다.

> **"이 설정을 켜면 기본 브리지 위의 컨테이너 간 통신이 끊긴다. 백엔드↔메시지큐처럼 통신이 필요한 서비스는 반드시 같은 커스텀 네트워크에 두어라."**

dockguard는 모든 권고에 이 **부작용(tradeoff)**을 붙이고, 서비스 간 통신 가능 여부를 **선언적으로 검증**하는 것을 목표로 합니다.
위 사고에서 나온 교훈은 각 룰의 설명에 그대로 들어가 있습니다.

| 사고에서 얻은 교훈 | dockguard에 반영된 곳 |
|--------------------|------------------------|
| 보안 설정이 서비스 통신을 끊을 수 있다 | DAEMON-001(icc) 부작용 설명, 자동 수정 시 **강경고 + 이중 확인** |
| 재부팅 후 네트워크 분리를 빨리 찾아야 한다 | **NET-001 서비스 의존성 통신 검증** — 공유 네트워크 · icc 차단 · 멈춘 컨테이너를 한 번에 |
| 재시작 정책이 없으면 정전 후 컨테이너가 안 올라온다 | NET-001이 멈춘 대상의 `restart` 정책까지 확인해 원인과 복구 명령 제시 |
| `compose down`은 익명 볼륨 데이터를 잃게 한다 | 재생성 안내를 `up -d --force-recreate`로 통일, named volume 권고 |
| 서비스마다 비밀번호를 따로 적어 두면 한쪽만 바뀐다 | COMPOSE-005 평문 시크릿 점검 — 한 곳(.env / secrets)에서 관리하도록 안내 |
| live-restore는 정전(호스트 재부팅)을 막아 주지 않는다 | DAEMON-004 부작용에 명시, `restart:` 정책 안내 |
| 호스트 외부 IP로 컨테이너끼리 접속하면 불안정하다 | DAEMON-001/003 부작용에 서비스 이름 접속 권고 |
| RabbitMQ 포트가 0.0.0.0에 열려 guest로 접속당했다 | NET-004 민감 포트 외부 노출 점검, DAEMON-009의 UFW 우회 경고 |

---

## dockguard의 장점

**1. "왜 연결이 안 되는지"까지 짚어 줍니다.**
서비스 간 의존성을 선언해 두면 실제 Docker 상태와 대조해, 통신이 안 되는 이유가 *공유 네트워크가 없어서*인지,
*icc로 막혀서*인지, *재시작 정책이 없어 재부팅 후 안 올라와서*인지 구분합니다. 그리고 실제 컨테이너 · 네트워크 이름이 들어간
복구 명령을 제시합니다. compose의 `depends_on`은 따로 선언하지 않아도 자동으로 검증합니다.

**2. 고치면 무엇이 깨지는지 알려줍니다.**
모든 권고에 부작용 설명이 붙어 있습니다. "icc를 끄면 기본 bridge의 통신이 끊긴다", "userns-remap을 켜면 기존 볼륨이 보이지 않는다"처럼
실제로 겪는 문제를 권고 바로 옆에서 보여주고, 부작용이 큰 수정은 자동 수정 때 강한 경고와 이중 확인을 거치게 합니다.

**3. 세 영역을 엮어서 판단합니다.**
`daemon.json` · compose 파일 · 실행 중인 네트워크를 한 번에 보고, 서로의 설정을 참고해 판정합니다.
`icc: false`와 기본 bridge에 떨어진 컨테이너를 함께 보고 "통신 불가"를 찾아내고, 데몬에서 no-new-privileges가 켜져 있으면
compose 쪽 경고를 거두는 식입니다. 영역마다 따로 점검하면 나오지 않는 결론입니다.

**4. 자동 수정이 안전합니다.**
기본은 미리보기(diff)이고, 적용할 때는 백업 → `dockerd --validate` 검증 → 원자적 교체 → 실패 시 자동 롤백 순서를 지킵니다.
Docker 재시작은 직접 하지 않고, 컨테이너가 유지되는 올바른 순서(리로드 → 재시작)를 안내합니다.

**5. 배우면서 쓰는 도구입니다.**
설명은 전부 한글이고, `dockguard learn`으로 11개 주제(icc, seccomp, capabilities, docker.sock …)를 개념부터 공격 시나리오,
실제 사례까지 공부할 수 있습니다.

**6. 바로 쓸 수 있습니다.**
무료 오픈소스이고 설치 한 번이면 끝입니다. 에이전트나 별도 서버가 필요 없고, Python을 설치할 수 없는 서버는 스냅샷을 떠서
다른 곳에서 분석할 수 있습니다. HTML 리포트 · JSON · CI 종료 코드(`--fail-on`)를 지원합니다.

> dockguard를 만들기 전에 기존 도구들을 먼저 살펴봤습니다. 이미지 취약점(CVE) 스캔은 Trivy, Dockerfile 린트는 hadolint,
> 더 넓은 CIS · IaC 규칙 점검은 docker-bench-security나 KICS처럼 이미 훌륭한 도구가 있습니다. dockguard는 그 도구들이 중심에 두지 않는
> **서비스 간 통신 검증**과 **설정 변경의 부작용 설명**에 집중했습니다. 함께 쓰는 것을 권장합니다.

---

## 설치

**요구 사항**: Python 3.10 이상. 점검 대상은 Linux Docker 호스트이며, macOS · Windows(Docker Desktop)에서도 동작합니다.

| 배포판 | 기본 Python | 준비 |
|--------|-------------|------|
| Ubuntu 22.04 / 24.04 | 3.10 / 3.12 | `sudo apt install python3-venv git` |
| Debian 12 | 3.11 | `sudo apt install python3-venv git` |
| Rocky / RHEL 9 | 3.9 | `sudo dnf install python3.11 git` 후 아래 명령의 `python3`를 `python3.11`로 |
| Ubuntu 20.04 | 3.8 | deadsnakes PPA 등으로 3.10 이상 설치 필요 |

### 리눅스 서버에 설치 (권장)

`/opt`에 설치하고 `/usr/local/bin`에 링크를 걸면, **어느 디렉터리에서든 `sudo dockguard`로** 실행할 수 있습니다.
(`sudo`는 보안상 PATH를 제한하는데, `/usr/local/bin`은 그 안에 포함됩니다.)

```bash
sudo git clone https://github.com/taeyangkim4875-byte/dockguard.git /opt/dockguard
sudo python3 -m venv /opt/dockguard/.venv
sudo /opt/dockguard/.venv/bin/pip install "/opt/dockguard[docker]"
sudo ln -sf /opt/dockguard/.venv/bin/dockguard /usr/local/bin/dockguard

dockguard --version
```

업데이트는 `sudo git -C /opt/dockguard pull && sudo /opt/dockguard/.venv/bin/pip install "/opt/dockguard[docker]"`.
`[docker]`는 Docker SDK for Python을 함께 설치하는 옵션이며, 빼도 `docker` 명령으로 자동 전환해 동작합니다.

### 개발용 설치

```bash
git clone https://github.com/taeyangkim4875-byte/dockguard.git && cd dockguard
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

---

## 서버에서 실행하기

dockguard는 **어느 디렉터리에서 실행해도 되는 명령어**입니다. 다만 점검 대상마다 찾는 위치가 다르니 아래 표를 참고하세요.

| 점검 대상 | 어디서 찾나 | 실행 위치 영향 |
|-----------|-------------|:--------------:|
| `daemon.json` | `/etc/docker/daemon.json` (rootless는 `~/.config/docker/`) | 없음 |
| 실행 중인 컨테이너 · 네트워크 | Docker 소켓 (`sudo` 필요) | 없음 |
| **compose 파일** | **현재 디렉터리와 하위 3단계** 자동 탐색 | **있음** → `cd`하거나 `-f`로 지정 |
| 의존성 선언 파일 | `./dependencies.yaml` → `./config/dependencies.yaml` → `/etc/dockguard/dependencies.yaml` | 서버 전역 위치에 두면 없음 |

그래서 운영 서버에서는 보통 이렇게 씁니다.

```bash
# 한 번만: 서비스 의존성을 서버 전역 위치에 선언
sudo mkdir -p /etc/dockguard
sudo cp /opt/dockguard/config/dependencies.example.yaml /etc/dockguard/dependencies.yaml
sudo vi /etc/dockguard/dependencies.yaml

# 진단 — compose 파일이 모여 있는 곳을 지정
sudo dockguard scan -f /srv                      # 또는: cd /srv && sudo dockguard scan
sudo dockguard scan -f /srv --explain            # 상세 설명
sudo dockguard scan -f /srv -o /root/dockguard-report.html   # HTML 리포트로 저장

# 수정 (daemon.json만, 미리보기 → 적용)
sudo dockguard fix daemon
sudo dockguard fix daemon --apply
```

`sudo`가 필요한 이유: Docker 소켓 접근(NET-*)과 `daemon.json` 수정(`fix --apply`) 때문입니다. `sudo` 없이 실행해도 크래시하지 않고,
권한이 필요한 점검만 이유와 함께 **건너뜀**으로 표시합니다.

**정전 · 재부팅 직후 점검**이나 **정기 점검**에도 쓸 수 있습니다.

```bash
# /etc/cron.d/dockguard — 매일 새벽 HIGH 이상 취약점이 있으면 메일 (cron의 MAILTO)
MAILTO=ops@example.com
30 4 * * * root /usr/local/bin/dockguard scan -f /srv --fail-on high -o /var/log/dockguard/latest.html > /dev/null
```

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

### 5. 서비스 의존성 검증 — 정전 후 "왜 연결이 안 되지?"를 즉시 찾기

dockguard의 핵심 기능입니다. 서비스 간 통신 의존성을 선언해 두면, 실제 Docker 상태와 대조해 **통신이 불가능한 조합**을 찾아냅니다.
증상 → 진단 → 복구 → 재발 방지까지 이어지는 전체 흐름은 **[데모 문서](docs/demo.md)**에 있습니다.

```bash
cp config/dependencies.example.yaml config/dependencies.yaml   # 의존성 선언 (자동 탐색 위치)
sudo dockguard scan --category network                          # 실행 중인 Docker 상태와 대조
```

Docker가 없는 PC에서도 저장소에 포함된 **정전 사고 재현 예시**로 바로 확인할 수 있습니다.

```bash
dockguard scan -c network \
  --docker-snapshot examples/rabbitmq-incident/snapshot.json \
  --deps examples/rabbitmq-incident/dependencies.yaml \
  --daemon-config examples/rabbitmq-incident/daemon.json
```

```
 심각도     ID        제목                      상태   대상                                  현재값
 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 CRITICAL   NET-001   서비스 의존성 통신 검증   취약   backend-container → rabbitmq:5672     공유 네트워크 없음 — backend-container: bridge
                                                                                                 / rabbitmq: messaging_mq-net
 CRITICAL   NET-001   서비스 의존성 통신 검증   취약   report-worker → redis:6379            messaging-redis-1 컨테이너가 실행 중이 아님
                                                                                                 (exited, restart: no) — 재시작 정책이 없어
                                                                                                 재부팅 후 자동으로 올라오지 않음
 HIGH       NET-004   민감 포트 외부 노출 점검  취약   Docker 호스트                         2건 — rabbitmq 0.0.0.0:5672->5672 (RabbitMQ AMQP);
                                                                                                 rabbitmq 0.0.0.0:15672->15672 (RabbitMQ 관리 UI)
 LOW        NET-002   고아 컨테이너 네트워크    취약   Docker 호스트                         2개 — backend-container (bridge), web (bridge)
 MEDIUM     NET-003   기본 bridge 공유 경고     주의   Docker 호스트                         2개가 기본 bridge에 있지만 icc: false로 서로 통신 불가
 CRITICAL   NET-001   서비스 의존성 통신 검증   통과   service-manager → rabbitmq:5672       공유 네트워크: messaging_mq-net
 CRITICAL   NET-001   서비스 의존성 통신 검증   통과   report-worker → rabbitmq (depends_on) 공유 네트워크: messaging_mq-net
```

`--explain`을 붙이면 선언한 이유("백엔드가 RabbitMQ 큐를 소비")와 함께, **실제 컨테이너 · 네트워크 이름이 들어간 복구 명령**을 보여줍니다.

```bash
# 지금 바로 복구하려면
docker network connect messaging_mq-net backend-container
```

#### Python을 설치할 수 없는 서버라면 — 스냅샷으로 오프라인 분석

서버에서 아래 명령으로 상태를 떠 와서, dockguard가 설치된 PC에서 분석할 수 있습니다.

```bash
# 서버에서 실행 (docker 명령만 있으면 됨)
{
  echo '{"containers":'; docker inspect $(docker ps -aq) 2>/dev/null || echo '[]'
  echo ',"networks":';   docker network inspect $(docker network ls -q)
  echo ',"info":';       docker info --format '{{json .}}'
  echo '}'
} > snapshot.json

# dockguard가 설치된 PC에서
dockguard scan -c network --docker-snapshot snapshot.json --deps config/dependencies.yaml
```

> ⚠️ **스냅샷에는 컨테이너 환경변수(비밀번호가 들어 있을 수 있음)가 포함됩니다.** dockguard는 환경변수를 쓰지 않으므로,
> `jq`가 있다면 첫 줄을 `docker inspect $(docker ps -aq) | jq 'map(del(.Config.Env))'`로 바꿔 제거한 뒤 옮기세요.
> 어느 쪽이든 스냅샷은 민감 정보로 다루고 분석 후 삭제하세요.

### 6. 리포트로 저장하기 — HTML · JSON

```bash
dockguard scan -o report.html          # 한 파일로 완결되는 HTML (외부 CSS·폰트·스크립트 없음 → 메일 첨부·오프라인 열람 가능)
dockguard scan -o result.json          # 확장자로 형식 자동 결정
dockguard scan --format json | jq '.score'       # 표준 출력으로 JSON (진행 표시는 stderr로 분리)
dockguard scan -o scan.txt --explain   # 색상 없는 텍스트 리포트
```

**HTML 리포트**는 공유 · 보고용입니다. 상단에 점수 게이지와 심각도별 개수, **조치가 필요한 항목** 요약 표(클릭하면 해당 카드로 이동)가 있고,
영역별 카드에는 현재값 → 권장값이 설정 diff처럼 표시되며, 부작용은 "고치면 생기는 일" 박스로 강조됩니다. 명령어 블록에는 복사 버튼이 있고,
라이트/다크 테마와 인쇄를 지원합니다.

![HTML 리포트](docs/images/report.png)

<sub>샘플 파일: [docs/sample-report.html](docs/sample-report.html) — 내려받아 브라우저로 열어 보세요.</sub>

**JSON 리포트**는 CI/CD · 다른 도구 연동용입니다. `schema_version`으로 형식을 관리하고, 각 항목에 설명 원문과 `learn_topic`을 담습니다.

```json
{
  "schema_version": 1,
  "host": "prod-server-01",
  "score": {"value": 34, "max": 100, "grade": "F", "deducted": 66},
  "summary": {"rules_run": 26, "status": {"fail": 6, "warn": 1, "pass": 15, "skip": 4}, "failed_by_severity": {"critical": 1, "high": 2, "...": 0}},
  "collection_errors": [],
  "findings": [{"rule_id": "NET-001", "severity": "critical", "status": "fail", "target": "backend-container → rabbitmq:5672", "learn_topic": "network-isolation", "...": "..."}]
}
```

**CI 파이프라인에서 막기** — 특정 심각도 이상의 취약점이 있으면 종료 코드 1을 돌려줍니다.

```yaml
# GitHub Actions 예시: compose 파일에 CRITICAL/HIGH 취약점이 있으면 PR 실패
- run: pip install git+https://github.com/taeyangkim4875-byte/dockguard.git
- run: dockguard scan -c compose -f . --fail-on high -o dockguard.json
```

### 7. 보안 개념 학습 — `dockguard learn`

리포트의 짧은 설명과 별개로, 각 개념을 **개념 → 동작 원리 → 공격 시나리오 → 권장 방법 → 실제 사례** 순서로 깊이 있게 설명합니다.

```bash
dockguard learn                 # 주제 목록
dockguard learn icc             # 주제 이름으로
dockguard learn COMPOSE-004     # 룰 ID로 — 해당 룰과 가장 관련 깊은 주제 (docker-sock)
dockguard learn ufw             # 별칭으로 (port-exposure)
```

| 주제 | 내용 |
|------|------|
| `icc` | 기본 bridge의 컨테이너 간 통신, 커스텀 네트워크와의 차이 |
| `lateral-movement` | 침해된 컨테이너 하나가 서버 전체로 번지는 경로 |
| `network-isolation` | 신뢰 수준별 네트워크 설계, `internal: true`, 서비스 이름 접속 |
| `privileged` | privileged가 푸는 것들과 호스트 디스크 마운트 탈출 |
| `capabilities` | root 권한의 조각들, Docker 기본 14개, `cap_drop: [ALL]` |
| `seccomp` | 시스템 콜 필터, 기본 프로파일이 막아 준 커널 취약점들 |
| `userns-remap` | uid 매핑 원리, 데이터 디렉터리 분리, CVE-2019-5736 |
| `rootless` | 데몬까지 일반 사용자로, docker 그룹 = root 문제 |
| `docker-sock` | Docker API 소켓의 위험, 2375 포트, 소켓 프록시 |
| `secrets-management` | 평문 → .env → secrets → 시크릿 저장소, 비밀번호 불일치 사고 |
| `port-exposure` | `ports:`가 UFW를 우회하는 원리, `DOCKER-USER`, `"ip": "127.0.0.1"` |

`--explain`과 HTML 리포트의 각 항목에도 관련 학습 주제(`dockguard learn <주제>`)가 표시됩니다.

### 8. 조직에 맞게 조정하기 — 룰셋

모든 권고가 모든 환경에 맞지는 않습니다. 당장 고칠 수 없는 항목은 **이유를 남기고** 끄거나 심각도를 조정합니다.
끈 룰은 모든 리포트 상단에 표시되어, 예외가 조용히 숨지 않습니다.

```yaml
# config/ruleset.yaml (또는 ./ruleset.yaml, /etc/dockguard/ruleset.yaml — 자동 탐색)
disabled:
  - COMPOSE-006   # 레거시 앱이 루트 FS에 로그를 씀 — 로그 볼륨 분리 후 다시 켤 것
severity:
  COMPOSE-008: low   # 성능 때문에 host 네트워크를 쓰는 GPU 서버
```

```bash
dockguard scan --ruleset ./my-ruleset.yaml
```

없는 룰 ID나 잘못된 심각도는 오타일 가능성이 높아, 무시하지 않고 **오류로 멈춥니다** (끄려던 룰이 켜진 채 점수가 나오면 안 되기 때문).

### 9. 룰 목록 보기

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
| `-d`, `--deps PATH` | 서비스 의존성 파일. 지정하면 network 영역이 자동으로 포함됨. 기본: `./dependencies.yaml`, `./config/dependencies.yaml` 자동 탐색 |
| `--docker-snapshot PATH` | Docker에 직접 연결하는 대신 서버에서 떠 온 스냅샷 JSON을 분석 (오프라인 분석) |
| `-e`, `--explain` | 취약 항목마다 위험 이유 · 수정 방법 · 부작용 · 근거를 상세 표시 |
| `-o`, `--output PATH` | 리포트를 파일로 저장. 확장자 `.html` · `.json`이면 그 형식, 그 외는 색상 없는 텍스트 |
| `--format [terminal\|json\|html]` | 출력 형식 명시. `json`을 `-o` 없이 쓰면 표준 출력으로, `html`을 `-o` 없이 쓰면 `dockguard-<호스트>-<시각>.html` |
| `--fail-on [critical\|high\|medium\|low]` | 이 심각도 이상 취약 항목이 있으면 종료 코드 1 (메시지는 stderr) |
| `--ruleset PATH` | 룰 끄기 · 심각도 조정 파일. 기본: `./ruleset.yaml`, `./config/ruleset.yaml`, `/etc/dockguard/ruleset.yaml` 자동 탐색 |

### `dockguard fix daemon`

| 옵션 | 설명 |
|------|------|
| `--dry-run` / `--apply` | 기본은 `--dry-run`(미리보기). `--apply`를 붙여야 백업 후 실제로 수정 |
| `-r`, `--rule ID` | 수정할 룰만 선택. 여러 번 지정 가능. **부작용이 큰 항목(예: DAEMON-001)은 여기 명시해야만 포함** |
| `--daemon-config PATH` | `daemon.json` 경로 직접 지정 |

종료 코드: `0` 성공 · `1` 사용자가 취소했거나 적용 실패 · `2` 잘못된 입력(없는 파일, 알 수 없는 룰 ID, 파싱 불가한 JSON)

### `dockguard fix compose`

compose 파일을 자동 수정하지 않는 이유와, 수정 예시를 보는 방법(`scan -c compose --explain`)을 안내합니다.

### `dockguard learn [주제 | 룰 ID]`

보안 학습 주제 목록 또는 주제 하나의 상세 설명. 없는 주제면 비슷한 주제를 제안합니다 (종료 코드 2).

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

### Network — 네트워크 격리와 서비스 의존성 (4종, 구현 완료)

실행 중인 Docker의 **실제 상태**를 봅니다 (Docker SDK → docker CLI 순으로 자동 폴백, 또는 스냅샷 파일).

| ID | 점검 내용 | 판정 기준 | 심각도 | 근거 |
|----|-----------|-----------|:------:|------|
| **NET-001** | **서비스 의존성 통신 검증** | 선언된 A → B마다: 컨테이너 존재 · B 실행 중 · **공유 네트워크** · icc 차단 여부 · 포트 노출 | CRITICAL | dockguard 고유 |
| NET-002 | 고아 컨테이너 | 커스텀 네트워크에 하나도 연결되지 않은 실행 중 컨테이너 | LOW | CIS 5.30 (연관) |
| NET-003 | 기본 bridge 공유 | 기본 bridge에 2개 이상 — icc 켜짐: 취약(측면 이동), 꺼짐: 주의(통신 불가) | MEDIUM | CIS 5.30 |
| NET-004 | 민감 포트 외부 노출 | 5672 · 15672 · 3306 · 5432 · 6379 · 27017 · 9200 · 2375 등이 `0.0.0.0`/`::`에 공개 | HIGH | CIS 5.14 |

<details>
<summary><b>NET-001이 판정하는 상황 전부 보기</b></summary>

| 상황 | 결과 | 안내 |
|------|:----:|------|
| 같은 커스텀 네트워크를 공유 | 통과 | 공유 네트워크 이름 표시 |
| **공유 네트워크 없음** (예: 백엔드는 기본 bridge, RabbitMQ는 커스텀 네트워크) | 취약 | `docker network connect <상대 네트워크> <컨테이너>` + compose 영구 반영 방법 |
| 대상 컨테이너가 멈춰 있음 | 취약 | 재시작 정책이 `no`면 "재부팅 후 자동으로 올라오지 않음" + `docker update --restart unless-stopped` |
| 컨테이너가 없음 | 취약 | 이름 변경 · 재생성 누락 가능성 |
| 공유 네트워크가 기본 bridge뿐이고 `icc: false` | 취약 | icc 차단 (daemon.json **또는** Docker가 bridge에 기록한 실제 상태로 판단) |
| 커스텀 네트워크에 `enable_icc=false` | 취약 | 네트워크 단위 통신 차단 |
| 공유 네트워크가 기본 bridge뿐이고 icc 켜짐 | 주의 | 이름 DNS 불가, 재기동마다 IP 변경 |
| 대상이 해당 포트를 EXPOSE하지 않음 | 주의 | 포트 번호 확인 |
| host 네트워크 모드가 끼어 있음 | 주의/취약 | 공개 포트로만 통신 가능한지 확인 |
| `network_mode: container:<x>` | — | 소유 컨테이너의 네트워크로 판단 |
| compose로 스케일된 서비스 | — | 출발 복제본은 **전부** 닿아야 하고, 대상 복제본은 **하나라도** 닿으면 됨 |

</details>

**의존성은 두 곳에서 옵니다.**

1. **`dependencies.yaml`** — 명시적 선언 (`--deps`로 지정하거나 `./dependencies.yaml`, `./config/dependencies.yaml`을 자동 탐색)
2. **compose `depends_on`** — 선언 파일이 없어도, 이 호스트에서 **실제로 실행 중인** compose 프로젝트의 `depends_on`을 자동으로 검증합니다. 같은 쌍이 파일에도 있으면 파일의 선언(포트 · 이유 포함)을 우선합니다.

```yaml
# config/dependencies.yaml — config/dependencies.example.yaml을 복사해서 사용
dependencies:
  - from: "backend-container"   # 컨테이너 이름 또는 compose 서비스 이름
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
│   ├── docker_runtime.py      # 실행 중인 Docker 수집 (SDK → CLI 폴백, 스냅샷), 오류 안내
│   ├── dependencies.py        # dependencies.yaml 로드 · compose depends_on 추론
│   ├── engine.py              # 룰 실행 (카테고리 필터, 룰셋 적용, 예외 격리)
│   ├── ruleset.py             # 룰 끄기 · 심각도 조정 (ruleset.yaml)
│   └── scoring.py             # 점수 · 등급
├── rules/
│   ├── __init__.py            # 하위 모듈 재귀 자동 import
│   ├── daemon/                # DAEMON-001 ~ 010 (+ _base.py 공통 베이스)
│   ├── compose/               # COMPOSE-001 ~ 012 (+ _base.py: 서비스 순회, 포트/볼륨/이미지 파서)
│   └── network/               # NET-001 ~ 004 (의존성 통신 검증, 고아 컨테이너, 기본 bridge, 민감 포트)
├── remediators/
│   └── daemon_remediator.py   # 계획 · diff · 백업 · 검증 · 롤백 · 다음 단계 안내
├── reporters/
│   ├── terminal.py            # rich 리포트 (점수 게이지, --explain), learn 화면
│   ├── html.py                # 한 파일로 완결되는 HTML 리포트 (Markdown → HTML, 원문 HTML 차단)
│   ├── json_reporter.py       # CI/CD 연동용 JSON (schema_version)
│   └── remediation.py         # fix / rules 화면
├── templates/
│   └── report.html.j2         # HTML 리포트 템플릿 (인라인 CSS/JS, 라이트·다크·인쇄)
└── knowledge/
    ├── explanations.py        # dockguard learn 학습 콘텐츠 (11개 주제)
    ├── references.py          # CIS 근거 표기 (v1.6.0 기준)
    ├── compose_facts.py       # 위험 capability, 시크릿 이름 규칙 등 보안 지식 상수
    └── network_facts.py       # 외부 노출되면 안 되는 민감 포트 목록
config/
├── dependencies.example.yaml  # 서비스 의존성 선언 예시
└── ruleset.example.yaml       # 룰셋 예시
examples/
└── rabbitmq-incident/         # 정전 사고 재현 (스냅샷 · 의존성 · daemon.json · compose · reproduce.sh)
docs/
├── demo.md                    # 데모 시나리오: 정전 후 의존성 검증
├── sample-report.html         # HTML 리포트 샘플
└── images/                    # README 스크린샷 (scripts/make_screenshots.py로 생성)
.github/workflows/ci.yml       # pytest 매트릭스 + 실제 Docker E2E
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
| 네트워크 룰은 설정 파일보다 **실행 중인 상태**를 우선 | 설정 파일에 적힌 것과 실제로 떠 있는 것은 다를 수 있습니다(수동 `docker run`, 임시 `network connect`). 장애는 실제 상태에서 일어납니다. icc도 Docker가 bridge에 기록한 값을 먼저 봅니다. |
| SDK · CLI · 스냅샷이 같은 `docker inspect` JSON을 공유 | 수집 경로가 셋이어도 파서는 하나라 동작이 일관되고, 테스트는 가짜 inspect JSON만 넣으면 됩니다. |
| Docker에 연결 못 하면 룰마다 '건너뜀'을 남김 | 조용히 결과를 빼면 "네트워크는 문제없음"으로 오해합니다. 점검하지 못했다는 사실 자체를 표에 드러냅니다. |
| compose `depends_on`을 의존성으로 자동 추론 | 선언 파일을 쓰지 않아도 기본 검증이 되게 합니다. 단, 이 호스트에서 실행 중인 프로젝트만 대상으로 해 다른 서버용 compose 파일로 오탐하지 않습니다. |
| NET-004는 Docker가 없으면 compose 파일로 대체 판정 | 민감 포트 노출은 가장 흔한 사고 경로라, 실제 상태를 볼 수 없을 때도 확인할 수 있는 만큼은 확인합니다. |
| HTML 리포트는 외부 리소스 없이 한 파일로 | 서버에서 만든 리포트를 메일로 보내거나 인터넷이 없는 곳에서 열어도 똑같이 보여야 합니다. 웹 폰트 대신 시스템 폰트를 씁니다. |
| 리포트의 Markdown은 원문 HTML을 허용하지 않음 | `dependencies.yaml`의 이유 문구처럼 사용자 입력이 섞입니다. 공유되는 리포트가 스크립트 실행(XSS) 경로가 되지 않도록 테스트로 검증합니다. |
| JSON을 stdout으로 낼 때 나머지 출력은 stderr로 | `dockguard scan --format json \| jq`가 항상 동작하도록, 진행 표시 · 안내 · `--fail-on` 경고가 JSON에 섞이지 않게 합니다. |
| 설명 텍스트 품질을 테스트로 검사 | 룰과 학습 주제의 설명이 130개가 넘습니다. `**강조(괄호)**에` 같은 한국어 Markdown 함정을 사람이 찾기는 어려워, 전부 렌더링해 보고 남은 `**`를 잡아냅니다. |

---

## 개발과 테스트

```bash
pip install -e ".[dev]"
pytest                                        # 전체 테스트
pytest --cov=dockguard --cov-report=term-missing
python scripts/make_screenshots.py --font D2Coding.ttf   # README 스크린샷 · 샘플 리포트 재생성
```

**GitHub Actions CI**([`.github/workflows/ci.yml`](.github/workflows/ci.yml))가 모든 푸시와 PR에서 두 가지를 확인합니다.

| 잡 | 내용 |
|----|------|
| `pytest` | Ubuntu × Python 3.10 · 3.11 · 3.12 · 3.13 + Windows. 커버리지 90% 미만이면 실패. 리눅스 전용 코드(POSIX 파일 권한 등)도 여기서 검증 |
| `e2e-docker` | **러너의 실제 Docker에서 정전 사고를 재현**(`examples/rabbitmq-incident/reproduce.sh`)하고, Docker SDK 경로와 docker CLI 폴백 경로 모두로 NET-001 · NET-004가 제대로 잡히는지, 복구 후에는 모두 통과하는지, `--fail-on`이 종료 코드 1을 내는지 검증. 생성한 HTML/JSON 리포트는 아티팩트로 업로드 |

- **테스트 834개, 커버리지 98%** — 단위 테스트는 실제 Docker 없이 실행됩니다.
- 각 룰마다 **통과 · 취약 · 파일 없음(기본값) · 파싱 실패 · 잘못된 타입** 케이스를 공통 테스트로 검사하고, 룰별 경계 조건을 따로 검사합니다.
- compose 룰은 안전 · 취약 fixture 전체에 대한 공통 테스트와, 오탐 방지 로직(변수 참조, 이스케이프, 레지스트리 포트, 멀티 스테이지 Dockerfile 등)에 대한 경계 테스트를 갖추고 있습니다.
- Remediator는 **백업 내용이 원본과 같은지, 검증 실패 시 원본과 디렉터리가 그대로인지, 적용 후 검증 실패 시 롤백되는지**를 테스트합니다.
- CLI는 `typer.testing.CliRunner`로 **y/N 입력까지 흉내 내어** 확인 · 취소 · 이중 확인 흐름을 테스트합니다.

| 파일 | 내용 |
|------|------|
| `tests/test_daemon_rules.py` | DAEMON-001 ~ 010 판정 로직과 설명 필드 품질 |
| `tests/test_compose_rules.py` | COMPOSE-001 ~ 012 판정 로직, 파서, 시크릿 비노출, 수정 예시 |
| `tests/test_compose_loader.py` | compose 탐색 우선순위 · 깊이 제한 · override 병합 · YAML 오류 위치 |
| `tests/test_network_rules.py` | NET-001 ~ 004 판정 (공유 네트워크, icc 차단, 멈춘 컨테이너, host/container 모드, 스케일 서비스, 정전 시나리오) |
| `tests/test_docker_runtime.py` | SDK · CLI · 스냅샷 수집 경로와 폴백, inspect 파서, Docker 오류 안내 분류 |
| `tests/test_dependencies.py` | 의존성 파일 검증 오류 메시지, depends_on 추론, 선언 우선 중복 제거 |
| `tests/test_reports.py` | JSON 스키마 · stdout 순수성, HTML 자기완결성 · **XSS 이스케이프**, 텍스트 리포트, `--fail-on` |
| `tests/test_learn.py` | 필수 학습 주제, 관련 룰 ID 유효성, 별칭 · 룰 ID 검색, 없는 주제 제안 |
| `tests/test_content_quality.py` | **모든 룰 · 학습 주제의 Markdown이 제대로 렌더링되는지** (한국어 강조 표기 함정 자동 검출) |
| `tests/test_remediator.py` | 계획 · diff · 백업 · 검증 · 롤백 · 직렬화 · 다음 단계 안내 |
| `tests/test_collector.py` | 플랫폼별 탐색, BOM · 빈 파일 · 권한 오류, rootless 감지 |
| `tests/test_engine.py` | 자동 등록 · 중복 ID 거부 · 카테고리 필터 · 예외 격리 |
| `tests/test_cli.py` | scan · rules · fix 명령 통합 테스트 |
| `tests/test_scoring.py` | 감점 · 하한 · 등급 경계값 |
| `tests/test_ruleset.py` | 룰셋 형식 검증 · 룰 비활성화 · 심각도 조정의 점수 반영 · 리포트 표시 |
| `tests/e2e/check_incident.py` | CI의 실제 Docker E2E 결과 검증 스크립트 |
| `tests/fixtures/daemon/` | 안전 · 취약 · 빈 객체 · 깨진 JSON · 잘못된 타입 예시 |
| `tests/fixtures/compose/` | 안전 · 취약(제작 배경 사고의 RabbitMQ 구성 재현) · 깨진 YAML 예시 |
| `examples/rabbitmq-incident/` | 정전 사고 재현 — 스냅샷(단위 테스트 · 오프라인 데모), `reproduce.sh`(실제 Docker 데모 · CI E2E) |

> 테스트는 실제 Docker에 절대 연결하지 않습니다. 개발 PC나 CI 러너에 Docker가 떠 있어도 결과가 달라지지 않도록 conftest에서 수집 경로를 막아 둡니다.

---

## 현재 한계

정직하게 적어 둡니다.

- **daemon 룰은 주로 `daemon.json`을 봅니다.** `dockerd` 명령행 플래그나 systemd drop-in으로 준 설정은, Docker에 연결된 경우 userns-remap · rootless(`docker info`)와 icc(기본 bridge 옵션)만 실제 상태로 교차 확인합니다. 나머지 항목은 아직 설정 파일 기준입니다.
- **NET-001은 네트워크 경로까지만 확인합니다.** 대상이 실제로 포트를 리스닝하는지, 비밀번호가 맞는지, `DOCKER-USER` 체인이 막고 있지 않은지는 알 수 없습니다. 통과 후에도 연결이 안 되면 애플리케이션 로그의 인증 오류를 확인하세요.
- 네트워크 점검은 **로컬 Docker 호스트 하나**를 봅니다. Swarm 오버레이 네트워크나 여러 호스트에 걸친 의존성은 다루지 않습니다.
- **Windows에서는 파일 권한(DAEMON-007)을 점검하지 않습니다.** POSIX 권한 개념이 없기 때문입니다.
- `dockerd --validate`는 Docker 23.0 이상에서만 동작합니다. 그보다 오래된 버전이나 dockerd가 없는 환경에서는 JSON 문법 검증만 하고, 그 사실을 결과에 표시합니다.
- **compose의 `extends:` · `include:`는 아직 따라가지 않습니다.** YAML 앵커(`<<: *common`)는 지원합니다.
- `docker-compose.prod.yml` 같은 **부분 파일은 자동 탐색하지 않습니다.** 단독으로 보면 base 설정이 빠져 오탐이 많기 때문입니다. 필요하면 `-f`로 직접 지정하세요.
- 시크릿 판정은 **환경변수 이름 규칙**에 기반합니다. 이름이 평범한 변수(예: `DB_CONN=postgres://user:pass@...`)에 들어간 비밀번호는 아직 잡지 못합니다.
- COMPOSE-002는 원격 이미지의 `USER`를 알 수 없어, 이미지가 내부적으로 non-root로 실행되더라도 compose에 `user:`가 없으면 취약으로 표시할 수 있습니다. 로컬 이미지 정보(`docker image inspect`)로 보완하는 것은 추후 과제입니다.

---

## 로드맵

- [x] **Phase 1** — 코어 엔진, 플러그인 룰 레지스트리, 터미널 리포트, 보안 점수
- [x] **Phase 2** — daemon 룰 10종, 안전한 자동 수정(`fix daemon`), `rules` 명령
- [x] **Phase 3** — docker-compose 스캐너 (룰 12종, 자동 탐색 + override 병합, 서비스별 수정 예시)
- [x] **Phase 4** — 네트워크 격리 + **서비스 의존성 통신 검증** (`--deps`, depends_on 추론), Docker SDK/CLI/스냅샷 수집
- [x] **Phase 5** — HTML · JSON 리포트, `--fail-on`, `dockguard learn` 보안 학습 기능 (11개 주제)
- [x] **Phase 6** — GitHub Actions CI(실제 Docker E2E 포함), 룰셋, 데모 시나리오, 스크린샷

**앞으로 해 볼 것**

- `docker image inspect`로 이미지의 `USER`를 확인해 COMPOSE-002 오탐 줄이기
- `dockerd` 실행 옵션 · systemd drop-in까지 읽어 daemon 룰의 실제 적용 상태 교차 확인 확대
- compose `extends:` · `include:` 지원
- 연결 문자열(`postgres://user:pass@...`) 안의 비밀번호 탐지
- NET-001에서 대상 포트가 실제로 리스닝 중인지 확인 (컨테이너 네트워크 네임스페이스에서 연결 시도)
