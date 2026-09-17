# 데모 — 5분 안에 dockguard 보여주기

발표 · 면접 · 녹화용 **대본**입니다. 복사해서 그대로 따라 하면 됩니다.

| 시나리오 | 보여주는 것 | 시간 |
|----------|-------------|------|
| [1. 예방 — 취약점 진단과 개선](#시나리오-1-예방--취약점을-찾고-안전하게-고친다) | `scan` → `fix` → 점수 변화, **자동 수정을 제한한 이유** | 2분 |
| [2. 진단 — 장애 원인 추적](#시나리오-2-진단--장애의-근본-원인을-찾는다-) ★ | `diagnose` — 며칠 걸린 디버깅을 몇 초에 | 3분 |
| [3. 학습](#시나리오-3-학습--개념까지-설명한다) | `learn` — 개념 · 공격 시나리오 · 실제 사례 | 30초 |

**준비물**: dockguard 설치([README](../README.md#설치)). 시나리오 2의 실습에만 Docker가 필요하고, Docker가 없으면 저장소에 포함된 스냅샷으로 똑같이 따라 할 수 있습니다.

> 두 시나리오는 이어집니다. 1에서 **보안을 강화**하고, 2에서 **그 보안 설정 때문에 서비스가 끊깁니다.**
> 이 도구가 만들어진 이유가 정확히 그 지점입니다.

---

## 시나리오 1: 예방 — 취약점을 찾고 안전하게 고친다

### 1-1. 취약한 설정 준비

실제 `/etc/docker/daemon.json`을 건드리지 않도록 **사본**으로 진행합니다.

```bash
mkdir -p /tmp/dockguard-demo
cp tests/fixtures/daemon/insecure.json /tmp/dockguard-demo/daemon.json
cat /tmp/dockguard-demo/daemon.json
```

```json
{
  "icc": true,
  "no-new-privileges": false,
  "live-restore": false,
  "userland-proxy": true,
  "iptables": false,
  "seccomp-profile": "unconfined",
  "insecure-registries": ["10.0.0.5:5000", "localhost:5000"],
  "registry-mirrors": ["http://mirror.internal"]
}
```

### 1-2. 진단

```bash
dockguard scan -c daemon --daemon-config /tmp/dockguard-demo/daemon.json
```

```
┌──────────────────────────────────────────────────────┐
│  전체 점수: 0/100    등급 F                          │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                      │
│   CRITICAL 0   HIGH 4   MEDIUM 3   LOW 2             │
│  통과 0 · 취약 9 · 주의 0 · 건너뜀 1  (룰 10개 실행) │
└──────────────────────────────────────────────────────┘
 HIGH     DAEMON-002   no-new-privileges 기본 활성화   취약   false
 HIGH     DAEMON-006   user namespace remapping        취약   미설정 (컨테이너 root = 호스트 root)
 HIGH     DAEMON-008   기본 seccomp 프로파일 유지      취약   "unconfined" — 모든 컨테이너의 seccomp 보호 해제
 HIGH     DAEMON-010   insecure-registry 미사용        취약   insecure-registries ["10.0.0.5:5000"] …
 MEDIUM   DAEMON-001   ICC(컨테이너 간 통신) 제한      취약   true
 …
```

**말할 것**: "점수는 100에서 시작해 심각도만큼 깎입니다. 이 서버는 0점, F등급입니다."

### 1-3. 왜 위험한지, 고치면 무엇이 깨지는지

```bash
dockguard scan -c daemon --daemon-config /tmp/dockguard-demo/daemon.json --explain
```

**DAEMON-001(icc)** 하나만 짚으면 충분합니다. 화면에 세 블록이 나옵니다.

- **■ 왜 위험한가** — 기본 브리지의 모든 컨테이너가 서로 통신할 수 있어, 하나가 뚫리면 옆으로 번진다(측면 이동)
- **■ 어떻게 고치나** — `"icc": false`
- **■ 부작용 / 주의사항** — *"기본 브리지 위의 컨테이너 간 통신이 전부 끊긴다. 통신이 필요한 서비스는 반드시 같은 커스텀 네트워크에 두어야 한다"*

**말할 것**: "다른 점검 도구는 위의 두 블록에서 끝납니다. 세 번째 블록이 이 도구를 만든 이유입니다. 저는 이걸 몰라서 며칠을 썼습니다."

### 1-4. 수정 — 기본은 미리보기

```bash
dockguard fix daemon --daemon-config /tmp/dockguard-demo/daemon.json
```

```
 DAEMON-002   no-new-privileges 기본 활성화   "no-new-privileges": true    재시작   안전
 DAEMON-004   live-restore 활성화             "live-restore": true         리로드   안전
 DAEMON-005   로그 드라이버 / 크기 제한       "log-opts": {…}              재시작   안전

변경 미리보기 (diff)
 -  "no-new-privileges": false,
 +  "no-new-privileges": true,
 …

수동 조치 필요 (자동 수정 대상 아님)
 DAEMON-006   user namespace remapping   켜는 순간 기존 이미지·컨테이너·볼륨이 보이지 않게 되고…
 DAEMON-001   ICC(컨테이너 간 통신) 제한  부작용이 커서 기본 수정 대상에서 제외했습니다…

  미리보기입니다. 파일은 변경되지 않았습니다. 적용하려면: dockguard fix daemon --apply
```

**말할 것**: "취약점은 9개인데 자동으로 고치는 건 3개뿐입니다. 나머지는 왜 수동인지까지 설명합니다. 자동화가 오히려 장애를 만든 경험이 있어서 이렇게 설계했습니다."

```bash
dockguard fix daemon --daemon-config /tmp/dockguard-demo/daemon.json --apply
```

백업 → 검증 → 원자적 교체 순서로 적용되고, 실패하면 자동 롤백됩니다. 적용 후엔 **지금 상태에 맞는 다음 단계**(리로드 → 재시작 순서, 되돌리는 명령)를 안내합니다.

### 1-5. 점수 변화 — 한 번에 A가 되지 않는다

```bash
dockguard scan -c daemon --daemon-config /tmp/dockguard-demo/daemon.json
```

| 단계 | 점수 | 남은 취약점 |
|------|------|-------------|
| 처음 | **0/100 (F)** | 9건 |
| `fix daemon --apply` 후 | **10/100 (F)** | 6건 — 전부 수동 조치 항목 |
| 안내대로 수동 조치까지 마친 뒤 | **100/100 (A)** | 0건 |

**말할 것**: "명령 한 번에 A로 만들어 주는 도구가 아닙니다. 안전한 것만 고치고, 위험한 건 **왜 위험한지 설명하고 사람에게 넘깁니다.** 그게 이 도구의 입장입니다."

> 리눅스에서는 `DAEMON-007`(파일 소유자 · 권한)도 함께 점검합니다. 데모용 사본은 root 소유가 아니라서 이 항목이 취약으로 남습니다 — 실제 `/etc/docker/daemon.json`에서는 해당되지 않습니다. `sudo chown root:root /tmp/dockguard-demo/daemon.json`을 하면 100점이 됩니다.

### 1-6. 다음 시나리오로 넘어가는 다리

수동 조치 항목 중에 **`"icc": false`** 가 있었습니다. 권고대로 적용했다고 합시다. 옳은 보안 조치입니다.

**그리고 며칠 뒤 정전이 납니다.**

> 🎬 **녹화 팁**: 1-2(점수 F) → 1-3(부작용 블록) → 1-5(점수 표)만 잘라 붙이면 60초 클립이 됩니다.

---

## 시나리오 2: 진단 — 장애의 근본 원인을 찾는다 ★

### 2-0. 상황

> 정전으로 서버가 재부팅됐습니다. 컨테이너는 전부 올라왔는데, 백엔드가 메시지를 소비하지 못해 이력이 쌓이지 않습니다.
> 로그에 남은 건 이것뿐입니다.
>
> ```
> [backend] AMQPConnectionError: [Errno 111] Connection refused (5672)
> ```
>
> RabbitMQ는 떠 있고, 포트도 열려 있고, 비밀번호도 맞습니다. 같은 서버인데 왜 안 될까요?

### 2-1. 재현 (30초)

```bash
bash demo/setup_demo.sh
```

```
▶ 네트워크 두 개 생성 — demo-net-mq / demo-net-app (서로 분리)
▶ demo-rabbitmq — demo-net-mq 에서 기동, 5672·15672를 0.0.0.0에 공개
▶ demo-backend — demo-net-app 에서 기동 (다른 네트워크!), 접속 주소는 127.0.0.1

재현 완료 — 두 컨테이너는 실행 중이지만 서로 통신할 수 없는 상태입니다.
```

가벼운 `alpine` 컨테이너 2개만 만들고, 이름은 전부 `demo-` 로 시작합니다. 기존 컨테이너는 건드리지 않습니다.

**Docker가 없다면** 저장소에 포함된 실제 사고 스냅샷으로 똑같이 진행할 수 있습니다. 아래 모든 명령에서 컨테이너 이름을 `backend-container`, `rabbitmq`로 바꾸고 `--docker-snapshot examples/rabbitmq-incident/snapshot.json`을 붙이면 됩니다.

### 2-2. 진단 — 이 데모의 핵심

```bash
dockguard diagnose connectivity demo-backend demo-rabbitmq --port 5672
```

```
  검사 과정

  [통과]  1. 두 컨테이너가 존재하고 실행 중인가?
          → demo-backend, demo-rabbitmq 모두 실행 중
          · demo-backend → demo-backend: running (image: alpine:3.20, restart: always)
          · demo-rabbitmq → demo-rabbitmq: running (image: alpine:3.20, restart: unless-stopped)

  [통과]  2. demo-rabbitmq가 5672 포트를 여는가?
          → 5672 포트를 여는 것으로 선언됨
          · demo-rabbitmq 호스트 공개 포트: 0.0.0.0:5672->5672/tcp, 0.0.0.0:15672->15672/tcp

  [실패]  3. 두 컨테이너가 공유하는 네트워크가 있는가?
          → 공유 네트워크 없음 — demo-backend: [demo-net-app] / demo-rabbitmq: [demo-net-mq]
          · demo-backend 네트워크: demo-net-app
          · demo-rabbitmq 네트워크: demo-net-mq
          · 공통: 없음

  [생략]  4. 그 네트워크에서 컨테이너 간 통신이 허용되는가?
          → 공유 네트워크가 없어 판정 불가 — 참고: 기본 bridge는 통신은 되지만 컨테이너 이름 DNS가 없다.

  [실패]  5. demo-backend는 demo-rabbitmq를 어떤 주소로 찾는가?
          → RABBITMQ_HOST가 127.0.0.1 — 컨테이너 안에서 이 주소는 자기 자신을 가리킨다
          · RABBITMQ_HOST=127.0.0.1

┌─ 근본 원인  두 컨테이너가 공유하는 네트워크가 있는가? ─────────────────────────┐
│  네트워크 격리 — 두 컨테이너가 공유하는 Docker 네트워크가 없어 도달할 수 없다  │
│                                                                                │
│  ■ 근거 (실제로 확인한 값)                                                     │
│    demo-backend 네트워크: demo-net-app                                         │
│    demo-rabbitmq 네트워크: demo-net-mq                                         │
│    공통: 없음                                                                  │
│                                                                                │
│  ■ 해결                                                                        │
│    docker network connect demo-net-mq demo-backend        (임시)               │
│    compose의 두 서비스에 같은 networks: 지정                (영구)              │
│                                                                                │
│  ■ 주의사항 / 부작용                                                           │
│   • 임시 연결은 재기동 시 풀린다 → compose에 반영하지 않으면 같은 장애 반복    │
│   • 같은 네트워크면 모든 포트로 통신 가능 → 목적별 네트워크로 나눠라           │
└────────────────────────────────────────────────────────────────────────────────┘

┌─ 추가로 발견된 문제  이것도 고쳐야 연결됩니다 ─────────────────────────────────┐
│  RABBITMQ_HOST=127.0.0.1는 컨테이너 안에서 자기 자신을 가리킨다                │
└────────────────────────────────────────────────────────────────────────────────┘
```

**말할 것 (여기가 하이라이트)**:

1. "제가 며칠 동안 손으로 밟은 순서가 그대로 다섯 단계로 들어가 있습니다."
2. "**통과한 단계도 보여줍니다.** 포트가 열려 있다는 걸 확인했으니 그 방향은 더 안 봐도 됩니다. 무엇이 문제가 *아닌지* 아는 것도 디버깅입니다."
3. "각 줄에 **실제로 확인한 값**이 붙습니다. 도구 말을 그냥 믿는 게 아니라 눈으로 검증할 수 있어야 하니까요."
4. "그리고 **원인이 하나가 아닙니다.** 실제 사고도 그랬습니다. 네트워크만 고치고 재기동하면 또 안 됩니다."

### 2-3. 1차 복구 — 그리고 다시 진단

제시된 명령을 그대로 실행합니다.

```bash
docker network connect demo-net-mq demo-backend
dockguard diagnose connectivity demo-backend demo-rabbitmq --port 5672
```

```
  [통과]  3. 두 컨테이너가 공유하는 네트워크가 있는가?
          → 공유 네트워크: demo-net-mq
  [통과]  4. 그 네트워크에서 컨테이너 간 통신이 허용되는가?
          → demo-net-mq에서 통신 허용

  [실패]  5. demo-backend는 demo-rabbitmq를 어떤 주소로 찾는가?
          → RABBITMQ_HOST가 127.0.0.1 — 컨테이너 안에서 이 주소는 자기 자신을 가리킨다

┌─ 근본 원인  demo-backend는 demo-rabbitmq를 어떤 주소로 찾는가? ────────────────┐
│  RABBITMQ_HOST=127.0.0.1는 컨테이너 안에서 자기 자신을 가리킨다                │
│  ■ 해결   RABBITMQ_HOST: demo-rabbitmq   # 컨테이너 이름으로                   │
└────────────────────────────────────────────────────────────────────────────────┘
```

**말할 것**: "3번은 통과로 바뀌었고, **남아 있던 문제가 근본 원인으로 올라왔습니다.** '고쳤는데 왜 아직 안 되지?'에 도구가 바로 답합니다."

### 2-4. 2차 복구 — 정상 확인

```bash
docker rm -f demo-backend
docker run -d --name demo-backend --network demo-net-mq --restart unless-stopped \
  -e RABBITMQ_HOST=demo-rabbitmq -e RABBITMQ_PORT=5672 alpine:3.20 sleep 3600

dockguard diagnose connectivity demo-backend demo-rabbitmq --port 5672
```

```
  [통과]  5. demo-backend는 demo-rabbitmq를 어떤 주소로 찾는가?
          → 컨테이너 이름으로 접속하도록 설정됨

┌────────────────────────────────────────────────────────────────────────────────┐
│  네트워크 레벨에서는 연결을 막는 원인을 찾지 못했습니다.                       │
│  두 컨테이너는 서로 도달할 수 있는 상태입니다.                                 │
│                                                                                │
│  ■ 다음으로 확인할 것                                                          │
│    1. 애플리케이션이 정말 그 포트를 듣고 있는지: docker exec … ss -tlnp        │
│    3. 인증 실패(비밀번호 · 계정 · vhost)는 이 진단이 잡지 못한다: docker logs  │
│    5. 호스트 방화벽 · iptables DOCKER-USER 체인: sudo iptables -L DOCKER-USER  │
└────────────────────────────────────────────────────────────────────────────────┘
```

**말할 것**: "원인을 못 찾았을 때도 결과입니다. **네트워크는 아니라는 것**과 다음에 볼 곳을 알려 줍니다. 탐색 범위가 절반으로 줍니다."

### 2-5. 재발 방지 — 영구 반영

`docker network connect`는 컨테이너를 다시 만들면 풀립니다. compose에 반영해야 다음 정전에 같은 일이 반복되지 않습니다.

```yaml
services:
  backend:
    networks: [mq-net]
    restart: unless-stopped
    environment:
      RABBITMQ_HOST: rabbitmq        # 호스트 IP가 아니라 서비스 이름으로
  rabbitmq:
    networks: [mq-net]
    restart: unless-stopped
    ports:
      - "127.0.0.1:15672:15672"      # 관리 UI는 루프백에만 (NET-004)
                                     # 5672는 같은 네트워크 컨테이너만 쓰므로 공개하지 않음
networks:
  mq-net:
```

정리합니다.

```bash
bash demo/cleanup_demo.sh
```

> 🎬 **녹화 팁**: 2-2 한 화면이 이 프로젝트의 전부입니다. 터미널을 **110칸**으로 맞추고
> `asciinema rec demo.cast` 로 2-1 ~ 2-4를 한 번에 녹화한 뒤, 2-2의 진단 화면을 GIF로 잘라 README 상단에 넣으세요.

### 2-6. (심화) 사고 전체 재현 — 예방 점검과 함께

위는 컨테이너 2개짜리 최소 재현입니다. **사고 전체**(컨테이너 5개, 재시작 정책이 없어 안 올라온 Redis, 0.0.0.0에 열린 관리 포트)를 재현해 `scan`으로 한 번에 보고 싶다면:

```bash
bash examples/rabbitmq-incident/reproduce.sh
dockguard scan -c network --deps examples/rabbitmq-incident/dependencies.yaml --explain
bash examples/rabbitmq-incident/cleanup.sh
```

![네트워크 진단 결과](images/terminal-network.png)

| 결과 | 의미 |
|------|------|
| **NET-001 취약** `backend-container → rabbitmq:5672` — 공유 네트워크 없음 | 백엔드는 `bridge`, RabbitMQ는 `messaging_mq-net`. 통신 경로 자체가 없습니다 |
| **NET-001 취약** `report-worker → redis:6379` — 실행 중이 아님 | Redis의 재시작 정책이 `no`라 재부팅 후 안 올라왔습니다 |
| **NET-004 취약** RabbitMQ 5672/15672가 `0.0.0.0`에 노출 | 통신 장애와 별개로, 외부에서 직접 접속 가능한 상태입니다 |
| **NET-003 주의** 기본 bridge에 2개가 있지만 `icc: false`로 통신 불가 | 시나리오 1에서 켠 그 설정입니다 |

이 시나리오는 [GitHub Actions E2E 잡](../.github/workflows/ci.yml)에서 **매 커밋마다 실제 Docker로** 재현 · 검증됩니다 — `scan`(Docker SDK 경로와 CLI 폴백 경로 모두)과 `diagnose` 둘 다.

`dependencies.yaml`에 "누가 누구에게 붙어야 하는가"를 선언해 두면, 장애가 나기 전에 정기 점검으로 잡을 수 있습니다.

```yaml
dependencies:
  - from: "backend-container"
    to: "rabbitmq"
    port: 5672
    reason: "백엔드가 RabbitMQ 큐를 소비"
```

```bash
# /etc/cron.d/dockguard — 재부팅 2분 뒤, 그리고 매일 새벽 점검
MAILTO=ops@example.com
@reboot    root sleep 120 && /usr/local/bin/dockguard scan -c network --fail-on critical > /dev/null
30 4 * * *  root /usr/local/bin/dockguard scan -f /srv --fail-on high -o /var/log/dockguard/latest.html > /dev/null
```

---

## 시나리오 3: 학습 — 개념까지 설명한다

```bash
dockguard learn icc
```

개념 → 동작 원리 → **공격 시나리오** → 권장 방법 → **실제 사례** 순으로 나옵니다.
마지막 "실제 사례" 절에는 이 프로젝트가 시작된 그 사고가 적혀 있습니다.

```bash
dockguard learn                 # 주제 11개 목록
dockguard learn COMPOSE-004     # 룰 ID로도 찾을 수 있다 (→ docker-sock)
```

**말할 것**: "리포트를 읽다가 모르는 개념이 나오면 바로 여기서 배웁니다. 저 자신이 배우려고 만든 기능입니다."

> 🎬 **녹화 팁**: 목록 한 화면 + `learn icc`의 '실제 사례' 절만 보여주면 충분합니다. 30초를 넘기지 마세요.

---

## 5분 발표 대본 요약

| 시간 | 할 것 | 한 문장 |
|------|-------|---------|
| 0:00 | 사고 이야기 | "정전 뒤 백엔드가 메시지큐에 못 붙었고, 원인 찾는 데 며칠 걸렸습니다." |
| 0:30 | 시나리오 1 (scan) | "취약점을 찾아 주는 도구는 많습니다. 그런데 **고치면 뭐가 깨지는지**는 아무도 안 알려줍니다." |
| 1:30 | 시나리오 1 (fix) | "9개 중 3개만 자동으로 고칩니다. 자동화가 장애를 만든 경험이 있어서요." |
| 2:00 | **시나리오 2 (diagnose)** | "그때 제가 손으로 밟은 순서를 도구에 넣었습니다." ← **여기에 시간을 쓰세요** |
| 4:00 | 원인이 둘 | "네트워크만 고치면 아직 안 됩니다. 도구가 그걸 알려줍니다." |
| 4:30 | 마무리 | "며칠 걸린 문제를, 다시는 며칠 안 걸리게 만들었습니다." |

## 자주 나오는 질문

**Q. 그냥 `docker exec nc -z` 하면 되지 않나요?**
그 방법은 컨테이너 안에 `nc`가 있어야 하고(distroless 이미지엔 없습니다), 컨테이너에 프로세스를 띄우며, "연결 안 됨"만 알려 줍니다. dockguard는 `docker inspect` 정보만 읽어 **부수효과 없이**, **왜** 안 되는지(네트워크 격리인지 icc인지 주소인지)까지 구분하고, 서버에서 떠 온 스냅샷으로 **오프라인에서도** 같은 진단을 합니다.

**Q. 점수 100점 기준은 뭔가요?**
개선 전후를 비교하기 위한 **상대 지표**입니다. CRITICAL 40 · HIGH 20 · MEDIUM 10 · LOW 3점씩 감점합니다. 절대 평가가 아니라 "고치면 올라간다"를 보여주는 용도입니다.

**Q. 실제로 연결을 시도해 보나요?**
아니요. 네트워크 **경로**가 성립하는지만 봅니다. 비밀번호 불일치, 방화벽(`DOCKER-USER`), 앱이 `127.0.0.1`에만 리스닝하는 경우는 잡지 못하며, 원인을 못 찾으면 그 사실과 다음 확인 사항을 함께 알려 줍니다.

---

관련 문서: [README](../README.md) · [설계 결정 기록](decisions.md) · [HTML 리포트 샘플](sample-report.html)
