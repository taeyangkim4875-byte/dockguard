"""보안 교육 콘텐츠 — `dockguard learn <주제>`로 읽는다.

Finding의 짧은 설명과 별개로 "이 개념이 무엇이고 왜 중요한지"를 깊이 있게 담는다.
각 주제는 개념 → 동작 원리 → 공격 시나리오 → 권장 방법 → 실제 사례 순서로 읽히도록 구성했다.
본문은 Markdown이다 (터미널은 rich, HTML 리포트는 markdown-it으로 렌더링).
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass


@dataclass(frozen=True)
class Topic:
    key: str
    title: str
    summary: str  # 목록에 보이는 한 줄 설명
    concept: str  # 이 개념이 무엇인가
    detail: str  # 동작 원리 (문단 단위 상세 설명)
    attack_scenario: str  # 공격자가 이것을 어떻게 악용하는가
    best_practice: str  # 어떻게 해야 하는가
    real_world: str  # 실제 사례와 교훈
    related_rules: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()

    SECTIONS = (
        ("concept", "개념"),
        ("detail", "동작 원리"),
        ("attack_scenario", "공격 시나리오"),
        ("best_practice", "권장 방법"),
        ("real_world", "실제 사례와 교훈"),
    )


_TOPICS: list[Topic] = [
    Topic(
        key="icc",
        title="ICC — 컨테이너 간 통신",
        summary="기본 bridge 위의 컨테이너끼리 통신을 허용할지 정하는 데몬 설정",
        concept="""\
ICC(Inter-Container Communication)는 Docker **기본 bridge 네트워크(`docker0`)에** 붙은 컨테이너끼리 서로 통신할 수 \
있는지를 정하는 데몬 설정이다. 기본값은 `true`로, 같은 기본 bridge에 있는 컨테이너는 서로의 **모든 포트**에 접속할 수 있다.""",
        detail="""\
Docker는 컨테이너를 만들 때 가상 이더넷 쌍(veth)을 만들어 한쪽은 컨테이너 안에, 다른 쪽은 호스트의 bridge(`docker0`)에 \
꽂는다. 같은 bridge에 꽂힌 컨테이너들은 하나의 스위치에 연결된 PC들처럼 서로 통신한다.

`icc: false`로 설정하면 Docker는 iptables의 FORWARD 체인에 **docker0에서 docker0으로 가는 트래픽을 버리는 규칙**을 넣는다. \
그래서 이 설정은 `iptables: true`(기본값)일 때만 효과가 있다 (DAEMON-009).

중요한 점: **이 설정은 기본 bridge에만 적용된다.** 직접 만든 커스텀 네트워크(`docker network create`, compose의 \
`networks:`)는 영향을 받지 않으며, 같은 커스텀 네트워크 안에서는 항상 통신이 허용된다. 커스텀 네트워크마다 따로 막고 싶다면 \
네트워크 옵션 `com.docker.network.bridge.enable_icc=false`를 쓴다.

또 하나의 한계: iptables 규칙은 **IP 패킷**을 걸러낼 뿐, IP가 아닌 raw 이더넷 프레임(L2)은 막지 못한다. Docker가 컨테이너에 \
기본으로 주는 `NET_RAW` capability가 있으면, `icc: false` 상태에서도 같은 bridge의 컨테이너에 ARP 스푸핑 같은 L2 공격을 \
시도할 수 있다. 이 문제는 docker-bench-security 저장소에서도 "icc를 끄라는 권고가 정말 의미가 있나"라는 논의로 제기된 적이 있다. \
icc는 여러 겹의 방어 중 한 겹일 뿐이다.

기본 bridge와 커스텀 네트워크의 차이도 함께 알아 두자.

| | 기본 bridge (`docker0`) | 커스텀 bridge 네트워크 |
|---|---|---|
| 컨테이너 이름으로 DNS 조회 | 안 됨 (IP로만) | 됨 (내장 DNS 127.0.0.11) |
| icc 설정 | daemon.json의 `icc` | 네트워크별 `enable_icc` |
| 다른 네트워크와의 통신 | — | 기본적으로 격리됨 |""",
        attack_scenario="""\
1. 공격자가 외부에 공개된 웹 컨테이너의 취약점(파일 업로드, 역직렬화 등)으로 셸을 얻는다.
2. 컨테이너 안에서 `172.17.0.0/16` 대역을 스캔한다. 기본 bridge라 같은 호스트의 모든 컨테이너가 보인다.
3. 인증 없이 떠 있는 Redis(6379)를 찾는다. `CONFIG SET dir`/`dbfilename`으로 임의 파일을 쓰거나, 캐시에 담긴 세션 토큰을 훔친다.
4. 기본 계정이 남아 있는 RabbitMQ(5672)에 접속해 큐의 메시지(주문, 개인정보)를 읽거나 조작 메시지를 넣는다.

웹 서버 하나의 취약점이 **데이터 계층 전체의 침해**로 번지는 전형적인 경로다 (→ `dockguard learn lateral-movement`).""",
        best_practice="""\
- 서비스를 **목적별 커스텀 네트워크**로 나누고, 통신이 필요한 서비스만 같은 네트워크에 둔다.
- 기본 bridge는 쓰지 않는다. 그 위에 아무것도 없게 만든 뒤 `icc: false`로 잠가 두면, 실수로 기본 bridge에 붙은 컨테이너가 \
다른 컨테이너를 공격하는 발판이 되지 않는다.
- 외부 인터넷이 필요 없는 백엔드 네트워크는 compose에서 `internal: true`로 만들어 아웃바운드도 막는다.
- raw 소켓이 필요 없는 컨테이너는 `cap_drop: [NET_RAW]`로 L2 공격 경로까지 닫는다 (→ `dockguard learn capabilities`).
- `icc: false`를 적용하기 **전에** 서비스 간 의존성을 선언하고 dockguard로 검증한다 (`dockguard scan --deps`).""",
        real_world="""\
dockguard의 제작자는 RabbitMQ 보안 작업 중 정전으로 서버가 재부팅된 뒤, `icc: false`와 네트워크 분리 때문에 백엔드가 \
RabbitMQ에 접속하지 못해 메시지 소비가 멈추는 장애를 겪었다. 에러는 `Connection refused`뿐이었고, 원인이 데몬 설정이라는 \
것을 찾는 데 가장 오래 걸렸다.

교훈: **보안 설정은 가용성과 함께 설계해야 한다.** icc를 끄는 것은 옳지만, 그 전에 "누가 누구와 통신해야 하는가"가 정리되어 \
있어야 한다. dockguard가 모든 권고에 부작용(tradeoff)을 붙이고 NET-001로 의존성을 검증하는 이유다.""",
        related_rules=("DAEMON-001", "DAEMON-009", "NET-001", "NET-003"),
        aliases=("inter-container-communication",),
    ),
    Topic(
        key="lateral-movement",
        title="측면 이동(Lateral Movement)",
        summary="침해된 컨테이너 하나를 발판으로 옆 컨테이너·호스트로 번지는 공격",
        concept="""\
측면 이동은 공격자가 **처음 들어온 지점에서 다른 시스템으로 옮겨 가는** 단계다. 처음 침해되는 곳은 대개 외부에 노출된 \
웹 서버처럼 가치가 낮은 곳이고, 공격자의 진짜 목표(DB, 메시지큐, 관리 도구, 호스트 자체)는 그 안쪽에 있다. 컨테이너 환경의 \
보안은 "침입을 막는 것"만큼 **"침입이 번지지 않게 하는 것"이** 중요하다.""",
        detail="""\
컨테이너 환경이 측면 이동에 취약해지는 이유는 대부분 **내부를 믿기 때문**이다.

- **평평한 네트워크**: 모든 서비스가 한 네트워크에 있으면 웹 컨테이너에서 DB 포트가 바로 보인다.
- **내부 서비스의 약한 인증**: "외부에서 안 보이니까"라는 이유로 Redis 무인증, RabbitMQ `guest`, 기본 관리자 계정이 남는다.
- **공유된 시크릿**: 여러 서비스가 같은 DB 계정·비밀번호를 쓰면 하나만 털려도 전부 접근된다. 환경변수의 비밀번호는 \
`/proc/<pid>/environ`으로 읽힌다.
- **호스트로 가는 문**: `docker.sock` 마운트, privileged, 호스트 디렉터리 쓰기 마운트는 컨테이너 → 호스트 이동을 한 줄로 만든다.
- **클라우드 메타데이터**: 클라우드 VM에서는 컨테이너가 `169.254.169.254`에 접근해 인스턴스의 권한 토큰을 얻을 수 있다.""",
        attack_scenario="""\
```
[인터넷] → 웹 컨테이너 (RCE)
            │ 같은 네트워크 스캔
            ├→ Redis 6379 (무인증) → 세션 탈취
            ├→ RabbitMQ 5672 (guest) → 큐 메시지 열람·위조
            └→ 모니터링 컨테이너 (docker.sock 마운트)
                  └→ docker run --privileged -v /:/host … → 호스트 root
                        └→ 같은 서버의 모든 서비스 + 다른 서버의 SSH 키
```
각 단계는 개별적으로는 "사소한 설정"이지만, 이어지면 서버 전체가 넘어간다.""",
        best_practice="""\
- **네트워크 분할**: 목적별 네트워크로 나누고, 공격 표면(웹)과 데이터 계층(DB·큐)을 직접 연결하지 않는다.
- **내부 서비스도 인증**: 내부망이라도 기본 계정을 지우고 서비스별 계정·강한 비밀번호를 쓴다.
- **최소 권한**: non-root, `cap_drop: [ALL]`, `read_only`, `no-new-privileges` — 발판이 된 컨테이너에서 할 수 있는 일을 줄인다.
- **호스트로 가는 문 닫기**: docker.sock 마운트와 privileged를 없앤다.
- **탐지**: 컨테이너에서 예상치 못한 내부 스캔이나 새 연결이 생기면 알림을 받는다 (Falco 등).""",
        real_world="""\
모의해킹에서 자주 나오는 흐름은 "외부 서비스 하나 → 내부의 기본 계정"이다. dockguard 제작자도 RabbitMQ 5672/15672가 \
0.0.0.0에 열려 있어 **외부에서 guest 계정으로 접속되는** 사례를 지적받았다. 포트가 외부에 열려 있지 않았더라도, 같은 네트워크의 \
다른 컨테이너가 침해되었다면 똑같이 접근당했을 것이다. 네트워크 차단과 내부 인증은 **둘 다** 필요하다.""",
        related_rules=("DAEMON-001", "NET-002", "NET-003", "NET-004", "COMPOSE-004"),
        aliases=("lateral", "pivot"),
    ),
    Topic(
        key="network-isolation",
        title="네트워크 격리 설계",
        summary="서비스를 신뢰 수준별 네트워크로 나누고, 필요한 통신만 연결하는 방법",
        concept="""\
네트워크 격리는 "누가 누구와 통신해야 하는가"를 먼저 정하고, **그 통신만 가능하도록** 네트워크를 설계하는 것이다. \
Docker에서는 커스텀 네트워크가 격리의 기본 단위다. 서로 다른 네트워크의 컨테이너는 기본적으로 통신할 수 없고, \
한 컨테이너는 여러 네트워크에 동시에 연결될 수 있다.""",
        detail="""\
- **compose 기본 네트워크**: compose는 프로젝트마다 `<프로젝트>_default` 네트워크를 만들고 모든 서비스를 거기에 넣는다. \
편하지만 "모두가 모두와 통신"하는 평평한 구조다.
- **여러 네트워크**: 서비스마다 `networks:`로 필요한 네트워크만 붙인다. 리버스 프록시는 `frontend`와 `app`에, 앱은 `app`과 \
`data`에, DB는 `data`에만 두는 식이다.
- **`internal: true`**: 외부(인터넷)로 나가는 경로가 없는 네트워크. DB·큐 전용 네트워크에 쓰면 침해되더라도 외부로 데이터를 \
빼내기 어렵다.
- **`external: true`**: 다른 compose 프로젝트가 만든 네트워크를 가져다 쓴다. 프로젝트 간 통신(예: 공용 메시지큐)에 쓴다.
- **서비스 이름 DNS**: 같은 커스텀 네트워크 안에서는 서비스 이름(`rabbitmq`)으로 접속한다. 호스트 IP로 접속하는 구성은 \
NAT·방화벽 설정에 따라 재기동 후 갑자기 끊길 수 있다.
- **`ports:` vs `expose:`**: `ports:`는 호스트에 공개(외부 노출), `expose:`는 문서화일 뿐 공개하지 않는다. 같은 네트워크의 \
컨테이너끼리는 둘 다 없어도 통신된다.""",
        attack_scenario="""\
평평한 네트워크에서는 웹 컨테이너가 침해되면 DB·큐·캐시가 모두 한 번에 보인다. 격리된 구조에서는 웹(프록시) 컨테이너가 \
`frontend`와 `app`에만 있으므로 DB가 있는 `data` 네트워크에 도달하려면 **앱 컨테이너를 한 번 더** 침해해야 한다. \
공격 비용이 올라가고, 그 사이에 탐지될 가능성도 커진다.""",
        best_practice="""\
```yaml
services:
  proxy:    { networks: [frontend, app] }
  backend:  { networks: [app, data] }
  rabbitmq: { networks: [data] }
  postgres: { networks: [data] }
networks:
  frontend:
  app:
  data:
    internal: true     # 인터넷으로 나가는 경로 없음
```
- 통신 의존성을 `dependencies.yaml`로 **문서화하고 검증**한다. 격리를 강화할수록 "필요한 통신이 끊기는" 사고 위험도 커지므로, \
설정을 바꿀 때마다 `dockguard scan -c network`로 확인한다.
- 임시로 `docker network connect`한 것은 반드시 compose 파일에 반영한다.""",
        real_world="""\
격리는 잘못 설계하면 **보안 사고 대신 장애**를 만든다. dockguard 제작자의 사고에서 백엔드는 기본 bridge에, RabbitMQ는 \
커스텀 네트워크에 있어 공유 네트워크가 없었고, 정전 후 재기동하자 연결이 끊겼다. 이 도구의 NET-001(서비스 의존성 통신 검증)은 \
"격리는 하되, 필요한 통신은 보장한다"를 기계적으로 확인하기 위해 만들었다.""",
        related_rules=("NET-001", "NET-002", "NET-003", "DAEMON-001", "COMPOSE-008"),
        aliases=("network", "segmentation", "networks"),
    ),
    Topic(
        key="privileged",
        title="privileged 컨테이너",
        summary="격리를 거의 전부 끄는 옵션 — 침해되면 호스트 전체가 넘어간다",
        concept="""\
`--privileged`(compose: `privileged: true`)는 컨테이너에 호스트와 거의 같은 권한을 주는 옵션이다. 원래는 Docker 안에서 \
Docker를 돌리는 것처럼 특수한 용도를 위해 만들어졌지만, "권한 오류를 한 번에 없애는 스위치"로 남용되는 경우가 많다.""",
        detail="""\
privileged를 켜면 다음이 한꺼번에 풀린다.

- **모든 Linux capability** 부여 (`SYS_ADMIN`, `SYS_MODULE`, `NET_ADMIN` 등 → `dockguard learn capabilities`)
- **호스트의 모든 장치** 접근 (`/dev/sda`, `/dev/mem` …)
- **seccomp · AppArmor/SELinux 제한 해제** (→ `dockguard learn seccomp`)
- `/sys`, `/proc`의 일부를 쓰기 가능으로 마운트

즉 네임스페이스로 "보이는 것"만 분리되어 있을 뿐, **할 수 있는 일**은 호스트 root와 거의 같다.""",
        attack_scenario="""\
privileged 컨테이너에서 root를 얻은 공격자는 호스트 디스크를 그대로 마운트한다.
```bash
fdisk -l                    # 호스트 디스크가 보인다
mkdir /mnt/host && mount /dev/sda1 /mnt/host
echo 'ssh-ed25519 AAAA… attacker' >> /mnt/host/root/.ssh/authorized_keys
```
이 밖에도 커널 모듈 로드, cgroup `release_agent`를 이용한 탈출 등 알려진 기법이 모두 가능하다. privileged 컨테이너의 \
침해는 곧 **호스트의 침해**다.""",
        best_practice="""\
- privileged가 **왜** 필요한지부터 확인하고, 필요한 capability나 장치만 준다 (`cap_add`, `devices:`).
- `cap_drop: [ALL]`에서 시작해 에러를 보며 하나씩 추가하는 최소 권한 방식을 쓴다.
- Docker-in-Docker가 필요한 CI는 rootless Docker, Kaniko/Buildah(데몬 없는 빌드), Sysbox 같은 대안을 검토한다.
- 정말 필요한 경우 전용 호스트/VM에 격리하고, 그 호스트에는 다른 서비스를 두지 않는다.""",
        real_world="""\
CI 러너(`docker:dind`)와 모니터링·네트워크 도구가 privileged로 도는 경우가 흔하다. 한 번 켜 둔 privileged는 "지금 잘 돌아가니까" \
잊히기 쉽고, 그 컨테이너의 이미지나 의존성이 오염되는 순간 호스트 전체가 위험해진다. compose 파일에서 privileged를 발견하면 \
**"이것 없이는 정말 안 되는가?"를** 먼저 묻는 습관이 중요하다.""",
        related_rules=("COMPOSE-001", "COMPOSE-010", "DAEMON-006"),
        aliases=("priv",),
    ),
    Topic(
        key="capabilities",
        title="Linux capabilities",
        summary="root의 권한을 조각낸 단위 — 필요한 조각만 주는 것이 최소 권한",
        concept="""\
전통적인 리눅스에서 권한은 "root냐 아니냐" 둘뿐이었다. capability는 root의 권한을 **약 40개의 조각**으로 나눈 것이다. \
예를 들어 1024 미만 포트 바인딩은 `NET_BIND_SERVICE`, 파일 소유자 변경은 `CHOWN`, 파일 시스템 마운트는 `SYS_ADMIN`이다. \
프로세스에 필요한 조각만 주면 root로 실행되더라도 할 수 있는 일이 제한된다.""",
        detail="""\
Docker는 컨테이너에 기본으로 **14개**의 비교적 안전한 capability만 준다: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, \
`SETGID`, `SETUID`, `SETPCAP`, `NET_BIND_SERVICE`, `NET_RAW`, `SYS_CHROOT`, `MKNOD`, `AUDIT_WRITE`, `SETFCAP`.

위험한 것들은 기본에서 빠져 있다.

| capability | 할 수 있는 일 |
|---|---|
| `SYS_ADMIN` | mount, 네임스페이스 조작 등 — "새로운 root"라 불릴 만큼 범위가 넓다 |
| `SYS_MODULE` | 커널 모듈 로드 |
| `SYS_PTRACE` | 다른 프로세스 디버깅(메모리 읽기·쓰기) |
| `DAC_READ_SEARCH` | 파일 읽기 권한 검사 우회 |
| `NET_ADMIN` | 네트워크 인터페이스·라우팅·iptables 변경 |

현재 프로세스의 capability는 컨테이너 안에서 `grep Cap /proc/1/status`로 보고, `capsh --decode=<값>`으로 해석할 수 있다.""",
        attack_scenario="""\
"Shocker" 공격(2014)은 `DAC_READ_SEARCH`가 있으면 `open_by_handle_at()` 시스템 콜로 **컨테이너 밖 호스트 파일**을 열 수 \
있다는 점을 이용했다. 이 일 이후 Docker는 이 capability를 기본 목록에서 뺐다. 이처럼 capability 하나가 곧 탈출 경로가 될 수 \
있다. `SYS_ADMIN`이 있으면 cgroup·mount를 이용한 탈출 기법의 문이 열린다.""",
        best_practice="""\
```yaml
services:
  web:
    cap_drop: [ALL]               # 전부 뺀 뒤
    cap_add: [NET_BIND_SERVICE]   # 필요한 것만
```
- 엔트리포인트에서 권한을 내리는(gosu) 이미지는 `SETUID`, `SETGID`, `CHOWN`이 필요할 수 있다. 에러를 보며 하나씩 추가한다.
- non-root 사용자 + `no-new-privileges`와 함께 쓰면 효과가 커진다 (파일 capability로 권한을 다시 얻는 경로까지 막힘).
- 위험한 capability가 꼭 필요하면 이유를 compose 파일에 주석으로 남긴다.""",
        real_world="""\
"권한 오류가 나서 일단 `SYS_ADMIN`을 넣었다"는 compose 파일이 흔하다. 실제로 필요한 것은 대개 훨씬 좁은 권한이다 \
(예: FUSE 마운트는 `SYS_ADMIN` 대신 호스트에서 마운트 후 볼륨으로 전달). capability 목록은 **코드 리뷰 대상**으로 다뤄야 한다.""",
        related_rules=("COMPOSE-010", "COMPOSE-001", "COMPOSE-003", "DAEMON-002"),
        aliases=("caps", "capability", "cap"),
    ),
    Topic(
        key="seccomp",
        title="seccomp 시스템 콜 필터",
        summary="컨테이너가 호출할 수 있는 커널 기능을 제한하는 마지막 방어선",
        concept="""\
seccomp(secure computing mode)은 프로세스가 호출할 수 있는 **리눅스 시스템 콜을 제한**하는 커널 기능이다. 컨테이너는 \
결국 호스트 커널을 공유하므로, 커널에 닿는 입구(시스템 콜)를 줄이는 것은 커널 취약점 공격을 막는 가장 직접적인 방법이다.""",
        detail="""\
Docker는 모든 컨테이너에 **기본 seccomp 프로파일**을 적용한다. 300개가 넘는 시스템 콜 중 컨테이너에 필요 없고 위험한 \
약 44개(`mount`, `reboot`, `kexec_load`, `init_module`, `keyctl`, `unshare`, `bpf` 등)를 막는다.

- 프로파일은 JSON이다. 기본 동작(`defaultAction`)을 "거부"로 두고 허용할 시스템 콜을 나열하는 **허용 목록** 방식이다.
- 컨테이너 안에서 `grep Seccomp /proc/1/status`의 값이 `2`면 필터가 적용된 상태다.
- `docker info`의 Security Options에 `seccomp,profile=builtin`이 보이면 기본 프로파일이 쓰이고 있는 것이다.
- 컨테이너별로는 `security_opt: [seccomp:<파일>]`, 데몬 전체는 daemon.json의 `seccomp-profile`로 바꾼다.""",
        attack_scenario="""\
커널 권한 상승 취약점의 상당수는 특정 시스템 콜을 통해 커널의 버그를 건드린다. 예를 들어 `keyctl`을 이용한 CVE-2016-0728, \
`unshare`로 사용자 네임스페이스를 만든 뒤 파일시스템 코드의 버그를 건드리는 CVE-2022-0185 같은 취약점은 **Docker 기본 seccomp \
프로파일이 필요한 시스템 콜을 막아** 기본 설정의 컨테이너에서는 악용이 어려웠다. `seccomp=unconfined`인 컨테이너에서는 이 \
보호가 사라진다.""",
        best_practice="""\
- 데몬이든 컨테이너든 `unconfined`를 쓰지 않는다.
- 특정 시스템 콜이 필요한 컨테이너는 Docker 기본 프로파일을 받아 **그 시스템 콜만 추가한** 커스텀 프로파일을 그 컨테이너에만 적용한다.
- 디버깅(`strace`, `gdb`)을 위해 푼 설정은 디버깅이 끝나면 되돌린다. 운영과 디버깅 설정을 compose override로 분리하면 실수가 줄어든다.""",
        real_world="""\
"strace가 안 돼서", "어떤 라이브러리가 Operation not permitted를 내서" seccomp를 통째로 끄는 경우가 많다. 문제는 그 설정이 \
운영까지 따라간다는 것이다. 에러가 난 시스템 콜 하나만 허용하면 되는 일을, 300개 전부를 여는 것으로 해결하지 말자.""",
        related_rules=("DAEMON-008",),
        aliases=("seccomp-profile", "syscall"),
    ),
    Topic(
        key="userns-remap",
        title="user namespace remapping",
        summary="컨테이너의 root를 호스트의 일반 사용자로 바꿔 주는 설정",
        concept="""\
기본 설정에서 컨테이너 안의 root(uid 0)는 **호스트의 root(uid 0)와 같은 사용자**다. user namespace remapping은 컨테이너 안의 \
uid를 호스트의 **다른(권한 없는) uid 범위**로 매핑한다. 컨테이너 안에서는 root처럼 보이지만, 호스트에서 보면 아무 권한 없는 \
일반 사용자다.""",
        detail="""\
`"userns-remap": "default"`를 설정하면 Docker는 `dockremap` 사용자를 만들고, `/etc/subuid` · `/etc/subgid`에 uid 범위를 할당한다.

```
# /etc/subuid
dockremap:231072:65536
```
이제 컨테이너의 uid 0 → 호스트 uid 231072, 컨테이너의 uid 1000 → 호스트 uid 232072로 매핑된다.

알아 둘 동작:

- Docker는 **별도 데이터 디렉터리**(`/var/lib/docker/231072.231072/`)를 쓴다. 켜는 순간 기존 이미지·컨테이너·볼륨이 보이지 않는다.
- 바인드 마운트한 호스트 파일은 매핑된 uid로 접근하므로 소유권을 맞춰야 한다.
- `--privileged`, `--network=host`, `--pid=host`는 컨테이너별로 `--userns=host`를 지정해야 쓸 수 있다.""",
        attack_scenario="""\
runc 취약점 CVE-2019-5736은 컨테이너 안의 root가 호스트의 `runc` 바이너리를 덮어써, 다음 번 `docker exec` 때 **호스트 root로 \
코드를 실행**하게 만드는 탈출 공격이었다. 호스트의 root가 컨테이너 안에 매핑되지 않는 user namespace 환경에서는 컨테이너의 \
root가 호스트 파일을 덮어쓸 권한이 없어 공격이 막힌다. 컨테이너 탈출 취약점은 앞으로도 나올 것이고, userns는 **탈출하더라도 \
피해를 줄이는** 방어다.""",
        best_practice="""\
- 새로 구축하는 호스트라면 처음부터 켜는 것이 가장 쉽다 (데이터 이전 부담이 없음).
- 운영 중인 호스트라면: 볼륨 백업 → 설정 → 이미지 재다운로드 → 볼륨 복원·소유권 변경 순서로 계획을 세운다.
- 데몬 자체까지 일반 사용자로 돌리고 싶다면 rootless 모드를 검토한다 (→ `dockguard learn rootless`).""",
        real_world="""\
userns-remap을 켰다가 "이미지와 볼륨이 전부 사라졌다"며 놀라는 경우가 많다. 실제로는 다른 디렉터리를 보고 있을 뿐이지만, \
상태가 있는 서비스(RabbitMQ 계정·큐, DB)를 백업 없이 다시 띄우면 **정말로 새 빈 볼륨으로 시작**하게 된다. dockguard 제작자가 \
`docker compose down`으로 RabbitMQ 볼륨이 초기화되는 사고를 겪었듯, 데이터 위치가 바뀌는 작업은 항상 백업부터 한다. \
dockguard가 이 항목을 자동 수정하지 않는 이유다.""",
        related_rules=("DAEMON-006", "COMPOSE-002"),
        aliases=("userns", "user-namespace", "user-namespaces"),
    ),
    Topic(
        key="rootless",
        title="rootless Docker",
        summary="Docker 데몬 자체를 일반 사용자로 실행하는 모드",
        concept="""\
rootless 모드는 **Docker 데몬(`dockerd`)과 컨테이너를 모두 일반 사용자 권한으로** 실행한다. userns-remap은 컨테이너의 root만 \
바꿀 뿐 데몬은 여전히 root로 돌지만, rootless에서는 데몬이 침해되더라도 공격자가 얻는 것은 그 사용자의 권한뿐이다.""",
        detail="""\
- user namespace(rootlesskit)로 데몬과 컨테이너를 사용자 권한 안에 가둔다.
- 설정 파일은 `~/.config/docker/daemon.json`, 데이터는 `~/.local/share/docker`에 있다. 소켓은 `$XDG_RUNTIME_DIR/docker.sock`.
- 네트워크는 slirp4netns나 pasta 같은 사용자 공간 네트워크를 쓴다.

제약도 있다.

- 1024 미만 포트는 기본적으로 바인딩할 수 없다 (`net.ipv4.ip_unprivileged_port_start` 조정 필요).
- 리소스 제한(cgroup)은 cgroup v2 + systemd 환경에서만 제대로 동작한다.
- AppArmor를 쓸 수 없고, 네트워크 성능이 root 모드보다 낮을 수 있다.
- overlay 스토리지 드라이버는 커널 버전에 따라 제약이 있다.""",
        attack_scenario="""\
root 모드 Docker에서는 **docker 그룹에 속한 사용자 = root**다. docker 그룹 사용자는 `docker run -v /:/host`로 호스트 전체를 \
마운트할 수 있기 때문이다. 개발자 편의로 docker 그룹에 넣어 둔 계정 하나가 탈취되면 서버가 넘어간다. rootless 모드에서는 \
각 사용자가 자기 데몬을 가지므로 이 경로가 사라진다.""",
        best_practice="""\
```bash
# 설치 (Docker 공식 스크립트)
dockerd-rootless-setuptool.sh install
systemctl --user enable --now docker
sudo loginctl enable-linger $USER     # 로그아웃 후에도 데몬 유지
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock
```
- 단일 서비스 서버, CI 러너처럼 root 모드 전용 기능이 필요 없는 곳부터 적용한다.
- docker 그룹 멤버를 정기적으로 점검한다: `getent group docker`""",
        real_world="""\
"sudo 치기 귀찮아서" 개발자를 docker 그룹에 넣는 것은 매우 흔하지만, 이는 사실상 root 권한을 나눠 주는 것이다. dockguard도 \
Docker 소켓 권한이 없을 때 docker 그룹 추가 대신 sudo를 먼저 안내하고, 그룹 추가의 의미를 함께 경고한다.""",
        related_rules=("DAEMON-006", "DAEMON-007"),
        aliases=("rootless-mode", "docker-group"),
    ),
    Topic(
        key="docker-sock",
        title="docker.sock의 위험",
        summary="Docker API 소켓 — 이것에 접근할 수 있으면 호스트 root와 같다",
        concept="""\
`/var/run/docker.sock`은 Docker CLI가 데몬과 대화하는 **Unix 소켓(Docker Engine API)이다.** `docker ps`, `docker run` 같은 명령은 \
모두 이 소켓으로 HTTP 요청을 보낸다. 데몬은 root로 돌기 때문에, 이 소켓에 요청을 보낼 수 있다는 것은 **root 권한으로 \
무엇이든 실행할 수 있다**는 뜻이다.""",
        detail="""\
- 소켓의 기본 권한은 `root:docker`, `660`이다. 즉 root와 docker 그룹이 접근할 수 있다.
- 컨테이너에 소켓을 마운트하면 그 컨테이너가 Docker API를 쓸 수 있다. **`:ro`로 마운트해도** 소켓 파일을 지우지 못할 뿐, API 호출은 \
그대로 된다.
- 데몬을 TCP로 여는 경우(`-H tcp://0.0.0.0:2375`)는 더 위험하다. TLS 없는 2375 포트는 **인증 없는 원격 root 셸**과 같다.""",
        attack_scenario="""\
소켓이 마운트된 컨테이너가 침해되면:
```bash
# 컨테이너 안에서 (docker CLI가 없어도 curl로 가능)
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host \\
  -v /:/host alpine chroot /host
```
공격자는 호스트 root 셸을 얻는다. 인터넷에 열린 2375 포트는 자동화된 봇이 끊임없이 찾아다니며, 발견되면 암호화폐 채굴 \
컨테이너가 심어지는 사례가 많이 보고되어 있다.""",
        best_practice="""\
- 소켓 마운트를 없앤다. 꼭 필요하면 **소켓 프록시**(허용한 API만 통과)를 두고, 프록시는 내부 네트워크에만 둔다.
- Docker API를 원격으로 열어야 한다면 TLS 클라이언트 인증서를 쓰는 2376만 연다. 2375는 절대 열지 않는다.
- docker 그룹 멤버를 최소화한다 (→ `dockguard learn rootless`).
- CI에서 이미지를 빌드해야 한다면 Kaniko·Buildah처럼 데몬 없이 빌드하는 도구를 검토한다.""",
        real_world="""\
Traefik, Portainer, Watchtower처럼 소켓을 요구하는 도구는 설치 문서가 소켓 마운트를 기본으로 안내한다. 그래서 "공식 문서대로 했다"는 \
구성에서 소켓 마운트가 가장 흔하게 발견된다. 도구가 실제로 쓰는 API가 "컨테이너 목록 조회"뿐이라면 소켓 프록시로 그것만 허용하자.""",
        related_rules=("COMPOSE-004", "DAEMON-007", "NET-004"),
        aliases=("docker.sock", "docker-socket", "socket"),
    ),
    Topic(
        key="secrets-management",
        title="시크릿 관리",
        summary="비밀번호·토큰을 저장소와 이미지에 남기지 않고 한 곳에서 관리하는 방법",
        concept="""\
시크릿은 비밀번호, API 토큰, 인증서 키처럼 **노출되면 곧바로 권한이 넘어가는 값**이다. 시크릿 관리의 목표는 세 가지다. \
(1) 저장소·이미지·로그에 남기지 않는다, (2) 필요한 곳에만 전달한다, (3) 한 곳에서 관리해 교체(rotation)가 쉽게 한다.""",
        detail="""\
Docker 환경에서 시크릿을 다루는 방법을 안전한 순서로 나열하면:

| 방법 | 노출 위험 |
|---|---|
| compose 파일에 평문 | git에 영원히 남음 — **금지** |
| `.env` 파일 + `${VAR}` | 저장소에서는 빠지지만 `docker inspect` · `/proc/<pid>/environ`으로 보임 |
| Docker secrets (`/run/secrets/…`) | 컨테이너 안의 파일로만 전달, 환경변수에 안 남음 |
| 외부 시크릿 저장소 (Vault, 클라우드 Secret Manager) | 접근 제어·감사 로그·자동 교체 |

환경변수가 생각보다 널리 퍼진다는 점을 기억하자. 자식 프로세스에 상속되고, 에러 리포트·크래시 덤프·디버그 로그에 찍히며, \
`docker inspect` 권한이 있는 사람은 누구나 볼 수 있다. git 기록에 한 번 들어간 값은 파일을 지워도 `git log -p`로 되살아난다.""",
        attack_scenario="""\
1. 사내 저장소가 실수로 public 전환되거나, 외주 인력·퇴사자의 저장소 접근 권한이 남아 있다.
2. 공격자는 gitleaks·trufflehog 같은 도구로 전체 git 기록에서 `PASSWORD=`, `TOKEN=` 패턴을 찾는다.
3. 발견한 RabbitMQ·DB 비밀번호로 내부 서비스에 접속한다. 비밀번호를 여러 서비스가 공유했다면 피해가 번진다.""",
        best_practice="""\
- compose에는 `${VAR}`만 쓰고, 값은 `.env`(권한 `600`, `.gitignore`에 추가)나 Docker secrets로 옮긴다.
- 공식 이미지의 `*_FILE` 변수(`POSTGRES_PASSWORD_FILE` 등)를 활용하면 secrets 파일을 바로 쓸 수 있다.
- 값이 필요한 서비스를 모두 같은 출처에서 읽게 해 **불일치를 없앤다.**
- 한 번이라도 커밋된 시크릿은 **즉시 교체**한다. 기록 삭제보다 교체가 먼저다.
- pre-commit에 gitleaks 같은 검사를 넣어 커밋 전에 막는다.""",
        real_world="""\
dockguard 제작자의 사고에서는 서비스 매니저와 백엔드가 RabbitMQ 비밀번호를 각자 따로 갖고 있어, 계정을 다시 만든 뒤 한쪽만 \
맞춰 **인증이 실패**했다. 시크릿이 여러 파일에 흩어져 있으면 보안 문제일 뿐 아니라 운영 문제도 된다. 한 곳에서 관리하면 둘 다 해결된다.""",
        related_rules=("COMPOSE-005",),
        aliases=("secrets", "secret", "password", "env"),
    ),
    Topic(
        key="port-exposure",
        title="포트 공개와 방화벽 우회",
        summary="compose의 ports:로 공개한 포트는 UFW를 우회해 외부에 열린다",
        concept="""\
`ports: ["5672:5672"]`는 컨테이너 포트를 **호스트의 모든 인터페이스(0.0.0.0)에** 공개한다. 많은 사람이 "UFW로 막았으니 괜찮다"고 \
생각하지만, Docker가 연 포트는 **호스트 방화벽 규칙보다 먼저 처리되어** 외부에서 그대로 접속된다.""",
        detail="""\
Docker는 포트를 공개할 때 iptables의 `nat` 테이블(DOCKER 체인)에 목적지 주소 변환(DNAT) 규칙을 넣는다. 외부에서 들어온 패킷은 \
라우팅 전에 컨테이너 IP로 주소가 바뀌어 **FORWARD 체인**으로 가는데, UFW의 허용/차단 규칙은 주로 호스트 자신으로 들어오는 \
**INPUT 체인**에 있다. 그래서 `ufw deny 5672`가 컨테이너로 가는 트래픽에는 적용되지 않는다.

제대로 막는 방법:

- `127.0.0.1:5672:5672`처럼 **바인딩 주소를 지정**한다.
- daemon.json의 `"ip": "127.0.0.1"`로 **기본 바인딩 주소 자체를 루프백**으로 바꾼다 (IP를 적지 않은 `ports:`가 전부 루프백에만 열림).
- 외부 접근 제어는 Docker가 건드리지 않는 **`DOCKER-USER` 체인**에 넣는다 (반드시 `-i <외부 인터페이스>`와 함께).""",
        attack_scenario="""\
Shodan 같은 검색 엔진은 인터넷 전체를 스캔해 5672(RabbitMQ), 6379(Redis), 27017(MongoDB), 9200(Elasticsearch) 같은 포트가 열린 \
서버를 색인한다. 공격자는 이 목록에서 기본 계정이나 무인증 서비스를 골라 접속한다. 컨테이너로 띄운 RabbitMQ는 설정에 따라 \
`guest` 계정의 원격 로그인이 허용되어 있을 수 있으므로, 포트가 열려 있다면 반드시 직접 확인하고 guest를 삭제해야 한다.""",
        best_practice="""\
- 같은 호스트의 컨테이너끼리만 쓰는 포트는 **공개하지 않는다** (같은 네트워크면 `ports:` 없이 서비스 이름으로 접속됨).
- 호스트에서만 쓰는 관리 UI는 `127.0.0.1`에 바인딩하고 SSH 터널로 접속한다: `ssh -L 15672:127.0.0.1:15672 server`
- 다른 서버가 접속해야 하면 `DOCKER-USER` 체인에서 허용할 대역만 연다.
- 외부 스캔으로 확인한다: 다른 네트워크에서 `nmap -p 5672,15672,6379 <서버 IP>`""",
        real_world="""\
dockguard 제작자는 모의해킹에서 RabbitMQ 5672/15672 포트가 0.0.0.0에 열려 있어 **외부에서 guest 계정으로 접속당한** 사례를 \
지적받았다. 이 경험이 NET-004(민감 포트 외부 노출 점검)와 DAEMON-009의 UFW 우회 경고로 이어졌다.""",
        related_rules=("NET-004", "DAEMON-009", "COMPOSE-012"),
        aliases=("ports", "ufw", "firewall", "exposure"),
    ),
]

EXPLANATIONS: dict[str, Topic] = {t.key: t for t in _TOPICS}

_ALIASES: dict[str, str] = {alias: t.key for t in _TOPICS for alias in t.aliases}


def get_topic(query: str) -> Topic | None:
    """주제 키, 별칭, 또는 룰 ID로 주제를 찾는다 (대소문자 무관)."""
    q = query.strip().lower()
    if q in EXPLANATIONS:
        return EXPLANATIONS[q]
    if q in _ALIASES:
        return EXPLANATIONS[_ALIASES[q]]
    return topic_for_rule(query.strip().upper())


def topic_for_rule(rule_id: str) -> Topic | None:
    """룰과 가장 관련 깊은 주제 (related_rules의 첫 순서가 가까운 주제 우선)."""
    matches = [(t.related_rules.index(rule_id), t) for t in _TOPICS if rule_id in t.related_rules]
    return min(matches, key=lambda m: m[0])[1] if matches else None


def suggest_topics(query: str, limit: int = 3) -> list[str]:
    candidates = list(EXPLANATIONS) + list(_ALIASES)
    found = difflib.get_close_matches(query.strip().lower(), candidates, n=limit, cutoff=0.4)
    return list(dict.fromkeys(_ALIASES.get(c, c) for c in found))
