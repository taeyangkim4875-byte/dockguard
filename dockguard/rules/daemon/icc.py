"""DAEMON-001: ICC(컨테이너 간 통신) 제한."""

from dockguard.core.models import ApplyMethod, FixRisk, Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import BooleanDaemonRule


@register
class IccRule(BooleanDaemonRule):
    id = "DAEMON-001"
    title = "ICC(컨테이너 간 통신) 제한"
    severity = Severity.MEDIUM
    reference = cis("2.2", "Ensure network traffic is restricted between containers on the default bridge")

    key = "icc"
    recommended_value = False
    docker_default = True

    # 부작용(서비스 간 통신 단절)이 커서 `--rule DAEMON-001`로 명시해야만 자동 수정한다
    fix_risk = FixRisk.RISKY
    apply_with = ApplyMethod.RESTART
    fix_note = (
        "기본 브리지(bridge)에서 서로 통신하던 컨테이너들의 연결이 데몬 재시작 즉시 끊깁니다. "
        "백엔드↔메시지큐, 앱↔DB처럼 통신이 필요한 서비스를 먼저 같은 커스텀 네트워크로 옮겼는지 확인하세요. "
        "(`docker network inspect bridge`로 기본 브리지에 붙은 컨테이너를 확인할 수 있습니다)"
    )

    why = """\
Docker의 기본 브리지 네트워크(`docker0`)에 연결된 컨테이너들은 기본값(`icc: true`)에서 서로의 \
**모든 포트**로 자유롭게 통신할 수 있다. 서로 무관한 서비스라도 같은 기본 브리지에 있기만 하면 \
네트워크상으로 완전히 열려 있는 셈이다.

이 상태에서 컨테이너 하나(예: 외부에 노출된 웹 서버)가 취약점으로 침해되면, 공격자는 그 컨테이너를 \
발판으로 같은 브리지의 DB·메시지큐·캐시에 직접 접속을 시도할 수 있다. 이것을 \
**측면 이동**(lateral movement)이라 부른다. 내부 서비스는 "어차피 외부에서 안 보인다"는 이유로 \
기본 계정(RabbitMQ `guest`, 인증 없는 Redis 등)이 남아 있는 경우가 많아 피해가 커진다.

`icc: false`로 설정하면 Docker가 iptables 규칙으로 기본 브리지 내부의 컨테이너 간 트래픽을 차단한다. \
이후에는 명시적으로 같은 네트워크에 둔 서비스끼리만 통신할 수 있다."""

    how_to_fix = """\
1. **적용 전에** 기본 브리지(`bridge`)에 붙어 서로 통신하던 컨테이너가 있는지 확인하고, \
그런 서비스는 커스텀 네트워크로 옮긴다.

```bash
docker network inspect bridge --format '{{range .Containers}}{{.Name}} {{end}}'
docker network create app-net
docker network connect app-net backend
docker network connect app-net rabbitmq
```

2. `/etc/docker/daemon.json`에 다음 항목을 추가한다 (파일이 없으면 새로 만든다).

```json
{
  "icc": false
}
```

3. Docker 데몬을 재시작한다 (`icc`는 재시작해야 반영된다).

```bash
sudo systemctl restart docker
```"""

    tradeoff = """\
**`icc: false`는 기본 브리지 위의 모든 컨테이너 간 통신을 끊는다.** 백엔드↔메시지큐, 앱↔DB처럼 \
서로 통신해야 하는 서비스가 기본 브리지에 있었다면, 데몬 재시작 직후부터 연결이 실패한다. \
에러는 보통 `Connection refused`나 타임아웃으로만 나타나서, 원인이 데몬 설정이라는 걸 떠올리기 어렵다.

- 통신이 필요한 서비스는 **반드시 같은 커스텀 네트워크**(`docker network create` 또는 compose의 \
`networks:`)에 두어야 한다. 커스텀 브리지 네트워크 안에서는 `icc` 설정과 무관하게 통신이 허용되고, \
컨테이너 이름으로 DNS 조회도 된다.
- 한 서비스는 기본 브리지에, 다른 서비스는 커스텀 네트워크에 있으면 두 컨테이너는 \
**공유하는 네트워크가 없어** 통신할 수 없다.
- `docker network connect`로 임시 연결한 것은 컨테이너를 재생성하면 풀린다. compose 파일의 \
`networks:`에 영구 반영해야 한다.
- 컨테이너끼리 호스트의 외부 IP로 접속하는 방식(예: `RABBITMQ_HOST=<서버 IP>`)은 NAT·iptables·\
userland-proxy 설정에 따라 동작이 달라져 재기동 후 갑자기 끊길 수 있다. 같은 네트워크에 두고 \
서비스 이름(`rabbitmq`)으로 접속하는 것이 안전하다.
- 레거시 `--link` 옵션으로 개별 허용도 가능하지만 deprecated 기능이므로 권장하지 않는다.
- **`icc: false`만으로 완전히 격리되지는 않는다.** 이 설정은 IP 트래픽을 막는 iptables 규칙이라 IP가 아닌 \
raw 이더넷 프레임(L2)은 막지 못한다. 컨테이너에 기본으로 주어지는 `NET_RAW` capability가 있으면 같은 bridge의 \
다른 컨테이너에 ARP 스푸핑 같은 L2 공격을 시도할 수 있다. 목적별 커스텀 네트워크로 나누고, raw 소켓이 필요 없는 \
컨테이너에는 `cap_drop: [NET_RAW]`(또는 `ALL`)를 함께 적용하라 (COMPOSE-010).

> **실제 사례:** dockguard의 제작 배경이 된 사고에서, 정전으로 서버가 재부팅되자 `icc: false`와 \
네트워크 분리 때문에 백엔드가 RabbitMQ에 접속하지 못해 메시지 소비가 멈췄다. 설정 자체는 \
'보안 강화'였지만 서비스 간 네트워크 구성을 함께 점검하지 않아 장애로 이어졌다. 보안과 가용성은 \
함께 봐야 한다 — dockguard의 네트워크 의존성 검증(NET-001)이 바로 이 상황을 잡아내기 위한 기능이다."""

    learn_more = "https://docs.docker.com/engine/network/drivers/bridge/"
