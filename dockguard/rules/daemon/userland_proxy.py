"""DAEMON-003: userland-proxy 비활성화."""

from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import BooleanDaemonRule


@register
class UserlandProxyRule(BooleanDaemonRule):
    id = "DAEMON-003"
    title = "userland-proxy 비활성화"
    severity = Severity.MEDIUM
    reference = cis("2.16", "Ensure Userland Proxy is Disabled")

    key = "userland-proxy"
    recommended_value = False
    docker_default = True

    no_autofix_reason = (
        "포트 공개 방식(IPv6·hairpin NAT 접속)이 바뀌어 기존 접속 경로가 끊길 수 있으므로 "
        "영향을 확인한 뒤 수동으로 적용하세요."
    )

    why = """\
Docker가 컨테이너 포트를 호스트에 공개(`-p 8080:80`)하는 방법은 두 가지다. 하나는 커널의 \
iptables NAT 규칙이고, 다른 하나는 `docker-proxy`라는 **사용자 공간(userland) 프로세스**다. \
기본값(`userland-proxy: true`)에서는 공개 포트마다 root 권한의 `docker-proxy` 프로세스가 하나씩 떠서, \
주로 호스트 자신(localhost)에서 들어오는 연결을 컨테이너로 중계한다.

- 공개 포트 수만큼 **root 권한 네트워크 프로세스**가 늘어나 공격 표면이 커진다.
- 포트를 범위로 대량 공개하면(`-p 10000-20000:10000-20000`) 수천 개의 프로세스가 생겨 메모리를 낭비한다.
- 대부분의 트래픽은 커널 NAT만으로 처리할 수 있으므로, CIS 벤치마크는 이 프록시를 끄도록 권장한다."""

    how_to_fix = """\
1. `/etc/docker/daemon.json`에 추가한다.

```json
{
  "userland-proxy": false
}
```

2. Docker 데몬을 재시작한다. 이미 떠 있던 컨테이너는 재시작해야 반영된다.

```bash
sudo systemctl restart docker
```

3. 반영 여부를 확인한다 (출력이 없어야 한다).

```bash
ps -ef | grep '[d]ocker-proxy'
```"""

    tradeoff = """\
- **IPv6 localhost 접속이 실패할 수 있다.** 컨테이너에 IPv6 주소가 없는데 호스트에서 `::1`로 \
(또는 `localhost`가 `::1`로 해석되는 환경에서) 공개 포트에 접속하면, 이를 IPv4로 중계하던 \
docker-proxy가 없어져 연결이 거부된다. 접속 주소를 `127.0.0.1`로 명시하라.
- **호스트 IP + 공개 포트로 컨테이너끼리 접속하던 구성(hairpin NAT)은** 커널·방화벽 설정에 따라 \
동작이 달라질 수 있다. `RABBITMQ_HOST=<서버 IP>`처럼 호스트 주소로 다른 컨테이너에 접속하고 있다면, \
같은 Docker 네트워크에 두고 서비스 이름(`rabbitmq`)으로 접속하도록 바꾸는 것이 근본 해결이다.
- `iptables: false`와 함께 끄면 포트를 공개할 수단이 사라져 공개 포트가 동작하지 않는다 (DAEMON-009 참고).
- 데몬 재시작이 필요하므로 `live-restore`가 꺼져 있다면 모든 컨테이너가 재기동된다."""

    learn_more = "https://docs.docker.com/engine/network/packet-filtering-firewalls/"
