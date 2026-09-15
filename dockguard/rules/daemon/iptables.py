"""DAEMON-009: Docker의 iptables 관리 활성화."""

from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import BooleanDaemonRule


@register
class IptablesRule(BooleanDaemonRule):
    id = "DAEMON-009"
    title = "iptables 관리 활성화"
    severity = Severity.MEDIUM
    reference = cis("2.4", "Ensure Docker is allowed to make changes to iptables")

    key = "iptables"
    recommended_value = True
    docker_default = True

    no_autofix_reason = (
        "데몬 재시작 시 Docker 방화벽 규칙이 새로 생성되어 직접 관리하던 규칙과 충돌할 수 있으므로 "
        "수동으로 적용하세요."
    )

    why = """\
`iptables: false`로 설정하면 Docker는 방화벽(iptables) 규칙을 **전혀 만들지 않는다.** 그러면:

- 기본 브리지의 **`icc: false` 차단 규칙이 생성되지 않아** ICC 제한이 무력화된다 (DAEMON-001이 \
통과여도 실제로는 차단되지 않는다).
- 서로 다른 Docker 네트워크 사이의 격리 규칙도 생성되지 않아, 네트워크를 나눠 둔 의미가 사라진다.
- 포트 공개·아웃바운드 NAT를 사람이 직접 관리해야 하는데, 이 과정에서 규칙을 너무 넓게 열어 두는 \
실수가 흔하다.

Docker가 컨테이너 네트워크 규칙을 일관되게 관리하도록 두는 것이 안전하다."""

    how_to_fix = """\
1. `/etc/docker/daemon.json`에서 `"iptables": false`를 제거하거나 `true`로 바꾼다.

```json
{
  "iptables": true
}
```

2. 직접 추가해 두었던 Docker 관련 iptables 규칙이 있다면 목록을 백업해 둔다.

```bash
sudo iptables-save > ~/iptables-before-docker.rules
```

3. Docker 데몬을 재시작한 뒤 규칙이 생성됐는지 확인한다.

```bash
sudo systemctl restart docker
sudo iptables -L DOCKER-USER -n
```"""

    tradeoff = """\
iptables를 켜 둘 때(기본값) 반드시 알아야 할 함정이 있다: **Docker가 만드는 규칙은 UFW 같은 호스트 \
방화벽 규칙보다 먼저 적용된다.** `-p 5672:5672`로 공개한 포트는 `ufw deny 5672`를 해도 외부에서 \
접속된다. 호스트 방화벽만 믿고 RabbitMQ·DB 포트를 열어 두는 사고가 매우 흔하다.

- 외부 노출이 필요 없는 포트는 `127.0.0.1:5672:5672`처럼 루프백에만 바인딩하거나, 아예 공개하지 말고 \
컨테이너 네트워크로만 통신하게 하라 (NET-004 참고).
- 추가 필터링이 필요하면 Docker가 건드리지 않는 `DOCKER-USER` 체인에 규칙을 넣는다.
- `false`→`true`로 바꾸면 재시작 시 Docker 규칙이 새로 생성되므로, 직접 관리하던 규칙과 \
충돌·중복이 없는지 확인하라. 재시작 중에는 모든 컨테이너가 재기동된다(`live-restore` 미사용 시)."""

    learn_more = "https://docs.docker.com/engine/network/packet-filtering-firewalls/"
