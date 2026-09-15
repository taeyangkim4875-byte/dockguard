"""COMPOSE-008: 호스트 네트워크 모드 검토.

실무에서 정당하게 쓰는 경우(성능, 멀티캐스트, 일부 모니터링·GPU 서비스)가 많으므로 '취약'이 아니라
'주의'로 판정하고, 필요성을 검토하라는 톤으로 안내한다.
"""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, yaml_snippet


@register
class HostNetworkRule(ComposeRule):
    id = "COMPOSE-008"
    title = "호스트 네트워크 모드 검토"
    severity = Severity.MEDIUM
    reference = cis("5.10", "Ensure that the host's network namespace is not shared")
    recommended = "필요한 경우만 host, 그 외 브리지 네트워크 + ports"

    why = """\
`network_mode: host`는 컨테이너가 **호스트의 네트워크 스택을 그대로 공유**하게 한다. 컨테이너 네트워크 격리가 \
없어지므로:

- 컨테이너가 여는 모든 포트가 `ports:` 설정과 무관하게 **호스트의 모든 인터페이스에 바로 열린다.** 개발용 \
디버그 포트나 관리 포트가 의도치 않게 외부에 노출되기 쉽다.
- 컨테이너가 호스트의 `localhost`에만 열어 둔 서비스(DB, 관리 API)에 접근할 수 있다.
- Docker 네트워크의 격리와 서비스 이름 기반 DNS를 쓸 수 없어, 네트워크 설계(DAEMON-001, NET-001)의 \
보호를 받지 못한다.

다만 **정당한 사용처가 많다.** 대량 트래픽의 NAT 오버헤드 제거, 멀티캐스트/브로드캐스트가 필요한 서비스, \
호스트 네트워크를 관찰하는 모니터링 에이전트 등이다. 그래서 dockguard는 이 항목을 금지가 아니라 **"필요성을 \
검토하라"**는 주의로 표시한다."""

    how_to_fix = """\
1. 이 서비스가 host 네트워크를 **왜** 쓰는지 확인한다. 이유가 명확하고 문서화되어 있다면 유지해도 된다. \
그 경우 컨테이너가 여는 포트를 `ss -tlnp`로 확인하고, 불필요한 포트는 애플리케이션 설정에서 닫거나 \
`127.0.0.1`에만 바인딩하라.

2. 특별한 이유가 없다면 브리지 네트워크로 바꾸고 필요한 포트만 공개한다.

```yaml
services:
  app:
    # network_mode: host   ← 삭제
    networks: [app-net]
    ports:
      - "127.0.0.1:8080:8080"   # 외부 공개가 필요 없으면 루프백에만
networks:
  app-net:
```"""

    tradeoff = """\
- 브리지로 바꾸면 컨테이너가 **호스트의 `localhost` 서비스에 더 이상 `127.0.0.1`로 접근할 수 없다.** 호스트 \
서비스에 접근해야 한다면 `extra_hosts: ["host.docker.internal:host-gateway"]`를 쓰라.
- 다른 컨테이너에 `localhost:포트`로 접속하던 설정은 서비스 이름(`rabbitmq:5672`)으로 바꿔야 하고, 두 서비스는 \
**같은 Docker 네트워크**에 있어야 한다. 이것을 놓치면 전환 직후 서비스 간 연결이 끊긴다.
- 매우 높은 패킷 처리량이 필요한 서비스는 브리지의 NAT 오버헤드로 성능이 떨어질 수 있다. 이런 경우가 host \
모드를 유지할 정당한 이유다."""

    learn_more = "https://docs.docker.com/engine/network/drivers/host/"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        if str(service.get("network_mode", "")).strip().lower() == "host":
            return [ServiceIssue(name, "network_mode: host — 필요성 검토", Status.WARN)]
        return []

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        body = ["# network_mode: host   ← 꼭 필요하지 않다면 삭제", "networks: [app-net]", 'ports: ["127.0.0.1:8080:8080"]']
        return yaml_snippet({i.service: body for i in issues})
