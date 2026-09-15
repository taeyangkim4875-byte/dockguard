"""COMPOSE-012: 특권 포트(1024 미만) 매핑 검토.

80/443은 웹 서버가 정당하게 쓰는 표준 포트라 통과로 보고, 그 외 1024 미만 포트만 '주의'로 표시한다.
"""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.compose_facts import PRIVILEGED_PORT_LIMIT, STANDARD_WEB_PORTS
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, service_ports, yaml_snippet


@register
class PrivilegedPortsRule(ComposeRule):
    id = "COMPOSE-012"
    title = "특권 포트 매핑 검토"
    severity = Severity.LOW
    reference = cis("5.8", "Ensure privileged ports are not mapped within containers")
    recommended = "1024 이상 호스트 포트 (80/443 제외)"

    why = """\
1024 미만 포트는 전통적으로 **root만 열 수 있는 특권 포트**이고, SSH(22), SMTP(25), DNS(53) 같은 핵심 \
시스템 서비스가 쓴다. 컨테이너를 이런 호스트 포트에 매핑하면:

- 호스트의 실제 시스템 서비스(예: 호스트 sshd)와 **포트가 충돌**하거나, 반대로 호스트 서비스를 가장해 \
접속을 가로채는 구성이 될 수 있다.
- 방화벽·접근 제어가 "특권 포트 = 시스템 서비스"라는 가정 위에 짜여 있는 환경에서 예상치 못한 노출이 생긴다.
- 컨테이너 안의 애플리케이션도 그 포트를 열기 위해 root나 `NET_BIND_SERVICE` 권한이 필요해져, non-root \
실행(COMPOSE-002)과 충돌한다.

웹 서버의 80/443은 정당한 표준 포트라 dockguard는 통과로 본다. 그 외의 특권 포트는 의도한 것인지 검토하라는 \
의미로 **주의**를 표시한다."""

    how_to_fix = """\
1. 컨테이너 안에서는 1024 이상 포트를 쓰고, 꼭 필요한 경우에만 호스트의 특권 포트로 매핑한다.

```yaml
services:
  smtp-relay:
    ports:
      - "2525:2525"          # 25 대신
```

2. 외부 공개가 필요 없는 포트라면 루프백에만 바인딩하거나 아예 공개하지 않는다 (NET-004 참고).

```yaml
    ports:
      - "127.0.0.1:2525:2525"
```"""

    tradeoff = """\
- 표준 포트(예: DNS 53, SMTP 25)를 바꾸면 클라이언트 설정도 함께 바꿔야 한다. 외부 클라이언트가 표준 포트를 \
기대하는 서비스라면 매핑을 유지하되, 호스트에서 같은 포트를 쓰는 서비스가 없는지 확인하라.
- 이 항목은 심각도가 낮은 **검토 항목**이다. 포트 번호 자체보다 그 포트가 **어느 인터페이스에 열리는지** \
(0.0.0.0인지 127.0.0.1인지)가 훨씬 중요하다."""

    learn_more = "https://docs.docker.com/reference/compose-file/services/#ports"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        issues = []
        for binding in service_ports(service):
            port = binding.host_port
            if port is None or port >= PRIVILEGED_PORT_LIMIT or port in STANDARD_WEB_PORTS:
                continue
            issues.append(ServiceIssue(name, f"호스트 포트 {port} ({binding.raw})", Status.WARN, subject=binding.raw))
        return issues

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        blocks: dict[str, list[str]] = {}
        for issue in issues:
            blocks.setdefault(issue.service, ["ports:"]).append(f'  - "{issue.subject}"   # 1024 이상 포트로 바꿀 수 있는지 검토')
        return yaml_snippet(blocks)
