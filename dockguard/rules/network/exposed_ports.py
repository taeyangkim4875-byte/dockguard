"""NET-004: 민감 포트의 외부(0.0.0.0) 노출.

실행 중인 컨테이너의 실제 포트 바인딩을 본다. Docker에 연결할 수 없으면 compose 파일의 `ports:`로 대신 판정한다
(가장 흔한 사고 경로라서, Docker 없이도 최대한 확인한다).
"""

from __future__ import annotations

from dockguard.core.context import ComposeProject, DockerRuntime, ScanContext
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.network_facts import SENSITIVE_PORTS
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import service_ports
from dockguard.rules.network._base import NetworkRule, host_target

MAX_LISTED = 5
ALL_INTERFACE_HOSTS = {None, "", "0.0.0.0", "::"}


@register
class ExposedSensitivePortsRule(NetworkRule):
    id = "NET-004"
    title = "민감 포트 외부 노출 점검"
    severity = Severity.HIGH
    reference = cis("5.14", "Ensure that incoming container traffic is bound to a specific host interface")
    recommended = "127.0.0.1 바인딩 또는 포트 미공개 (컨테이너 네트워크로만 통신)"

    why = """\
`ports: ["5672:5672"]`처럼 IP 없이 포트를 공개하면 **호스트의 모든 네트워크 인터페이스(0.0.0.0)에** 열린다. \
메시지큐·DB·캐시처럼 **내부에서만 쓰는 서비스**가 이렇게 열리면 인터넷이나 사내망 어디서든 직접 접속할 수 있다.

이런 서비스는 "어차피 내부용"이라는 이유로 인증이 약한 경우가 많다. RabbitMQ의 `guest` 계정, 비밀번호 없는 \
Redis, 기본 계정이 남은 관리 UI가 대표적이다. **dockguard 제작자도 모의해킹에서 RabbitMQ 5672/15672 포트가 \
0.0.0.0에 열려 있어 외부에서 guest 계정으로 접속당한 사례를 겪었다.**

**호스트 방화벽(UFW)으로 막았다고 안심하면 안 된다.** Docker가 만드는 iptables 규칙은 UFW 규칙보다 먼저 \
적용되어, `ufw deny 5672`를 해도 공개된 컨테이너 포트는 외부에서 그대로 접속된다 (DAEMON-009 참고)."""

    how_to_fix = """\
1. 같은 호스트의 다른 컨테이너만 쓰는 포트라면 **아예 공개하지 않는다.** 같은 Docker 네트워크의 컨테이너는 \
`ports:` 없이도 서비스 이름으로 접속할 수 있다.

```yaml
services:
  rabbitmq:
    # ports: ["5672:5672", "15672:15672"]   ← 삭제
    networks: [mq-net]
```

2. 호스트에서만 접근해야 한다면 **루프백에만 바인딩**한다.

```yaml
    ports:
      - "127.0.0.1:15672:15672"
```

3. 관리 UI는 SSH 터널로 접속한다.

```bash
ssh -L 15672:127.0.0.1:15672 user@server   # 로컬 브라우저에서 http://localhost:15672
```

4. 다른 서버가 꼭 접속해야 한다면 `DOCKER-USER` 체인에서 허용할 IP만 연다. **`-i`로 외부 인터페이스를 반드시 \
지정**하라 — 빠뜨리면 컨테이너끼리의 통신까지 막힌다.

```bash
# eth0 = 외부 인터페이스 이름 (ip -br addr 로 확인)
sudo iptables -I DOCKER-USER -i eth0 -p tcp --dport 5672 ! -s 10.0.0.0/24 -j DROP
```"""

    tradeoff = """\
- 포트를 닫으면 **그 포트로 접속하던 외부 클라이언트(다른 서버의 앱, 개발자 PC의 DB 툴)가 즉시 끊긴다.** 누가 \
접속하는지 먼저 확인하라 (`ss -tnp | grep 5672`, RabbitMQ 관리 UI의 Connections 탭).
- 같은 호스트의 컨테이너가 `호스트IP:포트`로 접속하고 있었다면 포트를 닫는 순간 연결이 끊긴다. 같은 네트워크에 두고 \
서비스 이름으로 접속하도록 먼저 바꿔라 (NET-001).
- `127.0.0.1` 바인딩은 IPv4 루프백에만 열린다. 클라이언트가 `localhost`를 `::1`로 해석하면 접속이 안 될 수 있으니 \
`127.0.0.1`로 명시하라.
- 포트를 닫는 것과 별개로 **기본 계정(guest 등) 제거와 강한 비밀번호**는 반드시 함께 적용하라. 네트워크 차단은 \
한 겹의 방어일 뿐이다."""

    learn_more = "https://docs.docker.com/engine/network/packet-filtering-firewalls/"

    def check(self, context: ScanContext) -> list[Finding]:
        runtime = context.docker
        if runtime is None:
            return []
        if runtime.available:
            return self.evaluate(runtime, context)
        # Docker 없이도 compose 파일로 확인할 수 있는 만큼은 확인한다
        if context.compose_projects:
            return [self._check_compose(project) for project in context.compose_projects]
        return [self.make(Status.SKIP, target="Docker 호스트", current=f"점검 불가 — {runtime.error}")]

    def evaluate(self, runtime: DockerRuntime, context: ScanContext) -> list[Finding]:
        exposed: dict[tuple[str, int, int | None], str] = {}  # IPv4/IPv6 중복 바인딩은 하나로
        for container in runtime.running_containers:
            for port in container.ports:
                if port.open_to_all and port.container_port in SENSITIVE_PORTS:
                    key = (container.name, port.container_port, port.host_port)
                    exposed.setdefault(
                        key,
                        f"{container.name} 0.0.0.0:{port.host_port}->{port.container_port} ({SENSITIVE_PORTS[port.container_port]})",
                    )
        return [self._summarize(host_target(runtime), list(exposed.values()), "실행 중인 컨테이너")]

    def _check_compose(self, project: ComposeProject) -> Finding:
        exposed: list[str] = []
        for name, service in project.services.items():
            for binding in service_ports(service):
                try:
                    container_port = int(binding.container_port.split("-")[0])
                except ValueError:
                    continue
                if binding.host_ip in ALL_INTERFACE_HOSTS and binding.host_port and container_port in SENSITIVE_PORTS:
                    exposed.append(f"{name} {binding.raw} ({SENSITIVE_PORTS[container_port]})")
        return self._summarize(f"{project.label} (compose 파일 기준 — Docker 연결 불가)", exposed, "compose 파일")

    def _summarize(self, target: str, exposed: list[str], scope: str) -> Finding:
        if not exposed:
            return self.make(Status.PASS, target=target, current=f"{scope}에 외부 노출된 민감 포트 없음")
        listed = "; ".join(exposed[:MAX_LISTED]) + (f" 외 {len(exposed) - MAX_LISTED}건" if len(exposed) > MAX_LISTED else "")
        return self.make(Status.FAIL, target=target, current=f"{len(exposed)}건 — {listed}")
