"""COMPOSE-004: docker.sock 마운트 경고."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.compose_facts import DOCKER_SOCKET_NAMES
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, service_volumes, yaml_snippet


@register
class DockerSocketMountRule(ComposeRule):
    id = "COMPOSE-004"
    title = "docker.sock 마운트 금지"
    severity = Severity.CRITICAL
    reference = cis("5.32", "Ensure that the Docker socket is not mounted inside any containers")
    recommended = "docker.sock 마운트 제거 (필요 시 socket-proxy)"

    why = """\
`/var/run/docker.sock`은 Docker 데몬의 API 입구다. 이 소켓에 접근할 수 있으면 **호스트 root와 같은 권한**을 \
가진다. 소켓을 마운트한 컨테이너가 침해되면, 공격자는 다음 한 줄로 호스트를 장악한다.

```bash
docker run -it --privileged --pid=host -v /:/host alpine chroot /host
```

**`:ro`(읽기 전용)로 마운트해도 안전하지 않다.** 읽기 전용은 소켓 *파일*을 지우거나 바꾸지 못하게 할 뿐, \
소켓을 통한 API 호출(컨테이너 생성·실행)은 그대로 가능하다.

Traefik, Portainer, Watchtower, CI 러너처럼 이 소켓을 요구하는 도구가 많아서 무심코 붙여 두기 쉽지만, \
그 컨테이너는 사실상 **호스트에서 가장 강력한 프로세스**가 된다."""

    how_to_fix = """\
1. 정말 Docker API가 필요한 서비스인지 확인하고, 필요 없다면 마운트를 삭제한다.

2. 필요하다면 **소켓 프록시**를 두고, 그 서비스에 필요한 API만 허용한다. 예: 컨테이너 목록 조회만 필요한 경우

```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy:<고정 버전>
    environment:
      CONTAINERS: 1          # 컨테이너 조회만 허용
      POST: 0                # 생성·삭제 같은 쓰기 API 차단
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [proxy-net]    # 외부에 포트를 열지 않는다

  app:
    environment:
      DOCKER_HOST: tcp://socket-proxy:2375   # Traefik은 providers.docker.endpoint 로 지정
    networks: [proxy-net]
    # volumes: - /var/run/docker.sock:...   ← 삭제
```

3. CI 러너라면 rootless Docker나 Kaniko·Buildah처럼 데몬 소켓 없이 이미지를 빌드하는 방식을 검토한다."""

    tradeoff = """\
- 소켓을 빼면 해당 도구의 기능(자동 라우팅, 컨테이너 관리 UI, 자동 업데이트)이 동작하지 않는다. \
프록시를 둘 때는 도구가 실제로 쓰는 API 범위를 문서에서 확인해 최소한만 허용하라.
- 소켓 프록시도 결국 소켓에 접근하므로 **프록시 컨테이너 자체는 외부에 노출하지 말고** 전용 내부 네트워크에만 둔다.
- 모니터링 도구(cAdvisor 등)가 필요로 하는 경우, 소켓 대신 `/sys`, `/var/lib/docker` 등을 읽기 전용으로 \
주는 방식이 가능한지 확인하라."""

    learn_more = "https://docs.docker.com/engine/security/#docker-daemon-attack-surface"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        issues = []
        for mount in service_volumes(service):
            source = (mount.source or "").rstrip("/")
            if any(source.endswith(sock) for sock in DOCKER_SOCKET_NAMES):
                suffix = " (읽기 전용이어도 API 호출 가능)" if mount.read_only else ""
                issues.append(ServiceIssue(name, f"{mount.source} 마운트{suffix}"))
        return issues

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        return yaml_snippet(
            {
                i.service: [
                    "environment:",
                    "  DOCKER_HOST: tcp://socket-proxy:2375   # 필요한 API만 허용한 프록시 경유",
                    "# volumes:",
                    "#   - /var/run/docker.sock:/var/run/docker.sock   ← 삭제",
                ]
                for i in issues
            }
        )
