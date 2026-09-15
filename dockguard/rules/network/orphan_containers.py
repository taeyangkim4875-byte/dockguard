"""NET-002: 커스텀 네트워크에 속하지 않은 '고아' 컨테이너."""

from __future__ import annotations

from dockguard.core.context import DEFAULT_BRIDGE, SPECIAL_NETWORK_MODES, DockerRuntime, ScanContext
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.network._base import NetworkRule, host_target

MAX_LISTED = 6


@register
class OrphanContainersRule(NetworkRule):
    id = "NET-002"
    title = "고아 컨테이너 네트워크 점검"
    severity = Severity.LOW
    reference = cis("5.30", "Ensure that Docker's default bridge 'docker0' is not used", related=True)
    recommended = "모든 컨테이너를 목적별 커스텀 네트워크에 연결"

    why = """\
커스텀 네트워크에 하나도 연결되지 않은 컨테이너는 **서비스 네트워크 설계에서 빠져 있는** 컨테이너다. 대개 \
기본 bridge에만 붙어 있거나 네트워크가 아예 없다.

이런 컨테이너가 생기는 흔한 이유:

- 장애 복구 중 compose 대신 `docker run`으로 급하게 다시 띄웠다 (`--network`를 빠뜨림).
- compose 파일에서 `networks:`를 지정하지 않은 채 `network_mode: bridge`를 썼다.
- 테스트용으로 띄워 두고 잊어버린 컨테이너다.

이 컨테이너는 다른 서비스와 **이름으로 통신할 수 없고**(기본 bridge에는 DNS가 없다), 기본 bridge의 다른 \
컨테이너와는 icc 설정에 따라 **전부 열려 있거나 전부 막혀 있다.** 어느 쪽이든 의도한 구성이 아닐 가능성이 높다."""

    how_to_fix = """\
1. 컨테이너가 속해야 할 서비스 네트워크를 정하고 연결한다.

```bash
docker network connect app-net <컨테이너>
docker network disconnect bridge <컨테이너>   # 기본 bridge에서 분리
```

2. compose로 관리하도록 옮기고 `networks:`를 명시한다. 더 이상 쓰지 않는 컨테이너라면 삭제한다.

```bash
docker ps -a --filter network=bridge
docker rm -f <안 쓰는 컨테이너>
```"""

    tradeoff = """\
- 기본 bridge에서 분리하면 그 컨테이너에 **IP로 접속하던 다른 컨테이너의 연결이 끊긴다.** 누가 이 컨테이너에 \
접속하는지 먼저 확인하라 (NET-001 의존성 선언으로 검증 가능).
- 단독으로 동작하는 컨테이너(외부에 포트만 공개하는 웹 서버 등)는 실제 문제가 없을 수 있다. 심각도가 낮은 \
정리 항목이다.
- `network_mode: none`으로 일부러 격리한 컨테이너와 host 모드 컨테이너는 이 점검에서 제외한다."""

    learn_more = "https://docs.docker.com/engine/network/drivers/bridge/"

    def evaluate(self, runtime: DockerRuntime, context: ScanContext) -> list[Finding]:
        orphans: list[str] = []
        for container in runtime.running_containers:
            mode = container.network_mode
            if mode in SPECIAL_NETWORK_MODES or mode.startswith("container:"):
                continue
            networks = runtime.effective_networks(container)
            if not [n for n in networks if n != DEFAULT_BRIDGE]:
                orphans.append(f"{container.name} ({', '.join(networks) or '네트워크 없음'})")

        target = host_target(runtime)
        if not orphans:
            return [self.make(Status.PASS, target=target, current="모든 컨테이너가 커스텀 네트워크에 연결됨")]
        listed = ", ".join(orphans[:MAX_LISTED]) + (f" 외 {len(orphans) - MAX_LISTED}개" if len(orphans) > MAX_LISTED else "")
        return [self.make(Status.FAIL, target=target, current=f"{len(orphans)}개 — {listed}")]
