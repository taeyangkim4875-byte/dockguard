"""NET-003: 기본 bridge 공유 경고."""

from __future__ import annotations

from dockguard.core.context import DEFAULT_BRIDGE, DockerRuntime, ScanContext
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.network._base import NetworkRule, host_target
from dockguard.rules.network.dependency import bridge_icc_disabled

MAX_LISTED = 6


@register
class DefaultBridgeRule(NetworkRule):
    id = "NET-003"
    title = "기본 bridge 공유 경고"
    severity = Severity.MEDIUM
    reference = cis("5.30", "Ensure that Docker's default bridge 'docker0' is not used")
    recommended = "기본 bridge 대신 목적별 커스텀 네트워크"

    why = """\
`--network`를 지정하지 않은 컨테이너는 모두 **기본 bridge(`docker0`)에** 붙는다. 기본 bridge는 Docker 초기의 \
레거시 네트워크라 커스텀 네트워크와 동작이 다르다.

- **서로 무관한 컨테이너가 한 네트워크에 섞인다.** `icc: true`(기본값)면 이 컨테이너들은 서로의 모든 포트로 \
통신할 수 있어, 하나가 침해되면 나머지로 측면 이동하기 쉽다.
- **컨테이너 이름으로 DNS 조회가 안 된다.** IP로만 통신해야 하는데, IP는 재기동할 때마다 바뀐다.
- 반대로 `icc: false`면 이 컨테이너들은 **서로 전혀 통신할 수 없다.** 통신이 필요한 서비스가 기본 bridge에 \
남아 있으면 그대로 장애가 된다 (dockguard 제작 배경 사고의 원인).

dockguard는 기본 bridge에 2개 이상의 컨테이너가 있으면 icc가 켜져 있을 때 취약, 꺼져 있을 때 주의로 판정한다."""

    how_to_fix = """\
1. 서비스 묶음별로 커스텀 네트워크를 만들고 옮긴다.

```bash
docker network create app-net
docker network connect app-net <컨테이너>
docker network disconnect bridge <컨테이너>
```

2. compose로 관리하는 서비스는 `network_mode: bridge`를 지우고 `networks:`를 명시한다. compose는 기본적으로 \
프로젝트 전용 네트워크를 만들어 주므로, 별도 설정이 없어도 기본 bridge를 쓰지 않는다.

3. 새 컨테이너가 기본 bridge에 붙는 것 자체를 막고 싶다면 daemon.json에 `"icc": false`를 두어 기본 bridge를 \
사실상 격리 전용으로 만든다 (DAEMON-001의 부작용을 먼저 확인할 것)."""

    tradeoff = """\
- 커스텀 네트워크로 옮기면 IP가 바뀐다. **IP로 접속하던 설정은 서비스(컨테이너) 이름으로 바꿔야** 한다.
- 옮기는 순서가 중요하다. 통신하는 두 컨테이너 중 한쪽만 먼저 옮기면 그 사이에 연결이 끊긴다. 새 네트워크에 \
**둘 다 연결한 뒤** 기본 bridge에서 분리하라.
- 레거시 `--link`로 연결된 컨테이너는 커스텀 네트워크에서 동작하지 않는다. 링크 대신 같은 네트워크 + 이름 접속으로 \
바꿔라."""

    learn_more = "https://docs.docker.com/engine/network/drivers/bridge/"

    def evaluate(self, runtime: DockerRuntime, context: ScanContext) -> list[Finding]:
        on_bridge = [
            c.name
            for c in runtime.running_containers
            if c.network_mode != "host" and DEFAULT_BRIDGE in runtime.effective_networks(c)
        ]
        target = host_target(runtime)
        if len(on_bridge) < 2:
            current = "기본 bridge를 공유하는 컨테이너 없음" if not on_bridge else f"기본 bridge 컨테이너 1개 ({on_bridge[0]}) — 공유 대상 없음"
            return [self.make(Status.PASS, target=target, current=current)]

        listed = ", ".join(on_bridge[:MAX_LISTED]) + (f" 외 {len(on_bridge) - MAX_LISTED}개" if len(on_bridge) > MAX_LISTED else "")
        if bridge_icc_disabled(runtime, context):
            return [
                self.make(
                    Status.WARN,
                    target=target,
                    current=f"{len(on_bridge)}개가 기본 bridge에 있지만 icc: false로 서로 통신 불가 — {listed}",
                )
            ]
        return [self.make(Status.FAIL, target=target, current=f"{len(on_bridge)}개가 기본 bridge를 공유 (서로 모든 포트로 통신 가능) — {listed}")]
