"""COMPOSE-001: privileged 모드 사용 금지."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, is_true, yaml_snippet


@register
class PrivilegedRule(ComposeRule):
    id = "COMPOSE-001"
    title = "privileged 모드 사용 금지"
    severity = Severity.CRITICAL
    reference = cis("5.5", "Ensure that privileged containers are not used")
    recommended = "privileged 제거, 필요한 capability만 cap_add"

    why = """\
`privileged: true`는 컨테이너 격리를 **거의 전부 끈다.** 모든 Linux capability가 부여되고, 호스트의 모든 \
장치(`/dev/*`)에 접근할 수 있으며, seccomp·AppArmor 제한도 해제된다.

이 상태의 컨테이너 안에서 root 권한을 얻은 공격자는 **호스트 디스크를 그대로 마운트**(`mount /dev/sda1 /mnt`)해서 \
호스트의 `/etc/shadow`를 읽거나 SSH 키·cron을 심을 수 있다. 커널 모듈을 로드하거나 cgroup 기능을 악용한 \
탈출 기법도 모두 열려 있다. 즉 privileged 컨테이너가 하나 침해되면 **호스트 전체가 침해된 것**과 같다.

"편해서", "권한 오류가 나서" 켜 두는 경우가 많지만, 실제로 필요한 권한은 대부분 capability 한두 개로 해결된다."""

    how_to_fix = """\
1. 이 서비스가 **정확히 무엇 때문에** privileged가 필요한지 확인한다. 흔한 경우와 대체 방법:

| 필요한 동작 | privileged 대신 |
|-------------|-----------------|
| 1024 미만 포트 바인딩 | `cap_add: [NET_BIND_SERVICE]` |
| 네트워크 설정 변경 (VPN 등) | `cap_add: [NET_ADMIN]` + `devices: [/dev/net/tun]` |
| 특정 장치 접근 (GPU, USB) | `devices:` 로 해당 장치만 전달, GPU는 `deploy.resources.reservations.devices` |
| 시간 동기화 | `cap_add: [SYS_TIME]` |

2. `privileged: true`를 지우고, 먼저 `cap_drop: [ALL]`로 전부 뺀 뒤 필요한 것만 하나씩 추가한다.

3. 서비스를 재생성해 동작을 확인한다.

```bash
docker compose up -d --force-recreate <서비스명>
docker compose logs -f <서비스명>
```"""

    tradeoff = """\
- privileged에 기대던 기능이 `Operation not permitted`로 실패할 수 있다. 에러 로그에서 막힌 동작(mount, \
네트워크 설정, 장치 접근 등)을 확인하고 해당 capability나 장치만 추가하라. 처음부터 완벽히 맞추기 어렵다면 \
스테이징 환경에서 먼저 시험하라.
- Docker-in-Docker(`docker:dind`)처럼 **정말로 privileged가 필요한** 이미지도 있다. 이 경우 격리 수준이 낮다는 \
사실을 받아들이고 전용 호스트/VM에서만 실행하거나, rootless 모드·Kaniko·Sysbox 같은 대안을 검토하라.
- `userns-remap` 환경에서는 privileged 컨테이너가 `userns_mode: host`를 요구하므로 사용자 네임스페이스 보호까지 잃는다."""

    learn_more = "https://docs.docker.com/reference/cli/docker/container/run/#privileged"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        if is_true(service.get("privileged", False)):
            return [ServiceIssue(name, "privileged: true")]
        return []

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        return yaml_snippet(
            {
                i.service: [
                    "# privileged: true   ← 삭제",
                    "cap_drop: [ALL]",
                    "cap_add: [NET_BIND_SERVICE]   # 실제로 필요한 권한만",
                ]
                for i in issues
            }
        )
