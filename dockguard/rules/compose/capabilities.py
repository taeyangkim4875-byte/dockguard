"""COMPOSE-010: 위험한 Linux capability 추가 금지."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.compose_facts import DANGEROUS_CAPABILITIES
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, yaml_snippet


def normalize_capability(cap: Any) -> str:
    """'cap_sys_admin' / 'CAP_SYS_ADMIN' / 'SYS_ADMIN' → 'SYS_ADMIN'."""
    name = str(cap).strip().upper()
    return name[4:] if name.startswith("CAP_") else name


@register
class DangerousCapabilitiesRule(ComposeRule):
    id = "COMPOSE-010"
    title = "위험한 capability 추가 금지"
    severity = Severity.HIGH
    reference = cis("5.4", "Ensure that Linux kernel capabilities are restricted within containers")
    recommended = "cap_drop: [ALL] + 꼭 필요한 권한만 cap_add"

    why = """\
리눅스는 root의 권한을 **capability**라는 조각으로 나눈다. Docker는 컨테이너에 기본적으로 일부(약 14개)만 주고 \
위험한 것은 뺀다. `cap_add`로 위험한 capability를 추가하면 그만큼 컨테이너 격리가 약해진다.

| capability | 위험 |
|------------|------|
| `SYS_ADMIN` | mount·네임스페이스 조작 등 "사실상 root". 컨테이너 탈출 기법에 가장 많이 쓰인다 |
| `SYS_MODULE` | 커널 모듈 로드 = 호스트 커널 장악 |
| `SYS_PTRACE` | 다른 프로세스의 메모리 읽기·코드 주입 |
| `DAC_READ_SEARCH` | 파일 권한을 우회해 읽기 ("Shocker" 탈출 공격) |
| `NET_ADMIN` | 네트워크·iptables 설정 변경, 트래픽 가로채기 |
| `ALL` | 모든 capability — privileged와 거의 같다 |

"권한 오류가 나서" 일단 넣어 둔 capability가 공격자에게는 탈출 경로가 된다."""

    how_to_fix = """\
1. 먼저 **모든 capability를 빼고**, 에러가 나는 동작에 필요한 것만 하나씩 추가한다 (최소 권한 원칙).

```yaml
services:
  app:
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]    # 예: 80/443 포트 바인딩만 필요한 경우
```

2. 위험한 capability가 꼭 필요하다면 이유를 compose 파일에 주석으로 남기고, non-root·read_only·\
no-new-privileges 같은 다른 제한을 함께 건다.

3. 흔한 대체 방법:
- `SYS_ADMIN`으로 FUSE/마운트를 하던 경우 → 호스트에서 마운트 후 볼륨으로 전달
- `SYS_PTRACE`로 디버깅하던 경우 → 운영 환경에서는 제거, 디버깅 전용 compose override로 분리
- `NET_ADMIN`이 필요한 VPN 컨테이너 → 전용 호스트나 전용 네트워크로 격리"""

    tradeoff = """\
- `cap_drop: [ALL]`은 기본으로 주던 권한(`CHOWN`, `SETUID`, `SETGID` 등)까지 빼므로, 엔트리포인트에서 권한을 \
내리는(gosu) 이미지는 `SETUID`·`SETGID`·`CHOWN`을 다시 추가해야 기동된다. 에러 메시지를 보고 하나씩 추가하라.
- 모니터링·네트워크 도구(tcpdump, VPN, 네트워크 플러그인)는 `NET_ADMIN`·`NET_RAW`가 정말 필요할 수 있다. 이 경우 \
그 서비스를 다른 서비스와 네트워크로 분리해 영향 범위를 줄여라.
- capability를 줄였을 때 문제는 보통 기동 시점이 아니라 **특정 기능을 쓸 때** 나타난다. 스테이징에서 주요 \
기능을 한 번씩 확인하라."""

    learn_more = "https://docs.docker.com/reference/compose-file/services/#cap_add"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        added = service.get("cap_add") or []
        if not isinstance(added, list):
            return []
        dangerous = [cap for cap in (normalize_capability(c) for c in added) if cap in DANGEROUS_CAPABILITIES]
        if not dangerous:
            return []
        return [ServiceIssue(name, f"cap_add {', '.join(dangerous)}", subject=",".join(dangerous))]

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        blocks: dict[str, list[str]] = {}
        for issue in issues:
            lines = blocks.setdefault(issue.service, ["cap_drop: [ALL]", "cap_add: []   # 실제로 필요한 권한만 다시 추가"])
            for cap in issue.subject.split(","):
                lines.append(f"# {cap} ← {DANGEROUS_CAPABILITIES[cap]}. 꼭 필요한지 검토")
        return yaml_snippet(blocks)
