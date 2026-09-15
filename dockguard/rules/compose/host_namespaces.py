"""COMPOSE-009: 호스트 PID/IPC 네임스페이스 공유 금지."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, yaml_snippet

SHARED_NAMESPACE_KEYS = ("pid", "ipc")


@register
class HostNamespacesRule(ComposeRule):
    id = "COMPOSE-009"
    title = "호스트 PID/IPC 공유 금지"
    severity = Severity.HIGH
    reference = cis("5.16 / 5.17", "Ensure that the host's process / IPC namespace is not shared")
    recommended = "pid · ipc를 host로 두지 않음"

    why = """\
리눅스는 네임스페이스로 컨테이너가 보는 세상을 분리한다. `pid: host`나 `ipc: host`는 이 분리를 풀어 \
**호스트와 같은 공간을 공유**하게 한다.

- **`pid: host`** — 컨테이너에서 호스트의 **모든 프로세스가 보인다.** 다른 서비스 프로세스의 명령행 인자와 \
환경변수(`/proc/<pid>/environ`)에서 비밀번호를 읽을 수 있고, 권한이 있으면 호스트 프로세스에 시그널을 \
보내 죽이거나(`kill`) 디버거로 붙어 메모리를 조작할 수 있다. `nsenter`로 호스트 네임스페이스에 들어가는 \
탈출의 발판도 된다.
- **`ipc: host`** — 호스트의 공유 메모리·세마포어·메시지큐(System V IPC)에 접근한다. 같은 호스트의 다른 \
프로세스가 공유 메모리에 올려 둔 데이터를 읽거나 변조할 수 있다."""

    how_to_fix = """\
1. `pid: host` / `ipc: host`를 삭제한다.

2. 컨테이너끼리 프로세스나 공유 메모리를 공유해야 한다면, 호스트 대신 **특정 서비스와만** 공유한다.

```yaml
services:
  app:
    ipc: shareable
  sidecar:
    ipc: "service:app"     # app과만 IPC 공유
    pid: "service:app"     # app의 프로세스만 보임 (디버깅 사이드카 등)
```

3. 재생성 후 동작을 확인한다.

```bash
docker compose up -d --force-recreate
```"""

    tradeoff = """\
- 호스트 프로세스를 관찰하는 **모니터링·보안 에이전트**(node-exporter의 일부 수집기, Falco, 프로파일러 등)는 \
`pid: host`가 필요할 수 있다. 이 경우 전용 호스트에서만 실행하고, 읽기 전용 루트·non-root 등 다른 제한을 \
최대한 함께 걸어라.
- 공유 메모리를 크게 쓰는 애플리케이션(일부 DB, 머신러닝 프레임워크)이 `ipc: host`로 `/dev/shm` 크기 문제를 \
피하고 있었다면, 대신 `shm_size: 1gb`로 컨테이너 전용 공유 메모리를 늘려라."""

    learn_more = "https://docs.docker.com/reference/compose-file/services/#pid"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        return [
            ServiceIssue(name, f"{key}: host", subject=key)
            for key in SHARED_NAMESPACE_KEYS
            if str(service.get(key, "")).strip().lower() == "host"
        ]

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        blocks: dict[str, list[str]] = {}
        for issue in issues:
            blocks.setdefault(issue.service, []).append(f"# {issue.subject}: host   ← 삭제")
            if issue.subject == "ipc":
                blocks[issue.service].append("shm_size: 256mb   # 공유 메모리가 필요했다면")
        return yaml_snippet(blocks)
