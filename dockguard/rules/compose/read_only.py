"""COMPOSE-006: 읽기 전용 루트 파일시스템."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, is_true, yaml_snippet


@register
class ReadOnlyRootFsRule(ComposeRule):
    id = "COMPOSE-006"
    title = "읽기 전용 루트 파일시스템"
    severity = Severity.LOW
    reference = cis("5.13", "Ensure that the container's root filesystem is mounted as read only")
    recommended = "read_only: true + 쓰기 경로만 tmpfs/볼륨"

    why = """\
컨테이너의 루트 파일시스템이 쓰기 가능하면, 침입한 공격자가 **도구를 내려받고, 바이너리를 바꿔치기하고, \
웹셸이나 백도어를 심을 수 있다.** 컨테이너가 재생성되기 전까지 이 변경은 그대로 남는다.

`read_only: true`로 루트 파일시스템을 읽기 전용으로 만들면 이런 **변조와 지속성 확보(persistence)가** 크게 \
어려워진다. 애플리케이션이 실제로 써야 하는 경로(`/tmp`, 데이터 디렉터리)만 tmpfs나 볼륨으로 열어 주면 된다. \
"이 컨테이너가 어디에 쓰는지"를 명시하게 되므로 컨테이너의 불변성(immutability)도 좋아진다."""

    how_to_fix = """\
1. 컨테이너가 어디에 쓰는지 확인한다. 실행 중인 컨테이너에서 이미지 대비 바뀐 파일을 보면 된다.

```bash
docker diff <컨테이너명>     # A: 추가, C: 변경, D: 삭제
```

2. 루트를 읽기 전용으로 바꾸고, 쓰기가 필요한 경로만 연다.

```yaml
services:
  app:
    read_only: true
    tmpfs:
      - /tmp
      - /run
    volumes:
      - app-data:/var/lib/app     # 영구 데이터
```"""

    tradeoff = """\
- 쓰기 경로를 빠뜨리면 `Read-only file system` 에러로 기동에 실패한다. 흔한 곳: `/tmp`, `/run`(pid 파일), \
`/var/cache`, 애플리케이션 로그 디렉터리, nginx의 `/var/cache/nginx`.
- 메시지큐·DB처럼 데이터를 쓰는 서비스는 데이터 디렉터리를 반드시 **named volume**으로 연결해야 한다 \
(예: RabbitMQ의 `/var/lib/rabbitmq`). 볼륨 없이 쓰던 데이터는 이 기회에 볼륨으로 옮겨라.
- tmpfs는 메모리를 쓴다. 큰 파일을 쓰는 경로라면 `tmpfs` 대신 볼륨을 쓰거나 크기를 제한하라 \
(`tmpfs: [/tmp:size=64m]`).
- 컨테이너 안에서 패키지를 설치하는 식의 운영(`docker exec ... apt install`)은 더 이상 불가능하다. 이것은 \
부작용이라기보다 의도된 효과다."""

    learn_more = "https://docs.docker.com/reference/compose-file/services/#read_only"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        if is_true(service.get("read_only", False)):
            return []
        return [ServiceIssue(name, "read_only 미설정")]

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        return yaml_snippet({i.service: ["read_only: true", "tmpfs: [/tmp, /run]   # 쓰기가 필요한 경로만"] for i in issues})
