"""COMPOSE-002: non-root 사용자로 실행."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.compose_facts import PRIVILEGE_DROPPING_IMAGES
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, parse_image, yaml_snippet

ROOT_USERS = {"root", "0"}


def is_root_user(user: str) -> bool:
    """'root', '0', '0:0', 'root:root' 등 root로 실행되는 user 값인지."""
    return user.strip().split(":")[0].strip().lower() in ROOT_USERS


def dockerfile_user(project_dir: Path, build: Any) -> str | None:
    """build 컨텍스트의 Dockerfile에서 최종 스테이지의 USER 값을 읽는다. 알 수 없으면 None."""
    if isinstance(build, str):
        context, dockerfile = build, "Dockerfile"
    elif isinstance(build, dict):
        context, dockerfile = str(build.get("context", ".")), str(build.get("dockerfile", "Dockerfile"))
    else:
        return None
    if "://" in context or context.startswith("git@"):  # 원격 컨텍스트는 읽을 수 없다
        return None
    path = (project_dir / context / dockerfile).resolve()
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return None

    user: str | None = None
    for line in lines:
        stripped = line.strip()
        if re.match(r"(?i)^FROM\s", stripped):
            user = None  # 새 스테이지는 USER가 초기화된다
        match = re.match(r"(?i)^USER\s+(\S+)", stripped)
        if match:
            user = match.group(1)
    return user


@register
class NonRootUserRule(ComposeRule):
    id = "COMPOSE-002"
    title = "non-root 사용자로 실행"
    severity = Severity.HIGH
    reference = cis("4.1", "Ensure that a user for the container has been created")
    recommended = 'user: "1000:1000" (또는 Dockerfile의 USER)'

    why = """\
`user:`를 지정하지 않으면 컨테이너는 이미지에 정해진 사용자로 실행되고, **대부분의 이미지는 root(uid 0)로** \
실행된다. 기본 설정에서 컨테이너 안의 root는 호스트의 root와 **같은 uid**다 (DAEMON-006 참고).

그래서 root로 도는 컨테이너는 다음 상황에서 피해가 곧바로 커진다.

- 애플리케이션 취약점(RCE)으로 셸을 얻은 공격자가 컨테이너 안에서 **무엇이든** 할 수 있다 (패키지 설치, \
설정 변조, 다른 서비스로의 공격 도구 반입).
- 호스트 디렉터리를 바인드 마운트한 경우, 그 안의 파일을 **호스트 root 권한으로** 읽고 쓸 수 있다.
- 커널·런타임 취약점으로 컨테이너를 탈출하면 곧바로 호스트 root가 된다.

일반 사용자로 실행하는 것만으로 이 공격 경로 대부분이 막힌다."""

    how_to_fix = """\
1. **직접 만드는 이미지**라면 Dockerfile에 전용 사용자를 만들고 `USER`로 전환하는 것이 가장 좋다.

```dockerfile
RUN addgroup --system app && adduser --system --ingroup app app
USER app
```

2. 이미지를 고칠 수 없다면 compose에서 `user:`를 지정한다.

```yaml
services:
  app:
    user: "1000:1000"
```

3. 바인드 마운트·볼륨 디렉터리의 소유권을 그 uid에 맞춘다.

```bash
sudo chown -R 1000:1000 ./data
docker compose up -d --force-recreate
```"""

    tradeoff = """\
- **볼륨 권한 문제가 가장 흔하다.** 기존에 root로 쓰던 데이터 디렉터리를 일반 사용자가 쓰지 못해 \
`Permission denied`로 기동에 실패한다. 적용 전에 볼륨 소유권을 먼저 바꿔라.
- postgres · mysql · mariadb · redis · mongo 같은 공식 이미지는 **root로 시작해 엔트리포인트에서 \
스스로 권한을 내린다**(gosu). 이런 이미지에 `user:`를 강제로 넣으면 초기화 스크립트가 실패할 수 있다. \
dockguard는 이 경우를 '주의'로만 표시한다.
- 1024 미만 포트를 여는 서비스는 일반 사용자로 바인딩할 수 없다. 컨테이너 안에서는 8080 같은 높은 포트를 \
쓰고 `ports: ["80:8080"]`으로 매핑하라.
- `userns-remap`이 켜진 호스트에서는 컨테이너 root가 호스트의 일반 uid로 매핑되므로 위험이 줄어든다 \
(dockguard는 이 경우도 '주의'로 표시)."""

    learn_more = "https://docs.docker.com/reference/compose-file/services/#user"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        user = service.get("user")
        if user is not None and str(user).strip():
            if is_root_user(str(user)):
                return [ServiceIssue(name, f'user: "{user}" (root 명시)')]
            return []

        image = service.get("image")
        official = parse_image(str(image)).official_name if image else None
        if official in PRIVILEGE_DROPPING_IMAGES:
            return [ServiceIssue(name, f"user 미지정 — {official} 이미지는 엔트리포인트에서 권한을 내림", Status.WARN)]

        if "build" in service:
            built_user = dockerfile_user(project.directory, service["build"])
            if built_user is not None:
                return [ServiceIssue(name, f"Dockerfile USER {built_user} (root)")] if is_root_user(built_user) else []

        daemon = context.daemon
        if daemon is not None and daemon.usable and daemon.get("userns-remap"):
            return [ServiceIssue(name, "user 미지정 — userns-remap으로 호스트 권한은 없음", Status.WARN)]
        return [ServiceIssue(name, "user 미지정 (이미지 기본값, 대개 root)")]

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        failing = [i for i in issues if i.status == Status.FAIL]
        if not failing:
            return ""
        return yaml_snippet({i.service: ['user: "1000:1000"   # 볼륨 소유권도 이 uid로 맞출 것'] for i in failing})
