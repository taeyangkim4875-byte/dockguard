"""COMPOSE-003: 서비스별 no-new-privileges."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, is_true, yaml_snippet


def no_new_privileges_setting(service: dict[str, Any]) -> bool | None:
    """security_opt의 no-new-privileges 값. 없으면 None."""
    for opt in service.get("security_opt") or []:
        text = str(opt).strip()
        if not text.lower().startswith("no-new-privileges"):
            continue
        rest = text[len("no-new-privileges") :]
        if not rest:
            return True  # 값 없이 쓰면 true
        return is_true(rest.lstrip(":="))
    return None


@register
class ComposeNoNewPrivilegesRule(ComposeRule):
    id = "COMPOSE-003"
    title = "no-new-privileges 설정"
    severity = Severity.MEDIUM
    reference = cis("5.26", "Ensure that the container is restricted from acquiring additional privileges")
    recommended = "security_opt: [no-new-privileges:true]"

    why = """\
컨테이너 안에 setuid 비트가 설정된 실행 파일(`sudo`, `su`, `passwd` 등)이 있으면, 일반 사용자로 실행 중인 \
프로세스도 그 파일을 실행하는 순간 **root 권한을 얻을 수 있다.** COMPOSE-002로 non-root 사용자를 지정해도 \
이 경로가 열려 있으면 효과가 반감된다.

`no-new-privileges:true`는 커널의 `PR_SET_NO_NEW_PRIVS` 플래그를 설정해 setuid/setgid·파일 capability로 \
새 권한을 얻는 것을 막는다. non-root 실행과 **함께** 써야 권한 상승 경로가 제대로 닫힌다.

daemon.json에서 `"no-new-privileges": true`(DAEMON-002)를 켜 두면 모든 컨테이너에 기본 적용되며, \
dockguard는 이 경우 서비스별 설정이 없어도 통과로 판정한다."""

    how_to_fix = """\
서비스에 `security_opt`를 추가하고 재생성한다.

```yaml
services:
  app:
    security_opt:
      - no-new-privileges:true
```

```bash
docker compose up -d --force-recreate
```

모든 서비스에 일괄 적용하려면 daemon.json의 기본값으로 켜는 방법도 있다 (`dockguard fix daemon`)."""

    tradeoff = """\
- 컨테이너 안에서 `sudo`/`su`로 root를 얻는 스크립트가 있다면 `sudo: The "no new privileges" flag is set` \
에러로 실패한다. root가 필요한 작업은 이미지 빌드 단계(Dockerfile의 `RUN`)로 옮겨라.
- root로 시작해서 `gosu`/`su-exec`로 권한을 **내리는** 공식 이미지(postgres, redis 등)는 영향이 없다.
- `security_opt: [no-new-privileges:false]`처럼 명시적으로 끈 서비스는 daemon 기본값이 켜져 있어도 해제되므로 \
취약으로 판정한다."""

    learn_more = "https://docs.docker.com/reference/compose-file/services/#security_opt"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        setting = no_new_privileges_setting(service)
        if setting is True:
            return []
        if setting is False:
            return [ServiceIssue(name, "no-new-privileges:false (명시적으로 해제)")]
        daemon = context.daemon
        if daemon is not None and daemon.usable and daemon.get("no-new-privileges") is True:
            return []  # 데몬 기본값으로 적용됨
        return [ServiceIssue(name, "security_opt에 no-new-privileges 없음")]

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        return yaml_snippet({i.service: ["security_opt:", "  - no-new-privileges:true"] for i in issues})
