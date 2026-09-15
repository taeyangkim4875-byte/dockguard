"""COMPOSE-011: latest 태그 금지 (이미지 버전 고정)."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.compose_facts import DEFAULT_VALUE_PATTERN, VARIABLE_PATTERN
from dockguard.knowledge.references import best_practice
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, parse_image, yaml_snippet


@register
class ImageTagRule(ComposeRule):
    id = "COMPOSE-011"
    title = "latest 태그 금지 (버전 고정)"
    severity = Severity.LOW
    reference = best_practice("재현 가능한 배포 — 이미지 버전 태그 또는 다이제스트 고정")
    recommended = "명시적 버전 태그 (예: 3.13.7) 또는 @sha256 다이제스트"

    why = """\
태그를 생략하거나 `:latest`를 쓰면 **언제 pull하느냐에 따라 전혀 다른 이미지가 실행된다.** `latest`는 \
"가장 최신"이 아니라 그냥 **덮어쓸 수 있는 이름표**일 뿐이다.

- **예고 없는 장애**: 서버 재부팅이나 재배포 때 새 메이저 버전이 내려받아져 설정 형식이나 기본 동작이 \
바뀐다. 정전 후 재기동했더니 어제와 다른 버전이 떠 있는 상황이 생긴다.
- **보안 추적 불가**: 지금 운영 중인 버전을 모르면, 새 CVE가 발표됐을 때 영향 여부를 판단할 수 없다.
- **공급망 공격**: 레지스트리 계정이 탈취되어 `latest`가 악성 이미지로 바뀌면, 다음 pull에서 그대로 실행된다. \
다이제스트(`@sha256:...`)로 고정하면 내용이 1바이트라도 바뀐 이미지는 거부된다."""

    how_to_fix = """\
1. 현재 실행 중인 이미지의 정확한 버전과 다이제스트를 확인한다.

```bash
docker compose images
docker image inspect rabbitmq:latest --format '{{index .RepoDigests 0}}'
```

2. 명시적 버전(가능하면 패치 버전까지)으로 고정한다. 공급망 공격까지 막으려면 다이제스트를 함께 쓴다.

```yaml
services:
  rabbitmq:
    image: rabbitmq:3.13.7-management
    # 또는: rabbitmq:3.13.7-management@sha256:<다이제스트>
```

3. 버전 올리기는 Renovate·Dependabot 같은 도구로 PR을 받아 **검토 후** 반영하는 흐름을 만든다."""

    tradeoff = """\
- 버전을 고정하면 **보안 패치가 자동으로 들어오지 않는다.** 고정한 만큼 정기적으로 업데이트하는 절차 \
(월 1회 점검, 자동 PR 도구)가 반드시 필요하다. 고정만 하고 방치하면 오히려 오래된 취약 버전에 머문다.
- 다이제스트 고정은 가장 안전하지만 사람이 읽기 어렵고, 멀티 아키텍처 이미지에서는 매니페스트 리스트 \
다이제스트를 써야 한다. 태그와 다이제스트를 함께 적으면(`image:tag@sha256:...`) 가독성과 안전성을 모두 챙길 수 있다.
- `3.13`처럼 마이너 버전까지만 고정하면 패치는 자동으로 받지만 재현성은 조금 떨어진다. 팀의 업데이트 \
정책에 맞춰 선택하라."""

    learn_more = "https://docs.docker.com/reference/compose-file/services/#image"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        image = service.get("image")
        if not image:
            return []  # build만 쓰는 서비스는 대상 아님
        text = str(image).strip()

        if VARIABLE_PATTERN.search(text):
            # 변수의 기본값이 latest면 취약, 그 외에는 배포 시 값에 달려 있으므로 통과
            defaults = DEFAULT_VALUE_PATTERN.findall(text)
            if any(d.strip().lower() == "latest" for d in defaults):
                return [ServiceIssue(name, f"{text} (변수 기본값이 latest)", subject=text)]
            return []

        ref = parse_image(text)
        if ref.digest:
            return []
        if ref.tag is None:
            return [ServiceIssue(name, f"{text} (태그 없음 = latest)", subject=text)]
        if ref.tag.lower() == "latest":
            return [ServiceIssue(name, f"{text}", subject=text)]
        return []

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        blocks = {}
        for issue in issues:
            name = parse_image(issue.subject).name if "${" not in issue.subject else "<이미지>"
            blocks[issue.service] = [f"image: {name}:<버전>   # docker compose images 로 현재 버전 확인"]
        return yaml_snippet(blocks)
