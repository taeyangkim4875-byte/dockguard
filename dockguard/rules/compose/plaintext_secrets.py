"""COMPOSE-005: 평문 시크릿 금지."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.knowledge.compose_facts import DEFAULT_VALUE_PATTERN, VARIABLE_PATTERN, is_secret_name
from dockguard.knowledge.references import best_practice
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, service_environment

DOCKER_SECRETS_DIR = "/run/secrets/"


@register
class PlaintextSecretsRule(ComposeRule):
    id = "COMPOSE-005"
    title = "평문 시크릿 금지"
    severity = Severity.HIGH
    reference = best_practice("OWASP Secrets Management — 저장소에 비밀번호를 커밋하지 않는다")
    recommended = "${VAR} 참조 + .env(chmod 600, .gitignore) 또는 Docker secrets"

    why = """\
docker-compose.yml은 보통 **git으로 관리된다.** 여기에 비밀번호·토큰을 평문으로 적으면 저장소에 접근할 수 있는 \
모든 사람(퇴사자, 외주 인력, 유출된 CI 토큰, 실수로 public 전환된 저장소)에게 노출된다. git 기록에 한 번 \
들어간 값은 파일에서 지워도 **과거 커밋에 영원히 남는다.** 모의해킹에서 가장 자주 지적되는 항목 중 하나다.

평문 시크릿은 운영 사고의 원인도 된다. 같은 비밀번호를 여러 compose 파일·서비스에 따로 적어 두면, 한쪽만 \
바꾸고 다른 쪽을 잊어 **서비스 간 인증이 깨진다.** (dockguard의 제작 배경이 된 사고에서도 서비스 매니저와 \
백엔드의 RabbitMQ 비밀번호가 서로 달라 연결이 실패했다.) 시크릿을 한 곳(.env나 secrets)에서 관리하면 \
이런 불일치도 함께 막을 수 있다.

dockguard는 이름이 PASSWORD · SECRET · TOKEN · API_KEY 등으로 보이는 환경변수에 **값이 직접 적혀 있으면** \
취약으로 판정한다. 리포트에는 값을 절대 출력하지 않고 변수 이름만 보여준다."""

    how_to_fix = """\
1. 값을 `.env` 파일로 옮기고, compose에서는 `${변수}`로 참조한다.

```bash
# .env  (compose 파일과 같은 폴더)
DB_PASSWORD=실제값
```

```yaml
services:
  app:
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
```

2. `.env`의 권한을 제한하고 git에서 제외한다. 이미 커밋된 적이 있다면 **비밀번호를 반드시 교체**한다 \
(파일을 지워도 git 기록에는 남아 있다).

```bash
chmod 600 .env
echo ".env" >> .gitignore
git rm --cached .env 2>/dev/null
```

3. 더 안전하게는 **Docker secrets**를 쓴다. 값이 환경변수가 아니라 컨테이너 안의 파일(`/run/secrets/...`)로 \
전달되어 `docker inspect`나 프로세스 환경에 드러나지 않는다. 공식 이미지 대부분이 `*_FILE` 변수를 지원한다.

```yaml
services:
  db:
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
secrets:
  db_password:
    file: ./secrets/db_password.txt   # chmod 600, .gitignore
```"""

    tradeoff = """\
- **`${VAR}` 치환용 `.env`는 compose 파일과 같은 폴더(또는 `--env-file`로 지정한 곳)에 있어야 한다.** 다른 \
폴더에서 `docker compose -f 경로/compose.yml`로 실행하면 치환이 안 되어 빈 값으로 기동될 수 있다.
- **`env_file:`과 치환용 `.env`는 다른 것이다.** `env_file:`은 컨테이너에 변수를 넣어줄 뿐, compose 파일 안의 \
`${VAR}` 치환에는 쓰이지 않는다. 둘을 혼동해 "분명 .env에 넣었는데 빈 값"이 되는 일이 흔하다.
- `${DB_PASSWORD:-기본값}`처럼 기본값을 적으면 그 기본값이 다시 평문으로 저장소에 남는다. 기본값 없이 쓰고, \
누락 시 기동을 막으려면 `${DB_PASSWORD:?DB_PASSWORD가 필요합니다}`를 쓴다.
- `.env`로 옮겨도 환경변수는 `docker inspect`로 볼 수 있다. 서버 접근 권한자까지 막아야 한다면 Docker secrets를 쓰라.
- 비밀번호를 옮기면서 값이 바뀌면, 그 비밀번호를 쓰는 **모든 서비스**(백엔드, 워커, 관리 도구)를 함께 재생성해야 한다."""

    learn_more = "https://docs.docker.com/compose/how-tos/use-secrets/"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        issues = []
        for key, value in service_environment(service):
            if value is None or not value.strip() or not is_secret_name(key):
                continue
            text = value.strip()
            if VARIABLE_PATTERN.search(text):
                match = DEFAULT_VALUE_PATTERN.search(text)
                if match and match.group(1).strip():
                    issues.append(ServiceIssue(name, f"{key} (기본값에 평문)", subject=key))
                continue
            if text.startswith(DOCKER_SECRETS_DIR):
                continue
            issues.append(ServiceIssue(name, f"{key} (평문 값)", subject=key))
        return issues

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        by_service: dict[str, list[str]] = {}
        for issue in issues:
            by_service.setdefault(issue.service, []).append(issue.subject)
        lines = ["services:"]
        for service, keys in by_service.items():
            lines += [f"  {service}:", "    environment:"]
            lines += [f"      {key}: ${{{key}}}" for key in keys]
        lines += ["", "# .env (chmod 600, .gitignore에 추가) — 값은 여기에만"]
        lines += [f"# {key}=..." for key in dict.fromkeys(i.subject for i in issues)]
        return "\n".join(lines)
