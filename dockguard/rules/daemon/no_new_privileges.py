"""DAEMON-002: no-new-privileges 기본 활성화."""

from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.rules.daemon._base import BooleanDaemonRule


@register
class NoNewPrivilegesRule(BooleanDaemonRule):
    id = "DAEMON-002"
    title = "no-new-privileges 기본 활성화"
    severity = Severity.HIGH
    reference = (
        "CIS Docker Benchmark 2.18 — Ensure that containers are restricted "
        "from acquiring new privileges"
    )

    key = "no-new-privileges"
    recommended_value = True
    docker_default = False

    why = """\
리눅스에서 setuid/setgid 비트가 설정된 실행 파일(`sudo`, `su`, `passwd`, `mount` 등)은 실행하는 순간 \
파일 소유자(보통 root)의 권한을 얻는다. 컨테이너 안의 프로세스가 일반 사용자로 실행 중이더라도, \
이미지 안에 이런 바이너리가 남아 있으면 **권한 상승(privilege escalation)의 통로**가 된다.

`no-new-privileges`는 리눅스 커널의 `PR_SET_NO_NEW_PRIVS` 플래그를 컨테이너 프로세스에 설정해서, \
이후 어떤 프로그램을 실행하더라도 setuid/setgid 비트나 파일 capability로 **새 권한을 얻지 못하게** \
막는다. 한 번 설정되면 자식 프로세스까지 상속되고 되돌릴 수 없다.

daemon.json에서 켜면 이 옵션이 **모든 새 컨테이너의 기본값**이 된다. compose 파일마다 \
`security_opt`를 빠뜨리는 실수를 데몬 차원에서 막을 수 있고, 공격자가 웹 애플리케이션 취약점으로 \
컨테이너 셸을 얻었을 때 root로 올라가는 가장 흔한 경로 하나를 차단한다."""

    how_to_fix = """\
1. `/etc/docker/daemon.json`에 추가한다.

```json
{
  "no-new-privileges": true
}
```

2. Docker 데몬을 재시작한다.

```bash
sudo systemctl restart docker
```

3. 이 기본값은 **새로 생성되는 컨테이너**에만 적용된다. 기존 컨테이너는 재생성해야 반영된다.

```bash
docker compose up -d --force-recreate
```

데몬 전체에 적용하기 부담스럽다면 우선 서비스별로 compose에 지정할 수도 있다 (COMPOSE-003 참고).

```yaml
services:
  app:
    security_opt:
      - no-new-privileges:true
```"""

    tradeoff = """\
- 컨테이너 안에서 **setuid 바이너리에 의존하는 동작이 실패**한다. 예: 일반 사용자로 시작한 뒤 \
`sudo`/`su`로 root 권한을 얻는 엔트리포인트 스크립트. 이때 `sudo: The "no new privileges" flag is set, \
which prevents sudo from running as root.` 같은 에러가 난다.
  - 반대로 root로 시작해서 `gosu`/`su-exec`로 권한을 **내리는** 방식(공식 postgres·redis·rabbitmq \
이미지 등)은 권한 상승이 아니므로 영향이 없다.
- 데몬 재시작이 필요하므로 `live-restore`가 꺼져 있다면 **모든 컨테이너가 재기동**된다. \
서비스 기동 순서와 의존성(예: 메시지큐가 먼저 떠야 하는 백엔드)을 미리 확인하라.
- 기존 컨테이너는 재생성해야 적용되는데, 이때 `docker compose down` 후 `up`을 하면 익명 볼륨에 \
있던 데이터(예: named volume 없이 운영한 RabbitMQ의 계정·큐)가 새 볼륨으로 바뀌어 사라진 것처럼 \
보일 수 있다. 재생성은 `docker compose up -d --force-recreate`로 하고, 상태가 있는 서비스는 반드시 \
named volume을 사용하라."""

    learn_more = "https://docs.docker.com/reference/cli/dockerd/"
