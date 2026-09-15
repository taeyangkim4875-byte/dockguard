"""DAEMON-004: live-restore 활성화."""

from dockguard.core.models import Severity
from dockguard.core.rule import register
from dockguard.rules.daemon._base import BooleanDaemonRule


@register
class LiveRestoreRule(BooleanDaemonRule):
    id = "DAEMON-004"
    title = "live-restore 활성화"
    severity = Severity.LOW
    reference = "CIS Docker Benchmark 2.14 — Ensure live restore is enabled"

    key = "live-restore"
    recommended_value = True
    docker_default = False

    why = """\
기본 설정에서는 Docker 데몬(`dockerd`)이 종료되면 그 위에서 돌던 **모든 컨테이너도 함께 중지**된다. \
데몬 업그레이드, 설정 변경을 위한 재시작, 데몬 크래시가 곧바로 전체 서비스 중단으로 이어진다.

`live-restore: true`를 켜면 데몬이 내려가 있는 동안에도 컨테이너는 계속 실행되고, 데몬이 다시 \
올라오면 실행 중인 컨테이너에 재연결한다. 보안의 3요소(기밀성·무결성·**가용성**) 중 가용성을 높이는 \
설정이다. 또한 Docker 보안 패치를 적용할 때 서비스 중단 부담이 줄어들어, 패치를 미루지 않게 되는 \
효과도 있다."""

    how_to_fix = """\
1. `/etc/docker/daemon.json`에 추가한다.

```json
{
  "live-restore": true
}
```

2. `live-restore`는 데몬 재시작 없이 **설정 리로드**(SIGHUP)만으로 적용할 수 있다.

```bash
sudo systemctl reload docker
# 또는: sudo kill -SIGHUP $(pidof dockerd)
```

3. 적용 여부를 확인한다.

```bash
docker info --format '{{.LiveRestoreEnabled}}'
```"""

    tradeoff = """\
- **호스트 재부팅(예: 정전)에는 효과가 없다.** live-restore는 데몬 프로세스만 내려가는 상황을 위한 \
기능이다. 서버 자체가 꺼지면 컨테이너도 종료되며, 재부팅 후 서비스가 자동으로 올라오게 하려면 각 \
컨테이너에 `restart: unless-stopped`(또는 `always`) 재시작 정책이 필요하다. 이때 컨테이너 기동 \
순서는 보장되지 않으므로, 메시지큐·DB가 늦게 뜨는 경우를 대비한 재접속 로직도 확인하라.
- 데몬이 오래 내려가 있으면 데몬이 읽어 가던 컨테이너 로그 버퍼(기본 64KB)가 가득 차서, 로그를 \
출력하는 컨테이너가 **블로킹**될 수 있다. 데몬 다운타임은 짧게 유지해야 한다.
- 업그레이드 시 컨테이너 유지는 패치 릴리스(YY.MM.x) 사이에서만 지원되고, 메이저 버전(YY.MM) \
업그레이드에서는 컨테이너가 재시작될 수 있다.
- Swarm 서비스에는 적용되지 않는다 (단독 컨테이너만 대상)."""

    learn_more = "https://docs.docker.com/engine/daemon/live-restore/"
