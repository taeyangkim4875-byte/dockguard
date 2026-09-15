"""DAEMON-006: user namespace remapping."""

from __future__ import annotations

from dockguard.core.context import DaemonConfig, ScanContext
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import DaemonRule, to_json


@register
class UsernsRemapRule(DaemonRule):
    id = "DAEMON-006"
    title = "user namespace remapping"
    severity = Severity.HIGH
    reference = cis("2.9", "Enable user namespace support")
    recommended = '"userns-remap": "default" / rootless'

    no_autofix_reason = (
        "켜는 순간 Docker가 별도 데이터 디렉터리를 사용해 기존 이미지·컨테이너·볼륨이 보이지 않게 되고, "
        "바인드 마운트 권한 문제가 생깁니다. 데이터 이전 계획을 세운 뒤 수동으로 적용하세요."
    )

    why = """\
기본 설정에서 컨테이너 안의 root(uid 0)는 **호스트의 root(uid 0)와 같은 사용자**다. 네임스페이스·\
capability·seccomp로 할 수 있는 일이 제한돼 있을 뿐, 커널 입장에서는 같은 uid다. 그래서 컨테이너 탈출 \
취약점(예: runc 바이너리를 덮어쓰는 CVE-2019-5736)이나 잘못된 마운트(호스트 디렉터리, `docker.sock`)가 \
있으면 곧바로 **호스트 root 권한**으로 이어진다.

`userns-remap`을 켜면 리눅스 user namespace를 이용해 컨테이너 안의 uid 0을 호스트의 **권한 없는 uid**\
(예: 231072)로 매핑한다. 컨테이너 안에서는 여전히 root처럼 보이지만, 탈출하더라도 호스트에서는 아무 \
권한 없는 일반 사용자다. 컨테이너 탈출 공격의 피해를 근본적으로 줄이는 가장 강력한 방어 중 하나다.

데몬 자체를 일반 사용자로 실행하는 **rootless 모드**도 같은 효과(그 이상)를 준다."""

    how_to_fix = """\
1. **사전 점검**: 호스트 경로를 바인드 마운트하는 서비스, `privileged`·`network_mode: host`·\
`pid: host`를 쓰는 서비스를 목록으로 만든다 (아래 부작용 참고).

2. 상태가 있는 서비스(DB, RabbitMQ 등)의 볼륨을 백업한다.

```bash
docker run --rm -v rabbitmq_data:/data -v "$PWD":/backup alpine \\
  tar czf /backup/rabbitmq_data.tgz -C /data .
```

3. `/etc/docker/daemon.json`에 추가한다. `default`로 지정하면 Docker가 `dockremap` 사용자와 \
`/etc/subuid`, `/etc/subgid` 범위를 자동으로 만든다.

```json
{
  "userns-remap": "default"
}
```

4. 데몬을 재시작하고 적용 여부를 확인한다.

```bash
sudo systemctl restart docker
docker info --format '{{.SecurityOptions}}'   # name=userns 가 보여야 한다
grep dockremap /etc/subuid                    # 예: dockremap:231072:65536
```

5. 이미지를 다시 받고, 백업한 볼륨을 복원한 뒤 서비스를 기동한다.

대안: rootless 모드 — `dockerd-rootless-setuptool.sh install`"""

    tradeoff = """\
**부작용이 큰 설정이라 dockguard는 자동 수정하지 않는다.**

- **기존 이미지·컨테이너·볼륨이 "사라진 것처럼" 보인다.** userns-remap을 켜면 Docker는 \
`/var/lib/docker/231072.231072/` 같은 별도 데이터 디렉터리를 쓴다. 데이터가 지워진 것은 아니지만 \
(설정을 되돌리면 다시 보인다), 켠 직후엔 이미지 재다운로드와 named volume 데이터 이전이 필요하다. \
RabbitMQ 계정·큐가 볼륨 초기화로 사라지는 것과 똑같은 상황을 겪지 않으려면 **반드시 백업 후 진행**하라.
- **바인드 마운트 권한 문제**: 컨테이너 root가 호스트에서 uid 231072가 되므로, 호스트의 root(또는 \
1000번 사용자) 소유 디렉터리에 쓰지 못한다(`Permission denied`). 마운트 경로 소유권을 매핑된 uid로 \
바꿔야 한다 (예: `sudo chown -R 231072:231072 ./data`).
- **함께 쓸 수 없는 기능**: `--privileged`, `--network=host`, `--pid=host`는 컨테이너별로 \
`--userns=host`(compose: `userns_mode: host`)를 지정해야 동작하며, 그 컨테이너는 격리 효과를 잃는다.
- user namespace를 지원하지 않는 외부 볼륨/스토리지 드라이버는 동작하지 않을 수 있다."""

    learn_more = "https://docs.docker.com/engine/security/userns-remap/"

    def check(self, context: ScanContext) -> list[Finding]:
        # 실행 중인 데몬의 실제 상태가 있으면 우선한다 (daemon.json이 아니라 dockerd 실행 옵션으로 켠 경우도 잡힌다)
        runtime = context.docker
        if runtime is not None and runtime.available:
            target = context.daemon.target_label if context.daemon else "Docker 데몬"
            if runtime.has_security_option("rootless"):
                return [self.make(Status.PASS, target=target, current="rootless 모드 (docker info로 확인)")]
            if runtime.has_security_option("userns"):
                return [self.make(Status.PASS, target=target, current="user namespace 적용 중 (docker info로 확인)")]
        return super().check(context)

    def evaluate(self, daemon: DaemonConfig) -> list[Finding]:
        target = daemon.target_label
        if daemon.rootless:
            return [self.make(Status.PASS, target=target, current="rootless 모드 (데몬이 일반 사용자로 실행)")]

        value = daemon.get("userns-remap")
        if value is None or value == "":
            return [self.make(Status.FAIL, target=target, current="미설정 (컨테이너 root = 호스트 root)")]
        if not isinstance(value, str):
            return [self.make(Status.WARN, target=target, current=f"{to_json(value)} (문자열이어야 함)")]
        return [self.make(Status.PASS, target=target, current=to_json(value))]
