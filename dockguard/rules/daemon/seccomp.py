"""DAEMON-008: 기본 seccomp 프로파일 유지."""

from __future__ import annotations

from pathlib import Path

from dockguard.core.context import DaemonConfig
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import DaemonRule, to_json

# Docker 기본 프로파일을 뜻하는 값
BUILTIN_PROFILE_VALUES = {"builtin", "default"}


@register
class SeccompProfileRule(DaemonRule):
    id = "DAEMON-008"
    title = "기본 seccomp 프로파일 유지"
    severity = Severity.HIGH
    reference = cis("5.22 / 2.17", "Ensure the default seccomp profile is not Disabled")
    recommended = "기본 프로파일 (seccomp-profile 미설정)"

    no_autofix_reason = (
        "unconfined로 설정한 데에는 특정 컨테이너의 요구가 있었을 수 있습니다. "
        "필요한 시스템 콜을 확인한 뒤 수동으로 적용하세요."
    )

    why = """\
seccomp(secure computing mode)는 프로세스가 호출할 수 있는 **리눅스 시스템 콜을 제한**하는 커널 \
기능이다. Docker는 기본적으로 300여 개 시스템 콜 중 위험한 약 44개(`mount`, `reboot`, `kexec_load`, \
`keyctl`, `unshare`, 커널 모듈 로딩 등)를 차단하는 프로파일을 모든 컨테이너에 적용한다.

컨테이너 탈출과 커널 권한 상승 공격의 상당수는 특정 시스템 콜을 통해 커널 취약점을 건드린다. \
기본 seccomp 프로파일은 이런 공격 표면을 줄이는 **마지막 방어선** 중 하나로, 실제로 여러 커널 \
취약점(예: `keyctl`을 이용한 CVE-2016-0728)이 이 프로파일 덕분에 컨테이너 안에서는 악용되지 않았다.

daemon.json에서 `"seccomp-profile": "unconfined"`로 설정하면 **모든 컨테이너**에서 이 보호가 사라진다."""

    how_to_fix = """\
1. `/etc/docker/daemon.json`에서 `"seccomp-profile": "unconfined"` 줄을 삭제한다 (기본 프로파일로 복귀).

2. 특정 컨테이너가 차단된 시스템 콜을 꼭 써야 한다면, 데몬 전체를 푸는 대신 **그 컨테이너에만** \
커스텀 프로파일을 적용한다. Docker 기본 프로파일을 받아 필요한 시스템 콜만 허용 목록에 추가하면 된다.

```bash
curl -fsSL -o seccomp-custom.json \\
  https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json
```

```yaml
services:
  app:
    security_opt:
      - seccomp:./seccomp-custom.json
```

3. Docker 데몬을 재시작하고 확인한다.

```bash
sudo systemctl restart docker
docker info --format '{{.SecurityOptions}}'   # name=seccomp,profile=builtin
```"""

    tradeoff = """\
- `unconfined`를 쓰던 이유가 있었을 수 있다. 특정 시스템 콜이 필요한 컨테이너(일부 모니터링·디버깅 \
도구, 컨테이너 안에서 다시 컨테이너를 띄우는 Docker-in-Docker 등)는 기본 프로파일에서 \
`Operation not permitted`로 실패한다. 이런 경우 데몬 전체가 아니라 해당 컨테이너에만 필요한 시스템 \
콜을 허용한 커스텀 프로파일을 적용하라.
- 커스텀 프로파일 경로가 잘못되었거나 JSON이 깨져 있으면 **Docker 데몬이 시작되지 않는다.** 적용 후 \
반드시 `systemctl status docker`로 확인하라.
- 데몬 재시작이 필요하므로 `live-restore`가 꺼져 있다면 모든 컨테이너가 재기동된다."""

    learn_more = "https://docs.docker.com/engine/security/seccomp/"

    def evaluate(self, daemon: DaemonConfig) -> list[Finding]:
        target = daemon.target_label
        value = daemon.get("seccomp-profile")

        if value is None or value == "":
            return [self.make(Status.PASS, target=target, current="미설정 (Docker 기본 seccomp 프로파일 적용)")]
        if not isinstance(value, str):
            return [self.make(Status.WARN, target=target, current=f"{to_json(value)} (문자열이어야 함)")]
        if value.lower() == "unconfined":
            return [self.make(Status.FAIL, target=target, current='"unconfined" — 모든 컨테이너의 seccomp 보호 해제')]
        if value.lower() in BUILTIN_PROFILE_VALUES:
            return [self.make(Status.PASS, target=target, current=f"{to_json(value)} (Docker 기본 프로파일)")]
        if not Path(value).is_file():
            return [
                self.make(
                    Status.WARN,
                    target=target,
                    current=f"커스텀 프로파일 {value} — 파일을 찾을 수 없음 (데몬 기동 실패 위험)",
                )
            ]
        return [self.make(Status.PASS, target=target, current=f"커스텀 프로파일 {value}")]
