"""DAEMON-005: 로그 드라이버 / 크기 제한."""

from __future__ import annotations

from dockguard.core.context import DaemonConfig, ScanContext
from dockguard.core.models import ApplyMethod, ConfigPatch, Finding, FixRisk, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import DaemonRule, to_json

DOCKER_DEFAULT_LOG_DRIVER = "json-file"

# 자동 수정 시 넣는 기본 로테이션 값 (컨테이너당 최대 30MB)
DEFAULT_MAX_SIZE = "10m"
DEFAULT_MAX_FILE = "3"

# 크기 제한(max-size)을 걸어야 하는 로컬 파일 드라이버
ROTATION_REQUIRED_DRIVERS = {"json-file"}
# 자체 기본 로테이션이 있는 드라이버 (local: 20MB × 5개, 압축)
SELF_ROTATING_DRIVERS = {"local"}


@register
class LogLimitRule(DaemonRule):
    id = "DAEMON-005"
    title = "로그 드라이버 / 크기 제한"
    severity = Severity.LOW
    reference = cis("2.13", "Ensure centralized and remote logging is configured", related=True)

    fix_risk = FixRisk.SAFE
    recommended = f"max-size={DEFAULT_MAX_SIZE}, max-file={DEFAULT_MAX_FILE} (또는 local/원격 드라이버)"

    why = """\
기본 로그 드라이버 `json-file`은 **로그 크기 제한이 없다.** 컨테이너가 표준 출력으로 쓰는 로그는 \
`/var/lib/docker/containers/<id>/<id>-json.log`에 끝없이 쌓이고, 디버그 로그를 켜 두었거나 에러 루프에 \
빠진 컨테이너 하나가 수십 GB를 채우는 일이 흔하다.

디스크가 가득 차면 그 컨테이너뿐 아니라 **같은 호스트의 모든 컨테이너와 Docker 데몬 자체**가 \
비정상 동작한다. DB는 쓰기에 실패하고, RabbitMQ는 디스크 여유 공간 경보(disk alarm)로 메시지 발행을 \
차단한다. 공격자가 의도적으로 대량의 로그를 유발하는 서비스 거부(DoS)에도 취약하다.

로그는 보안 사고 조사의 핵심 증거이기도 하다. **로컬 로그는 크기를 제한하고, 오래 보관할 로그는 \
중앙 로그 시스템으로 보내는 것**이 이상적이다."""

    how_to_fix = """\
1. `/etc/docker/daemon.json`에 로그 로테이션을 설정한다 (컨테이너당 10MB × 3개 = 최대 30MB).

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

압축과 기본 로테이션(20MB × 5개)이 내장된 `local` 드라이버를 써도 된다: `"log-driver": "local"`

2. Docker 데몬을 재시작하고, 기존 컨테이너는 재생성해야 적용된다.

```bash
sudo systemctl restart docker
docker compose up -d --force-recreate
```

3. 현재 로그가 차지하는 용량을 확인한다.

```bash
sudo sh -c 'du -sh /var/lib/docker/containers/*/*-json.log' | sort -h | tail
```"""

    tradeoff = """\
- 설정은 **새로 만든 컨테이너**에만 적용된다. 기존 컨테이너는 재생성 전까지 계속 무제한으로 쌓인다.
- 로테이션된 오래된 로그는 삭제되므로 `docker logs`로 볼 수 있는 기간이 짧아진다. 사고 조사를 위해 \
오래 보관해야 한다면 syslog·journald·fluentd 같은 중앙 로그 시스템으로 보내라.
- `local` 드라이버는 압축된 내부 포맷이라, `-json.log` 파일을 직접 읽던 수집기(filebeat 등)가 있다면 \
동작하지 않는다.
- 원격 로그 드라이버(fluentd, gelf 등)는 수집 서버가 죽어 있으면 컨테이너 기동이 실패하거나 느려질 수 \
있다. `"mode": "non-blocking"` 같은 옵션을 함께 검토하라."""

    learn_more = "https://docs.docker.com/engine/logging/configure/"

    def evaluate(self, daemon: DaemonConfig) -> list[Finding]:
        target = daemon.target_label
        driver = daemon.get("log-driver", DOCKER_DEFAULT_LOG_DRIVER)
        opts = daemon.get("log-opts", {})

        if not isinstance(driver, str) or not isinstance(opts, dict):
            return [self.make(Status.WARN, target=target, current="log-driver/log-opts 형식이 올바르지 않음")]

        driver_label = driver if daemon.has("log-driver") else f"{driver} (기본값)"

        if driver == "none":
            return [
                self.make(
                    Status.WARN,
                    target=target,
                    current='"log-driver": "none" — 컨테이너 로그가 전혀 남지 않음 (사고 조사 불가)',
                )
            ]
        if driver in SELF_ROTATING_DRIVERS:
            return [self.make(Status.PASS, target=target, current=f"{driver_label} (내장 로테이션)")]
        if driver not in ROTATION_REQUIRED_DRIVERS:
            return [self.make(Status.PASS, target=target, current=f"{driver_label} (외부 로그 시스템으로 전송)")]

        if "max-size" in opts:
            rotation = f"max-size={opts['max-size']}"
            if "max-file" in opts:
                rotation += f", max-file={opts['max-file']}"
            return [self.make(Status.PASS, target=target, current=f"{driver_label}, {rotation}")]

        return [self.make(Status.FAIL, target=target, current=f"{driver_label}, max-size 미설정 (로그 무제한 증가)")]

    def plan_fix(self, finding: Finding, context: ScanContext) -> ConfigPatch | None:
        if finding.status != Status.FAIL or context.daemon is None:
            return None
        daemon = context.daemon
        existing = daemon.get("log-opts", {})
        # 사용자가 이미 정한 옵션(max-file 등)은 존중하고, 빠진 max-size만 채운다
        new_opts = {"max-file": DEFAULT_MAX_FILE, **existing, "max-size": DEFAULT_MAX_SIZE}
        set_values: dict = {}
        if not daemon.has("log-driver"):
            set_values["log-driver"] = DOCKER_DEFAULT_LOG_DRIVER  # 동작 변화 없음, 의도를 명시
        set_values["log-opts"] = new_opts
        return ConfigPatch(
            rule_id=self.id,
            summary=f'"log-opts": {to_json(new_opts)}',
            set_values=set_values,
            apply_with=ApplyMethod.RESTART,
            risk=FixRisk.SAFE,
            note="새로 생성되는 컨테이너부터 적용됩니다.",
            requires_recreate=True,
        )
