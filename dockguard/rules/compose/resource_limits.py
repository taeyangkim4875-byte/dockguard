"""COMPOSE-007: 리소스(CPU/메모리) 제한."""

from __future__ import annotations

from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.compose._base import ComposeRule, ServiceIssue, yaml_snippet


def _deploy_limits(service: dict[str, Any]) -> dict[str, Any]:
    deploy = service.get("deploy")
    if not isinstance(deploy, dict):
        return {}
    resources = deploy.get("resources")
    if not isinstance(resources, dict):
        return {}
    limits = resources.get("limits")
    return limits if isinstance(limits, dict) else {}


def has_memory_limit(service: dict[str, Any]) -> bool:
    return bool(service.get("mem_limit") or _deploy_limits(service).get("memory"))


def has_cpu_limit(service: dict[str, Any]) -> bool:
    keys = ("cpus", "cpu_quota", "cpu_shares")
    return any(service.get(k) for k in keys) or bool(_deploy_limits(service).get("cpus"))


@register
class ResourceLimitsRule(ComposeRule):
    id = "COMPOSE-007"
    title = "리소스(CPU/메모리) 제한"
    severity = Severity.MEDIUM
    reference = cis("5.11 / 5.12", "Ensure that the memory usage / CPU priority for containers is set")
    recommended = "deploy.resources.limits에 memory · cpus"

    why = """\
리소스 제한이 없는 컨테이너는 **호스트의 CPU와 메모리를 전부 쓸 수 있다.** 메모리 누수, 무한 루프, 트래픽 \
폭주, 또는 공격자의 의도적인 부하(DoS) 하나로 같은 호스트의 **모든 서비스가 함께 멈춘다.**

메모리가 바닥나면 리눅스 커널의 OOM Killer가 프로세스를 강제 종료하는데, 어떤 프로세스를 죽일지는 \
커널이 정한다. 문제를 일으킨 컨테이너가 아니라 **DB나 메시지큐가 대신 죽는** 일이 실제로 흔하다.

메모리 제한을 걸면 문제를 일으킨 컨테이너만 제한에 걸려 재시작되고, 다른 서비스는 보호된다. dockguard는 \
메모리 제한이 없으면 취약, 메모리만 있고 CPU 제한이 없으면 주의로 판정한다."""

    how_to_fix = """\
1. 현재 사용량을 확인해 제한값을 정한다 (평상시 사용량의 1.5~2배에서 시작).

```bash
docker stats --no-stream
```

2. compose에 제한을 추가한다. Compose V2(`docker compose`)는 스웜 모드가 아니어도 `deploy.resources`를 적용한다.

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
    pids_limit: 200        # fork bomb 방지 (CIS 5.29)
```"""

    tradeoff = """\
- **메모리 제한을 너무 낮게 잡으면 OOM으로 컨테이너가 반복 재시작된다.** `docker inspect <컨테이너> --format \
'{{.State.OOMKilled}}'`로 확인할 수 있다. 여유 있게 시작해서 모니터링하며 줄여라.
- JVM(Java), Node.js, Elasticsearch 등은 **힙 크기를 컨테이너 메모리 제한에 맞춰 따로 설정**해야 한다 \
(예: `-Xmx`, `--max-old-space-size`, `ES_JAVA_OPTS`). 힙이 제한보다 크면 곧바로 OOM이 난다.
- RabbitMQ는 메모리 사용량이 제한의 일정 비율(`vm_memory_high_watermark`)을 넘으면 **메시지 발행을 차단**한다. \
제한을 걸면 이 기준도 함께 줄어드므로 큐 적체가 많은 서비스는 여유를 두라.
- CPU 제한은 초과 시 죽이지 않고 느리게(throttling) 만든다. 응답 지연이 생기면 CPU 제한부터 의심하라."""

    learn_more = "https://docs.docker.com/reference/compose-file/deploy/#resources"

    def check_service(self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext):
        memory, cpu = has_memory_limit(service), has_cpu_limit(service)
        if memory and cpu:
            return []
        if not memory:
            detail = "memory · cpu 제한 없음" if not cpu else "memory 제한 없음"
            return [ServiceIssue(name, detail)]
        return [ServiceIssue(name, "cpu 제한 없음", Status.WARN)]

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        body = ["deploy:", "  resources:", "    limits:", '      cpus: "1.0"', "      memory: 512M   # docker stats로 사용량 확인 후 조정"]
        return yaml_snippet({i.service: body for i in issues})
