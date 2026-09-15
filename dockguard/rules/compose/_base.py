"""compose 룰 공통 베이스와 compose 문법 파서.

판정 단위: **프로젝트(compose 파일) × 룰 = Finding 1개.**
같은 문제가 서비스 5개에 있어도 Finding은 하나이고, 영향받는 서비스 목록을 current_value에 담는다.
서비스 수가 많다고 점수가 과도하게 떨어지지 않게 하고, 리포트도 룰 단위로 읽히게 하기 위해서다.

compose 파일은 자동 수정하지 않는다 (서비스 의존성이 복잡해 위험). 대신 영향받는 서비스 이름을 넣은
**수정 예시 YAML**을 how_to_fix 맨 앞에 붙여 준다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from dockguard.core.context import ComposeProject, ScanContext
from dockguard.core.models import Category, Finding, Status
from dockguard.core.rule import Rule

MAX_LISTED_ISSUES = 4  # current_value에 나열할 최대 항목 수


@dataclass
class ServiceIssue:
    """서비스 하나에서 발견된 문제."""

    service: str
    detail: str
    status: Status = Status.FAIL
    subject: str = ""  # 룰별 부가 정보 (예: 시크릿 환경변수 이름) — 수정 예시 생성에 사용


class ComposeRule(Rule):
    """compose 룰의 공통 베이스. 하위 클래스는 check_service()만 구현하면 된다."""

    category = Category.COMPOSE.value
    no_autofix_reason = (
        "compose 파일은 서비스 간 의존성이 복잡해 자동 수정하지 않습니다. "
        "`dockguard scan --explain`의 수정 예시를 참고해 직접 반영하세요."
    )

    why: str = ""
    how_to_fix: str = ""
    tradeoff: str = ""
    learn_more: str = ""
    recommended: str = ""

    def check(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for project in context.compose_projects:
            issues: list[ServiceIssue] = []
            for name, service in project.services.items():
                issues.extend(self.check_service(name, service, project, context))
            findings.append(self._summarize(project, issues))
        return findings

    def check_service(
        self, name: str, service: dict[str, Any], project: ComposeProject, context: ScanContext
    ) -> list[ServiceIssue]:
        raise NotImplementedError

    def fix_example(self, issues: list[ServiceIssue]) -> str:
        """영향받는 서비스에 맞춘 수정 예시 YAML (선택 구현)."""
        return ""

    def _summarize(self, project: ComposeProject, issues: list[ServiceIssue]) -> Finding:
        total = len(project.services)
        if not issues:
            return self._make(project, Status.PASS, f"서비스 {total}개 모두 통과", self.how_to_fix)

        status = Status.FAIL if any(i.status == Status.FAIL for i in issues) else Status.WARN
        affected = list(dict.fromkeys(i.service for i in issues))
        # 같은 내용의 문제는 서비스를 묶어서 한 번만 쓴다 ("backend, worker: user 미지정")
        grouped: dict[str, list[str]] = {}
        for issue in issues:
            services = grouped.setdefault(issue.detail, [])
            if issue.service not in services:
                services.append(issue.service)
        entries = [f"{', '.join(services)}: {detail}" for detail, services in grouped.items()]
        listed = "; ".join(entries[:MAX_LISTED_ISSUES])
        if len(entries) > MAX_LISTED_ISSUES:
            listed += f" 외 {len(entries) - MAX_LISTED_ISSUES}건"
        current = f"{len(affected)}/{total}개 서비스 — {listed}"

        example = self.fix_example(issues)
        how = f"**이 프로젝트에 적용할 수정 예시**\n\n```yaml\n{example}\n```\n\n{self.how_to_fix}" if example else self.how_to_fix
        return self._make(project, status, current, how)

    def _make(self, project: ComposeProject, status: Status, current: str, how_to_fix: str) -> Finding:
        return self.finding(
            status,
            target=project.label,
            current_value=current,
            recommended=self.recommended,
            why=self.why,
            how_to_fix=how_to_fix,
            tradeoff=self.tradeoff,
            learn_more=self.learn_more,
        )


def yaml_snippet(blocks: dict[str, list[str]]) -> str:
    """서비스별 줄 목록으로 `services:` 예시 YAML을 만든다 (주석을 넣기 위해 직접 조립)."""
    lines = ["services:"]
    for service, body in blocks.items():
        lines.append(f"  {service}:")
        lines.extend(f"    {line}" for line in body)
    return "\n".join(lines)


def is_true(value: Any) -> bool:
    """compose의 불리언 표기 (true / "true" / "yes" 등)."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "on", "1"}


# --------------------------------------------------------------------------- 이미지


@dataclass(frozen=True)
class ImageRef:
    raw: str
    name: str  # 레지스트리/경로 포함 (태그·다이제스트 제외)
    tag: str | None
    digest: str | None

    @property
    def official_name(self) -> str | None:
        """Docker Hub 공식 이미지면 이름 (예: 'postgres'), 아니면 None."""
        name = self.name
        for prefix in ("docker.io/library/", "index.docker.io/library/", "library/"):
            if name.startswith(prefix):
                name = name[len(prefix) :]
        return None if "/" in name else name


def parse_image(image: str) -> ImageRef:
    raw = image.strip()
    rest, _, digest = raw.partition("@")
    last_slash = rest.rfind("/")
    colon = rest.rfind(":")
    # 'registry:5000/app'의 콜론은 포트이므로, 마지막 경로 조각 안의 콜론만 태그로 본다
    if colon > last_slash:
        return ImageRef(raw=raw, name=rest[:colon], tag=rest[colon + 1 :], digest=digest or None)
    return ImageRef(raw=raw, name=rest, tag=None, digest=digest or None)


# --------------------------------------------------------------------------- 포트


@dataclass(frozen=True)
class PortBinding:
    host_ip: str | None  # None = 모든 인터페이스(0.0.0.0)
    host_port: int | None  # None = 호스트 포트 없음(임의 할당) 또는 변수라 알 수 없음
    host_port_end: int | None
    container_port: str
    protocol: str
    raw: str


_PORT_RANGE = re.compile(r"^(\d+)(?:-(\d+))?$")


def _port_range(text: str) -> tuple[int | None, int | None]:
    match = _PORT_RANGE.match(text.strip())
    if not match:
        return None, None
    start = int(match.group(1))
    return start, int(match.group(2)) if match.group(2) else start


def parse_port(entry: Any) -> PortBinding | None:
    """compose `ports:` 항목 하나 (짧은 문법 문자열/숫자, 긴 문법 매핑)를 해석한다."""
    if isinstance(entry, dict):
        published = entry.get("published")
        start, end = _port_range(str(published)) if published is not None else (None, None)
        return PortBinding(
            host_ip=entry.get("host_ip"),
            host_port=start,
            host_port_end=end,
            container_port=str(entry.get("target", "")),
            protocol=str(entry.get("protocol", "tcp")),
            raw=str(entry),
        )
    if isinstance(entry, int):
        return PortBinding(None, None, None, str(entry), "tcp", str(entry))
    if not isinstance(entry, str) or not entry.strip():
        return None

    text = entry.strip()
    spec, _, protocol = text.partition("/")
    host_ip: str | None = None
    if spec.startswith("["):  # [::1]:8080:80
        ip, _, spec = spec[1:].partition("]:")
        host_ip = ip
    parts = spec.rsplit(":", 2)
    if len(parts) == 3:
        host_ip, host, container = parts
    elif len(parts) == 2:
        host, container = parts
    else:
        return PortBinding(host_ip, None, None, parts[0], protocol or "tcp", text)
    start, end = _port_range(host) if host else (None, None)
    return PortBinding(host_ip or None, start, end, container, protocol or "tcp", text)


def service_ports(service: dict[str, Any]) -> list[PortBinding]:
    ports = service.get("ports") or []
    if not isinstance(ports, list):
        return []
    return [p for p in (parse_port(e) for e in ports) if p is not None]


# --------------------------------------------------------------------------- 볼륨


@dataclass(frozen=True)
class VolumeMount:
    source: str | None
    target: str | None
    read_only: bool
    raw: str


def parse_volume(entry: Any) -> VolumeMount | None:
    """compose `volumes:` 항목 하나를 해석한다 (짧은 문법 'src:dst[:mode]', 긴 문법 매핑)."""
    if isinstance(entry, dict):
        return VolumeMount(
            source=entry.get("source"),
            target=entry.get("target"),
            read_only=is_true(entry.get("read_only", False)),
            raw=str(entry),
        )
    if not isinstance(entry, str):
        return None
    parts = entry.split(":")
    if len(parts) == 1:  # 익명 볼륨 ('/data')
        return VolumeMount(None, parts[0], False, entry)
    mode = parts[2] if len(parts) > 2 else ""
    return VolumeMount(parts[0], parts[1], "ro" in mode.split(","), entry)


def service_volumes(service: dict[str, Any]) -> list[VolumeMount]:
    volumes = service.get("volumes") or []
    if not isinstance(volumes, list):
        return []
    return [v for v in (parse_volume(e) for e in volumes) if v is not None]


# --------------------------------------------------------------------------- 환경변수


def service_environment(service: dict[str, Any]) -> list[tuple[str, str | None]]:
    """`environment:` (매핑 또는 'KEY=VALUE' 목록)를 (이름, 값) 목록으로. 값이 없으면 None(셸에서 전달)."""
    env = service.get("environment")
    if isinstance(env, dict):
        return [(str(k), None if v is None else str(v)) for k, v in env.items()]
    if isinstance(env, list):
        result: list[tuple[str, str | None]] = []
        for item in env:
            key, sep, value = str(item).partition("=")
            result.append((key, value if sep else None))
        return result
    return []
