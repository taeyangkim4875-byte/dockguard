"""ScanContext: Collector가 수집한 모든 데이터를 담아 룰에 전달하는 객체.

룰은 Docker나 파일 시스템에 직접 접근하지 않고 오직 ScanContext만 본다.
덕분에 테스트에서는 가짜 ScanContext를 만들어 넣기만 하면 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FileStat:
    """POSIX 파일 소유권/권한 정보 (Windows에서는 수집하지 않는다)."""

    mode: int  # 권한 비트만 (예: 0o644)
    uid: int
    gid: int


@dataclass
class DaemonConfig:
    """daemon.json 수집 결과.

    - 파일이 없으면 `exists=False`, `data={}` — Docker는 이때 모든 항목을 기본값으로 동작하므로
      룰은 "미설정 = Docker 기본값"으로 판단해야 한다. (파일이 없다고 안전한 게 아니다!)
    - 파일은 있지만 읽기/파싱에 실패하면 `error`에 사유가 담긴다. 이 경우 룰은 SKIP한다.
    """

    path: Path
    exists: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    raw_text: str = ""  # 원본 텍스트 (수정 diff의 기준)
    stat: FileStat | None = None  # POSIX 소유권/권한 (Windows·파일 없음이면 None)
    rootless: bool = False  # rootless 모드 설정 파일(~/.config/docker/daemon.json)인지

    @property
    def usable(self) -> bool:
        """룰이 판단에 사용할 수 있는 상태인지 (파일 없음은 기본값으로 판단 가능)."""
        return self.error is None

    @property
    def user_scoped(self) -> bool:
        """시스템 파일이 아니라 사용자 소유가 정상인 설정 파일인지 (rootless, Docker Desktop)."""
        if self.rootless:
            return True
        try:
            return self.path.resolve().is_relative_to(Path.home().resolve())
        except OSError:  # pragma: no cover
            return False

    def has(self, key: str) -> bool:
        return key in self.data

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    @property
    def target_label(self) -> str:
        """Finding.target에 쓸 표시용 문자열."""
        return str(self.path) if self.exists else f"{self.path} (파일 없음)"


@dataclass
class ComposeProject:
    """compose 파일 하나(+ 자동 로드되는 override)를 파싱한 결과.

    `docker compose`처럼 같은 폴더의 `*.override.y(a)ml`을 병합해서 판단한다.
    base에는 없고 override에만 있는 설정(예: user)을 놓쳐 오탐하지 않기 위해서다.
    """

    path: Path
    services: dict[str, dict[str, Any]] = field(default_factory=dict)
    override: Path | None = None
    error: str | None = None
    name: str = ""  # compose 프로젝트 이름 (`name:` 또는 폴더 이름) — 실행 중인 컨테이너 라벨과 매칭

    @property
    def directory(self) -> Path:
        return self.path.parent

    def depends_on(self, service: str) -> list[str]:
        """서비스의 depends_on 대상 (목록/매핑 문법 모두)."""
        deps = self.services.get(service, {}).get("depends_on") or []
        if isinstance(deps, dict):
            return [str(d) for d in deps]
        if isinstance(deps, list):
            return [str(d) for d in deps]
        return []

    @property
    def label(self) -> str:
        """Finding.target 표시용 (현재 디렉터리 기준 상대 경로)."""
        try:
            shown = str(self.path.resolve().relative_to(Path.cwd().resolve()))
        except ValueError:
            shown = str(self.path)
        return f"{shown} (+ {self.override.name})" if self.override else shown


ALL_INTERFACES = {"", "0.0.0.0", "::"}
DEFAULT_BRIDGE = "bridge"
# 네트워크에 붙지 않는 특수 네트워크 모드
SPECIAL_NETWORK_MODES = {"host", "none"}


@dataclass(frozen=True)
class PublishedPort:
    """호스트에 공개된 컨테이너 포트 (docker inspect의 NetworkSettings.Ports)."""

    container_port: int
    protocol: str
    host_ip: str
    host_port: int | None

    @property
    def open_to_all(self) -> bool:
        """모든 인터페이스(0.0.0.0 / ::)에 바인딩되어 외부에서 접근 가능한지."""
        return self.host_ip in ALL_INTERFACES

    @property
    def label(self) -> str:
        host = f"[{self.host_ip}]" if ":" in self.host_ip else (self.host_ip or "0.0.0.0")
        return f"{host}:{self.host_port}->{self.container_port}/{self.protocol}"


@dataclass
class ContainerInfo:
    """실행 중이거나 멈춰 있는 컨테이너 하나 (docker inspect에서 필요한 것만)."""

    id: str
    name: str
    image: str = ""
    state: str = "running"
    restart_policy: str = "no"
    network_mode: str = "default"
    networks: list[str] = field(default_factory=list)  # 연결된 네트워크 이름
    ports: list[PublishedPort] = field(default_factory=list)
    exposed_ports: list[str] = field(default_factory=list)  # 예: "5672/tcp"
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def running(self) -> bool:
        return self.state == "running"

    @property
    def compose_project(self) -> str | None:
        return self.labels.get("com.docker.compose.project")

    @property
    def compose_service(self) -> str | None:
        return self.labels.get("com.docker.compose.service")

    @property
    def compose_config_files(self) -> list[Path]:
        raw = self.labels.get("com.docker.compose.project.config_files", "")
        return [Path(p) for p in raw.split(",") if p]

    def exposes(self, port: int) -> bool:
        return any(p.split("/")[0] == str(port) for p in self.exposed_ports)


@dataclass
class NetworkInfo:
    id: str
    name: str
    driver: str = "bridge"
    internal: bool = False
    options: dict[str, str] = field(default_factory=dict)

    @property
    def icc_disabled(self) -> bool:
        """네트워크 단위로 컨테이너 간 통신을 끈 경우 (기본 bridge는 daemon.json의 icc를 따른다)."""
        return self.options.get("com.docker.network.bridge.enable_icc", "").lower() == "false"


@dataclass
class DockerRuntime:
    """Docker 데몬에서 수집한 실제 상태. Docker에 연결하지 못하면 available=False와 사유."""

    available: bool
    source: str | None = None  # "Docker SDK" / "docker CLI" / "스냅샷 파일"
    error: str | None = None
    containers: list[ContainerInfo] = field(default_factory=list)
    networks: list[NetworkInfo] = field(default_factory=list)
    security_options: list[str] = field(default_factory=list)  # docker info의 SecurityOptions
    server_version: str | None = None
    host_name: str | None = None  # docker info의 Name (Docker가 도는 서버의 호스트 이름)

    @property
    def running_containers(self) -> list[ContainerInfo]:
        return [c for c in self.containers if c.running]

    def network(self, name: str) -> NetworkInfo | None:
        return next((n for n in self.networks if n.name == name), None)

    def find_container(self, ref: str) -> ContainerInfo | None:
        """이름 또는 ID(앞부분)로 컨테이너를 찾는다."""
        ref = ref.lstrip("/")
        for c in self.containers:
            if c.name == ref or c.id == ref or (len(ref) >= 12 and c.id.startswith(ref)):
                return c
        return None

    def effective_networks(self, container: ContainerInfo) -> list[str]:
        """`network_mode: container:<x>`면 그 컨테이너의 네트워크를 공유한다."""
        if container.network_mode.startswith("container:"):
            owner = self.find_container(container.network_mode.split(":", 1)[1])
            return list(owner.networks) if owner else []
        return list(container.networks)

    def has_security_option(self, name: str) -> bool:
        return any(f"name={name}" in opt for opt in self.security_options)


@dataclass(frozen=True)
class Dependency:
    """서비스 간 통신 의존성 하나 (A가 B의 port로 접속해야 한다)."""

    source: str  # from
    target: str  # to
    port: int | None = None
    reason: str = ""
    origin: str = ""  # 어디서 온 선언인지 (dependencies.yaml / compose depends_on)
    project: str | None = None  # compose 서비스 이름으로 찾을 때 프로젝트 범위

    @property
    def label(self) -> str:
        port = f":{self.port}" if self.port else ""
        return f"{self.source} → {self.target}{port}"


@dataclass
class ScanContext:
    """한 번의 진단에서 수집된 모든 데이터."""

    hostname: str
    scanned_at: datetime
    categories: set[str]
    daemon: DaemonConfig | None = None
    compose: list[ComposeProject] | None = None  # None = 수집하지 않음
    docker: DockerRuntime | None = None  # None = 수집하지 않음
    dependencies: list[Dependency] = field(default_factory=list)
    dependency_file: Path | None = None
    # 적용된 룰셋 (리포트에 "무엇을 껐는지" 표시하기 위함)
    ruleset_path: Path | None = None
    ruleset_summary: str = ""
    # 수집 과정에서 사용자에게 알려야 할 안내 (예: daemon.json을 찾지 못함)
    notices: list[str] = field(default_factory=list)
    # 수집 실패 (예: compose YAML 문법 오류) — 해당 대상은 점검되지 않았음을 강조해서 보여준다
    errors: list[str] = field(default_factory=list)

    @property
    def compose_projects(self) -> list[ComposeProject]:
        """정상적으로 파싱된 compose 프로젝트."""
        return [p for p in self.compose or [] if p.error is None]
