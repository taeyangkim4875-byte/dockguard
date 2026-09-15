"""공통 테스트 픽스처."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import pytest

from dockguard.core.collector import load_daemon_config
from dockguard.core.compose_loader import load_compose_project
from dockguard.core.context import (
    ComposeProject,
    ContainerInfo,
    DaemonConfig,
    DockerRuntime,
    NetworkInfo,
    PublishedPort,
    ScanContext,
)

FIXTURES = Path(__file__).parent / "fixtures"
DAEMON_FIXTURES = FIXTURES / "daemon"
COMPOSE_FIXTURES = FIXTURES / "compose"


@pytest.fixture
def daemon_fixture() -> Callable[[str], Path]:
    """`tests/fixtures/daemon/<이름>` 경로를 돌려준다."""

    def _path(name: str) -> Path:
        return DAEMON_FIXTURES / name

    return _path


def make_context(
    daemon: DaemonConfig | None = None,
    categories: set[str] | None = None,
    compose: list[ComposeProject] | None = None,
    docker: DockerRuntime | None = None,
    dependencies: list | None = None,
) -> ScanContext:
    """테스트용 ScanContext."""
    return ScanContext(
        hostname="test-host",
        scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        categories=categories or {"daemon", "compose", "network"},
        daemon=daemon,
        compose=compose,
        docker=docker,
        dependencies=dependencies or [],
    )


@pytest.fixture(autouse=True)
def no_real_docker(monkeypatch):
    """테스트가 실행 환경의 실제 Docker(개발 PC, CI 러너)에 따라 결과가 달라지지 않게 한다.

    Docker 연결이 필요한 테스트는 가짜 DockerRuntime이나 스냅샷 파일을 직접 넘긴다.
    """
    from dockguard.core import docker_runtime

    def unavailable():
        raise docker_runtime.DockerUnavailable(docker_runtime.MSG_NOT_RUNNING)

    monkeypatch.setattr(docker_runtime, "DEFAULT_BACKENDS", (unavailable,))


EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture
def incident_dir() -> Path:
    """정전 사고 재현 예시 (examples/rabbitmq-incident)."""
    return EXAMPLES / "rabbitmq-incident"


@pytest.fixture
def make_container() -> Callable[..., ContainerInfo]:
    """테스트용 컨테이너. 네트워크 이름 목록과 공개 포트((host_ip, host_port, container_port))를 받는다."""

    def _make(
        name: str,
        networks: tuple[str, ...] | list[str] = ("app-net",),
        *,
        state: str = "running",
        restart: str = "unless-stopped",
        mode: str = "default",
        ports: list[tuple[str, int, int]] | None = None,
        exposed: list[str] | None = None,
        labels: dict[str, str] | None = None,
    ) -> ContainerInfo:
        return ContainerInfo(
            id=f"{name}-{'0' * 60}"[:64],
            name=name,
            state=state,
            restart_policy=restart,
            network_mode=mode,
            networks=list(networks),
            ports=[PublishedPort(container_port=c, protocol="tcp", host_ip=ip, host_port=h) for ip, h, c in ports or []],
            exposed_ports=exposed or [],
            labels=labels or {},
        )

    return _make


@pytest.fixture
def make_runtime() -> Callable[..., DockerRuntime]:
    """테스트용 DockerRuntime. 컨테이너가 쓰는 네트워크는 자동으로 만들고, 옵션은 network_options로 준다."""

    def _make(
        containers: list[ContainerInfo],
        network_options: dict[str, dict[str, str]] | None = None,
        security_options: list[str] | None = None,
    ) -> DockerRuntime:
        names = {n for c in containers for n in c.networks} | set(network_options or {})
        networks = [NetworkInfo(id=n, name=n, options=(network_options or {}).get(n, {})) for n in sorted(names)]
        return DockerRuntime(
            available=True,
            source="test",
            containers=containers,
            networks=networks,
            security_options=security_options or [],
        )

    return _make


@pytest.fixture
def compose_fixture() -> Callable[[str], Path]:
    """`tests/fixtures/compose/<이름>` 경로를 돌려준다."""

    def _path(name: str) -> Path:
        return COMPOSE_FIXTURES / name

    return _path


@pytest.fixture
def compose_context() -> Callable[..., ScanContext]:
    """compose fixture 파일(들)을 파싱한 ScanContext. daemon 설정도 함께 줄 수 있다."""

    def _make(*names: str, daemon: dict | None = None) -> ScanContext:
        projects = [load_compose_project(COMPOSE_FIXTURES / n) for n in names]
        daemon_cfg = DaemonConfig(path=Path("/etc/docker/daemon.json"), exists=True, data=daemon) if daemon else None
        return make_context(daemon_cfg, compose=projects)

    return _make


@pytest.fixture
def context_factory() -> Callable[..., ScanContext]:
    """임의의 DaemonConfig로 ScanContext를 만드는 팩토리."""
    return make_context


@pytest.fixture
def daemon_context() -> Callable[[str], ScanContext]:
    """fixture 파일 이름으로 daemon.json을 로드한 ScanContext를 만든다."""

    def _make(name: str) -> ScanContext:
        return make_context(load_daemon_config(DAEMON_FIXTURES / name))

    return _make


@pytest.fixture
def missing_daemon_context(tmp_path: Path) -> ScanContext:
    """daemon.json이 존재하지 않는 호스트."""
    return make_context(load_daemon_config(tmp_path / "daemon.json"))
