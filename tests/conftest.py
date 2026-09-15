"""공통 테스트 픽스처."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import pytest

from dockguard.core.collector import load_daemon_config
from dockguard.core.compose_loader import load_compose_project
from dockguard.core.context import ComposeProject, DaemonConfig, ScanContext

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
) -> ScanContext:
    """테스트용 ScanContext."""
    return ScanContext(
        hostname="test-host",
        scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        categories=categories or {"daemon", "compose"},
        daemon=daemon,
        compose=compose,
    )


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
