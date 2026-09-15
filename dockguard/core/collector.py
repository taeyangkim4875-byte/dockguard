"""Collector: 진단에 필요한 데이터를 수집해 ScanContext를 만든다.

수집 실패는 예외로 터뜨리지 않고 ScanContext에 사유를 기록한다.
("권한이 없어서 못 읽었다"도 사용자에게 유용한 진단 결과다.)
"""

from __future__ import annotations

import json
import os
import socket
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable

from dockguard.core.compose_loader import DEFAULT_SEARCH_DEPTH, collect_compose_projects
from dockguard.core.context import ComposeProject, DaemonConfig, FileStat, ScanContext
from dockguard.core.models import Category

# 리눅스 표준 경로. 파일이 어디에도 없을 때 "여기에 만들면 된다"는 안내에도 쓴다.
LINUX_DAEMON_CONFIG = Path("/etc/docker/daemon.json")


def rootless_daemon_config() -> Path:
    """rootless 모드 dockerd가 읽는 daemon.json 경로."""
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return xdg / "docker" / "daemon.json"


def daemon_config_candidates() -> list[Path]:
    """플랫폼별 daemon.json 후보 경로 (우선순위 순)."""
    home = Path.home()
    if sys.platform.startswith("linux"):
        return [LINUX_DAEMON_CONFIG, rootless_daemon_config()]
    if sys.platform == "darwin":
        return [home / ".docker" / "daemon.json"]  # Docker Desktop
    if sys.platform == "win32":
        program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        return [
            home / ".docker" / "daemon.json",  # Docker Desktop
            program_data / "docker" / "config" / "daemon.json",  # Windows 컨테이너 엔진
        ]
    return [LINUX_DAEMON_CONFIG]


def find_daemon_config(candidates: Iterable[Path] | None = None) -> Path | None:
    """존재하는 첫 번째 daemon.json 경로. 없으면 None."""
    for path in candidates if candidates is not None else daemon_config_candidates():
        if path.is_file():
            return path
    return None


def _file_stat(path: Path) -> FileStat | None:
    """POSIX에서만 소유권/권한을 수집한다 (Windows의 stat 권한 비트는 의미가 없다)."""
    if os.name != "posix":
        return None
    try:
        st = path.stat()
    except OSError:
        return None
    return FileStat(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)


def load_daemon_config(path: Path, rootless: bool = False) -> DaemonConfig:
    """daemon.json을 읽어 DaemonConfig로 만든다. 실패해도 예외를 던지지 않는다."""
    if not path.exists():
        return DaemonConfig(path=path, exists=False, rootless=rootless)

    base = {"path": path, "exists": True, "stat": _file_stat(path), "rootless": rootless}
    try:
        # Windows 편집기가 붙이는 BOM도 허용
        text = path.read_text(encoding="utf-8-sig")
    except PermissionError:
        return DaemonConfig(**base, error="파일을 읽을 권한이 없습니다. sudo로 다시 실행해 보세요.")
    except OSError as exc:
        return DaemonConfig(**base, error=f"파일을 읽을 수 없습니다: {exc}")

    if not text.strip():
        # 빈 파일은 Docker도 설정 없음으로 취급한다
        return DaemonConfig(**base, data={}, raw_text=text)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return DaemonConfig(
            **base,
            raw_text=text,
            error=(
                f"JSON 파싱 실패 ({exc.lineno}행 {exc.colno}열: {exc.msg}). "
                "이 상태로는 Docker 데몬이 시작되지 않습니다."
            ),
        )
    if not isinstance(data, dict):
        return DaemonConfig(**base, raw_text=text, error="최상위 값이 JSON 객체({ ... })가 아닙니다.")
    return DaemonConfig(**base, data=data, raw_text=text)


def collect(
    categories: Iterable[str] | None = None,
    daemon_config_path: Path | None = None,
    compose_paths: list[Path] | None = None,
    search_root: Path | None = None,
) -> ScanContext:
    """요청된 카테고리에 필요한 데이터만 수집한다.

    Args:
        categories: 점검할 카테고리. None이면 전체.
        daemon_config_path: daemon.json 경로를 직접 지정 (None이면 자동 탐색).
        compose_paths: compose 파일 또는 폴더 (None이면 search_root에서 자동 탐색).
        search_root: compose 자동 탐색 시작 폴더 (기본: 현재 디렉터리).
    """
    selected = set(categories) if categories else {c.value for c in Category}
    context = ScanContext(
        hostname=socket.gethostname(),
        scanned_at=datetime.now().astimezone(),
        categories=selected,
    )

    daemon_selected = Category.DAEMON.value in selected
    compose_selected = Category.COMPOSE.value in selected
    # compose 룰도 daemon 설정을 참고한다 (예: 데몬 기본 no-new-privileges, userns-remap)
    if daemon_selected or compose_selected:
        context.daemon = _collect_daemon(context, daemon_config_path, announce=daemon_selected)
    if compose_selected:
        context.compose = _collect_compose(context, compose_paths, search_root or Path.cwd())

    return context


def _collect_compose(context: ScanContext, targets: list[Path] | None, search_root: Path) -> list[ComposeProject]:
    projects = collect_compose_projects(targets, search_root)
    if not projects:
        where = "지정한 폴더" if targets else "현재 디렉터리"
        context.notices.append(
            f"{where}와 하위 {DEFAULT_SEARCH_DEPTH}단계에서 compose 파일을 찾지 못했습니다. "
            "(--compose 로 파일이나 폴더를 지정하세요)"
        )
    for project in projects:
        if project.error is not None:
            context.errors.append(f"compose 파일을 점검하지 못했습니다 — {project.label}: {project.error}")
    return projects


def _is_rootless_path(path: Path) -> bool:
    return sys.platform.startswith("linux") and path == rootless_daemon_config()


def _collect_daemon(context: ScanContext, explicit_path: Path | None, announce: bool = True) -> DaemonConfig:
    if explicit_path is not None:
        return load_daemon_config(explicit_path, rootless=_is_rootless_path(explicit_path))

    found = find_daemon_config()
    if found is not None:
        return load_daemon_config(found, rootless=_is_rootless_path(found))

    # 어디에도 없으면 표준 경로 기준으로 "파일 없음" 처리 → 룰은 Docker 기본값으로 판단
    fallback = daemon_config_candidates()[0]
    if announce:
        context.notices.append(
            "daemon.json을 찾지 못했습니다. Docker 기본값 기준으로 점검합니다. "
            "(다른 위치에 있다면 --daemon-config 로 지정하세요)"
        )
    return DaemonConfig(path=fallback, exists=False)
