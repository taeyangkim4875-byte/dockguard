"""docker-compose 파일 탐색 · 파싱 · override 병합.

`docker compose`의 기본 동작을 따른다:
- 한 폴더에서는 `compose.yaml` > `compose.yml` > `docker-compose.yaml` > `docker-compose.yml` 중 하나만 쓴다.
- `-f` 없이 실행하면 같은 폴더의 override 파일을 자동으로 병합한다.
  (그래서 자동 탐색 시에는 override를 병합하고, 사용자가 파일을 직접 지정하면 그 파일만 본다.)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from dockguard.core.context import ComposeProject

# docker compose가 찾는 순서
COMPOSE_FILENAMES: tuple[str, ...] = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
OVERRIDE_FILENAMES: tuple[str, ...] = (
    "compose.override.yaml",
    "compose.override.yml",
    "docker-compose.override.yaml",
    "docker-compose.override.yml",
)

# 자동 탐색에서 건너뛸 디렉터리 (의존성·빌드 산출물·VCS)
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        "site-packages",
        ".idea",
        ".vscode",
    }
)
DEFAULT_SEARCH_DEPTH = 3  # 현재 디렉터리 기준 하위 몇 단계까지 찾을지


def find_project_file(directory: Path) -> Path | None:
    """폴더에서 docker compose가 사용할 compose 파일 (우선순위 순 첫 번째)."""
    for name in COMPOSE_FILENAMES:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def find_override_file(directory: Path) -> Path | None:
    for name in OVERRIDE_FILENAMES:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def discover_compose_files(root: Path, max_depth: int = DEFAULT_SEARCH_DEPTH) -> list[Path]:
    """root와 하위 폴더(max_depth 단계까지)에서 compose 파일을 찾는다."""
    root = root.resolve()
    found: list[Path] = []
    for dirpath, dirnames, _ in os.walk(root):
        current = Path(dirpath)
        depth = len(current.relative_to(root).parts)
        # 탐색 범위 제한 + 불필요한 폴더 제외 (os.walk는 dirnames를 제자리 수정하면 하위로 내려가지 않는다)
        dirnames[:] = [] if depth >= max_depth else sorted(d for d in dirnames if d not in SKIP_DIRS)
        project_file = find_project_file(current)
        if project_file is not None:
            found.append(project_file)
    return found


def deep_merge(base: Any, override: Any) -> Any:
    """compose override 병합을 단순화한 규칙: 매핑은 재귀 병합, 목록은 합집합, 값은 덮어쓰기."""
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            merged[key] = deep_merge(base[key], value) if key in base else value
        return merged
    if isinstance(base, list) and isinstance(override, list):
        return base + [item for item in override if item not in base]
    return override


def _read_yaml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except PermissionError:
        return None, "파일을 읽을 권한이 없습니다."
    except OSError as exc:
        return None, f"파일을 읽을 수 없습니다: {exc}"
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"{mark.line + 1}행 {mark.column + 1}열: " if mark is not None else ""
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        return None, f"YAML 문법 오류 ({where}{problem})"
    if data is None:
        return {}, None
    if not isinstance(data, dict):
        return None, "최상위 값이 매핑(key: value)이 아닙니다."
    return data, None


def load_compose_project(path: Path, override: Path | None = None) -> ComposeProject:
    """compose 파일을 파싱한다. 실패해도 예외 대신 error에 사유를 담는다."""
    data, error = _read_yaml(path)
    if error is not None:
        return ComposeProject(path=path, error=error)

    applied_override: Path | None = None
    if override is not None:
        extra, override_error = _read_yaml(override)
        if override_error is not None:
            return ComposeProject(path=path, override=override, error=f"{override.name}: {override_error}")
        data = deep_merge(data, extra)
        applied_override = override

    services = data.get("services")
    if not isinstance(services, dict) or not services:
        return ComposeProject(
            path=path, override=applied_override, error="services 항목이 없습니다 (compose 파일이 아닌 것 같습니다)."
        )
    # `svc:`처럼 값이 비어 있는 서비스도 빈 설정으로 취급
    normalized = {str(name): (cfg if isinstance(cfg, dict) else {}) for name, cfg in services.items()}
    return ComposeProject(path=path, services=normalized, override=applied_override)


def collect_compose_projects(targets: list[Path] | None, search_root: Path) -> list[ComposeProject]:
    """사용자가 지정한 파일/폴더(또는 search_root 자동 탐색)에서 compose 프로젝트를 모은다.

    - 파일을 직접 지정: 그 파일만 파싱 (`docker compose -f`와 같음, override 병합 안 함)
    - 폴더를 지정하거나 자동 탐색: 폴더마다 compose 파일 + override 병합
    """
    projects: list[ComposeProject] = []
    seen: set[Path] = set()

    def add(path: Path, override: Path | None) -> None:
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            projects.append(load_compose_project(path, override))

    for target in targets or [search_root]:
        if target.is_dir():
            for file in discover_compose_files(target):
                add(file, find_override_file(file.parent))
        else:
            add(target, None)
    return projects
