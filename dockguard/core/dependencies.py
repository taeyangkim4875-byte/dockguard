"""서비스 의존성 선언 로드와 compose `depends_on` 추론.

의존성은 두 곳에서 온다.
1. 사용자가 쓴 `dependencies.yaml` — "backend가 rabbitmq:5672에 붙어야 한다"를 명시적으로 선언
2. compose 파일의 `depends_on` — 선언 파일이 없어도 기본적인 검증이 되도록 자동 추론
   (이 호스트에서 실제로 실행 중인 compose 프로젝트만 대상)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from dockguard.core.context import ComposeProject, Dependency, DockerRuntime

# --deps를 주지 않았을 때 현재 디렉터리에서 찾는 위치
DEPENDENCY_FILE_CANDIDATES: tuple[str, ...] = (
    "dependencies.yaml",
    "dependencies.yml",
    "config/dependencies.yaml",
    "config/dependencies.yml",
    ".dockguard/dependencies.yaml",
)


class DependencyFileError(Exception):
    """의존성 파일 형식 오류. 메시지는 사용자에게 그대로 보여준다."""


def find_dependency_file(root: Path) -> Path | None:
    for name in DEPENDENCY_FILE_CANDIDATES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def _parse_port(value: Any, index: int) -> int | None:
    if value is None or value == "":
        return None
    try:
        port = int(str(value))
    except ValueError:
        raise DependencyFileError(f"{index}번째 항목: port는 숫자여야 합니다 ({value!r})") from None
    if not 0 < port < 65536:
        raise DependencyFileError(f"{index}번째 항목: port 범위(1~65535)를 벗어났습니다 ({port})")
    return port


def load_dependency_file(path: Path) -> list[Dependency]:
    """dependencies.yaml을 읽는다. 형식이 틀리면 어디가 틀렸는지 알려주는 DependencyFileError."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise DependencyFileError(f"파일을 읽을 수 없습니다: {exc}") from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" ({mark.line + 1}행 {mark.column + 1}열)" if mark is not None else ""
        raise DependencyFileError(f"YAML 문법 오류{where}") from exc

    items = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise DependencyFileError("최상위에 `dependencies:` 목록이 있어야 합니다 (config/dependencies.example.yaml 참고).")

    dependencies: list[Dependency] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict) or not str(item.get("from") or "").strip() or not str(item.get("to") or "").strip():
            raise DependencyFileError(f"{index}번째 항목: `from`과 `to`가 모두 필요합니다.")
        dependencies.append(
            Dependency(
                source=str(item["from"]).strip(),
                target=str(item["to"]).strip(),
                port=_parse_port(item.get("port"), index),
                reason=str(item.get("reason") or "").strip(),
                origin=path.name,
            )
        )
    return dependencies


def project_is_running(project: ComposeProject, runtime: DockerRuntime) -> bool:
    """이 호스트에 해당 compose 프로젝트의 컨테이너가 하나라도 있는지."""
    path = project.path.resolve()
    for container in runtime.containers:
        if container.compose_project == project.name:
            return True
        if any(_same_path(f, path) for f in container.compose_config_files):
            return True
    return False


def _same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b
    except OSError:  # pragma: no cover
        return False


def infer_compose_dependencies(projects: list[ComposeProject], runtime: DockerRuntime) -> list[Dependency]:
    """실행 중인 compose 프로젝트의 depends_on을 의존성으로 바꾼다."""
    inferred: list[Dependency] = []
    for project in projects:
        if not project_is_running(project, runtime):
            continue
        for service, config in project.services.items():
            mode = str(config.get("network_mode", ""))
            if mode.startswith(("service:", "container:")):
                continue  # 다른 서비스의 네트워크를 그대로 공유하므로 검증할 필요 없음
            for target in project.depends_on(service):
                inferred.append(
                    Dependency(
                        source=service,
                        target=target,
                        reason=f"compose depends_on ({project.path.name})",
                        origin="compose depends_on",
                        project=project.name,
                    )
                )
    return inferred
