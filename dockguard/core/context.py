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

    @property
    def directory(self) -> Path:
        return self.path.parent

    @property
    def label(self) -> str:
        """Finding.target 표시용 (현재 디렉터리 기준 상대 경로)."""
        try:
            shown = str(self.path.resolve().relative_to(Path.cwd().resolve()))
        except ValueError:
            shown = str(self.path)
        return f"{shown} (+ {self.override.name})" if self.override else shown


@dataclass
class ScanContext:
    """한 번의 진단에서 수집된 모든 데이터."""

    hostname: str
    scanned_at: datetime
    categories: set[str]
    daemon: DaemonConfig | None = None
    compose: list[ComposeProject] | None = None  # None = 수집하지 않음
    # 수집 과정에서 사용자에게 알려야 할 안내 (예: daemon.json을 찾지 못함)
    notices: list[str] = field(default_factory=list)
    # 수집 실패 (예: compose YAML 문법 오류) — 해당 대상은 점검되지 않았음을 강조해서 보여준다
    errors: list[str] = field(default_factory=list)

    @property
    def compose_projects(self) -> list[ComposeProject]:
        """정상적으로 파싱된 compose 프로젝트."""
        return [p for p in self.compose or [] if p.error is None]
