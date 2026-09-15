"""ScanContext: Collector가 수집한 모든 데이터를 담아 룰에 전달하는 객체.

룰은 Docker나 파일 시스템에 직접 접근하지 않고 오직 ScanContext만 본다.
덕분에 테스트에서는 가짜 ScanContext를 만들어 넣기만 하면 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


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

    @property
    def usable(self) -> bool:
        """룰이 판단에 사용할 수 있는 상태인지 (파일 없음은 기본값으로 판단 가능)."""
        return self.error is None

    def has(self, key: str) -> bool:
        return key in self.data

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    @property
    def target_label(self) -> str:
        """Finding.target에 쓸 표시용 문자열."""
        return str(self.path) if self.exists else f"{self.path} (파일 없음)"


@dataclass
class ScanContext:
    """한 번의 진단에서 수집된 모든 데이터."""

    hostname: str
    scanned_at: datetime
    categories: set[str]
    daemon: DaemonConfig | None = None
    # 수집 과정에서 사용자에게 알려야 할 안내 (예: daemon.json을 찾지 못함)
    notices: list[str] = field(default_factory=list)
