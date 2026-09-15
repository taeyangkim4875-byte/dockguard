"""룰 패키지 — 하위 모듈을 자동으로 import해서 `@register`가 실행되게 한다.

`rules/daemon`, `rules/compose`, `rules/network` (그리고 앞으로 추가될 어떤 하위 패키지든)
아래의 모든 모듈을 재귀적으로 불러온다. 새 룰은 파일만 추가하면 된다.
"""

from __future__ import annotations

import importlib
import pkgutil

_loaded = False


def load_all_rules() -> None:
    """rules 패키지 아래 모든 모듈을 import한다 (여러 번 호출해도 안전)."""
    global _loaded
    if _loaded:
        return
    for module_info in pkgutil.walk_packages(__path__, prefix=f"{__name__}."):
        importlib.import_module(module_info.name)
    _loaded = True
