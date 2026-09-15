"""룰셋 — 조직 상황에 맞게 룰을 끄거나 심각도를 조정한다 (config/ruleset.example.yaml 참고).

모든 환경에 모든 권고가 맞지는 않는다. 예를 들어 루트 파일시스템에 쓰는 레거시 앱은 당장 read_only를 켤 수 없다.
이런 예외를 코드 대신 설정 파일로 선언하고, 리포트에는 "무엇을 껐는지"를 항상 표시해 예외가 숨지 않게 한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

from dockguard.core.models import Severity

RULESET_FILE_CANDIDATES: tuple[str, ...] = ("ruleset.yaml", "ruleset.yml", "config/ruleset.yaml", "config/ruleset.yml")
SYSTEM_RULESET_FILE = Path("/etc/dockguard/ruleset.yaml")


class RulesetError(Exception):
    """룰셋 파일 형식 오류. 메시지는 사용자에게 그대로 보여준다."""


@dataclass
class Ruleset:
    path: Path | None = None
    disabled: set[str] = field(default_factory=set)
    severity: dict[str, Severity] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.disabled and not self.severity

    def summary(self) -> str:
        parts = []
        if self.disabled:
            parts.append(f"비활성 {', '.join(sorted(self.disabled))}")
        if self.severity:
            parts.append("심각도 조정 " + ", ".join(f"{rid}→{sev.name}" for rid, sev in sorted(self.severity.items())))
        return " · ".join(parts) or "변경 없음"


def find_ruleset_file(root: Path, system_file: Path = SYSTEM_RULESET_FILE) -> Path | None:
    for name in RULESET_FILE_CANDIDATES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return system_file if system_file.is_file() else None


def load_ruleset(path: Path, known_rule_ids: Iterable[str]) -> Ruleset:
    """룰셋 파일을 읽는다. 없는 룰 ID나 잘못된 심각도는 오타일 가능성이 높아 오류로 알린다."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    except OSError as exc:
        raise RulesetError(f"파일을 읽을 수 없습니다: {exc}") from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" ({mark.line + 1}행 {mark.column + 1}열)" if mark is not None else ""
        raise RulesetError(f"YAML 문법 오류{where}") from exc
    if not isinstance(data, dict):
        raise RulesetError("최상위는 `disabled:` / `severity:` 키를 가진 매핑이어야 합니다.")

    unknown_keys = set(data) - {"disabled", "severity"}
    if unknown_keys:
        raise RulesetError(f"알 수 없는 키: {', '.join(sorted(unknown_keys))} (disabled, severity만 사용할 수 있습니다)")

    known = set(known_rule_ids)
    disabled_raw = data.get("disabled") or []
    if not isinstance(disabled_raw, list):
        raise RulesetError("`disabled:`는 룰 ID 목록이어야 합니다.")
    disabled = {str(r).strip().upper() for r in disabled_raw}

    severity_raw = data.get("severity") or {}
    if not isinstance(severity_raw, dict):
        raise RulesetError("`severity:`는 `룰 ID: 심각도` 매핑이어야 합니다.")
    severity: dict[str, Severity] = {}
    valid = ", ".join(s.value for s in Severity)
    for rule_id, value in severity_raw.items():
        try:
            severity[str(rule_id).strip().upper()] = Severity(str(value).strip().lower())
        except ValueError:
            raise RulesetError(f"{rule_id}: 알 수 없는 심각도 '{value}' (가능한 값: {valid})") from None

    unknown_ids = sorted((disabled | set(severity)) - known)
    if unknown_ids:
        raise RulesetError(f"등록되지 않은 룰 ID: {', '.join(unknown_ids)} (dockguard rules 로 확인)")
    return Ruleset(path=path, disabled=disabled, severity=severity)
