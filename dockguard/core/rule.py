"""Rule 베이스 클래스와 자동 등록(registry).

새 점검을 추가하려면 `rules/<카테고리>/` 아래에 파일 하나를 만들고
Rule 하위 클래스에 `@register`를 붙이면 끝이다. 엔진이 알아서 찾아 실행한다.

    @register
    class MyRule(Rule):
        id = "DAEMON-099"
        category = "daemon"
        title = "..."
        severity = Severity.MEDIUM

        def check(self, context):
            return [self.finding(Status.PASS, target=..., ...)]
"""

from __future__ import annotations

from typing import TypeVar

from dockguard.core.context import ScanContext
from dockguard.core.models import Finding, Severity, Status

_REGISTRY: list[type["Rule"]] = []

R = TypeVar("R", bound=type["Rule"])


def register(cls: R) -> R:
    """룰 클래스 데코레이터 — 모듈이 import되면 자동 등록된다."""
    if not cls.id:
        raise ValueError(f"{cls.__name__}: 룰 id가 비어 있습니다.")
    if cls in _REGISTRY:
        return cls
    for existing in _REGISTRY:
        if existing.id == cls.id:
            raise ValueError(
                f"룰 id 중복: {cls.id} ({existing.__module__}.{existing.__name__} / "
                f"{cls.__module__}.{cls.__name__})"
            )
    _REGISTRY.append(cls)
    return cls


def registered_rule_classes() -> list[type["Rule"]]:
    """등록된 룰 클래스 목록 (id 순)."""
    return sorted(_REGISTRY, key=lambda c: c.id)


def all_rules() -> list["Rule"]:
    """등록된 모든 룰의 인스턴스 (id 순)."""
    return [cls() for cls in registered_rule_classes()]


class Rule:
    """모든 점검 룰의 베이스 클래스."""

    id: str = ""
    category: str = ""  # daemon / compose / network
    title: str = ""
    severity: Severity = Severity.MEDIUM
    reference: str = ""  # 근거 (CIS 항목 등)

    def check(self, context: ScanContext) -> list[Finding]:
        """컨텍스트를 점검해 Finding 목록을 반환한다."""
        raise NotImplementedError

    def remediate(self, finding: Finding, context: ScanContext, dry_run: bool = True):
        """수정 로직 (선택 구현). 기본은 미지원."""
        raise NotImplementedError(f"{self.id}는 자동 수정을 지원하지 않습니다.")

    def finding(
        self,
        status: Status,
        *,
        target: str,
        current_value: str,
        recommended: str,
        why: str,
        how_to_fix: str,
        tradeoff: str = "",
        auto_fixable: bool = False,
        learn_more: str = "",
        severity: Severity | None = None,
    ) -> Finding:
        """이 룰의 id/제목/카테고리/심각도/근거를 채운 Finding을 만든다."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=severity or self.severity,
            status=status,
            target=target,
            current_value=current_value,
            recommended=recommended,
            why=why,
            how_to_fix=how_to_fix,
            tradeoff=tradeoff,
            reference=self.reference,
            auto_fixable=auto_fixable,
            learn_more=learn_more,
        )
