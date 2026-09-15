"""룰 실행 엔진."""

from __future__ import annotations

import dataclasses
from typing import Iterable

from dockguard.core.context import ScanContext
from dockguard.core.models import RuleError, ScanResult
from dockguard.core.rule import Rule, all_rules
from dockguard.core.ruleset import Ruleset


class ScanEngine:
    """등록된 룰을 골라 실행하고 Finding을 모은다."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        categories: Iterable[str] | None = None,
        ruleset: Ruleset | None = None,
    ) -> None:
        """
        Args:
            rules: 실행할 룰 (None이면 rules 패키지를 자동 탐색해 등록된 전체 룰).
            categories: 실행할 카테고리 (None이면 전체).
            ruleset: 끌 룰과 심각도 조정 (None이면 기본값 그대로).
        """
        if rules is None:
            from dockguard.rules import load_all_rules

            load_all_rules()
            rules = all_rules()
        self.categories = set(categories) if categories else None
        self.ruleset = ruleset or Ruleset()
        selected = [r for r in rules if self.categories is None or r.category in self.categories]
        self.disabled_rules = [r for r in selected if r.id in self.ruleset.disabled]
        self.rules = [r for r in selected if r.id not in self.ruleset.disabled]

    def run(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        for rule in self.rules:
            try:
                findings = rule.check(context)
            except Exception as exc:  # noqa: BLE001 — 룰 하나의 버그로 전체 진단이 멈추면 안 된다
                result.errors.append(RuleError(rule_id=rule.id, message=f"{type(exc).__name__}: {exc}"))
            else:
                override = self.ruleset.severity.get(rule.id)
                if override is not None:
                    findings = [dataclasses.replace(f, severity=override) for f in findings]
                result.findings.extend(findings)
            result.rules_run += 1
        return result
