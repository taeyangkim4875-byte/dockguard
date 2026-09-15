"""룰 레지스트리 · 자동 탐색 · 엔진 테스트."""

from __future__ import annotations

import pytest

from dockguard.core import rule as rule_module
from dockguard.core.engine import ScanEngine
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import Rule, all_rules, register, registered_rule_classes
from dockguard.rules import load_all_rules

DAEMON_RULE_IDS = {f"DAEMON-{n:03d}" for n in range(1, 11)}
# DAEMON-007(파일 권한)은 OS에 따라 결과가 달라 내용 점검 룰만 따로 본다
DAEMON_CONTENT_RULE_IDS = DAEMON_RULE_IDS - {"DAEMON-007"}


class _StubRule(Rule):
    """테스트용 가짜 룰 — 레지스트리에 등록하지 않고 엔진에 직접 넘긴다."""

    def __init__(self, rule_id: str, category: str, status: Status = Status.PASS, severity=Severity.LOW):
        self.id = rule_id
        self.category = category
        self.title = f"stub {rule_id}"
        self.severity = severity
        self._status = status

    def check(self, context):
        return [
            self.finding(
                self._status,
                target="stub",
                current_value="x",
                recommended="y",
                why="why",
                how_to_fix="fix",
            )
        ]


class _ExplodingRule(Rule):
    id = "TEST-BOOM"
    category = "daemon"
    title = "항상 예외를 던지는 룰"

    def check(self, context):
        raise RuntimeError("의도된 실패")


# --------------------------------------------------------------------- 레지스트리 / 자동 탐색


def test_auto_discovery_registers_all_daemon_rules():
    load_all_rules()
    ids = {cls.id for cls in registered_rule_classes()}
    assert DAEMON_RULE_IDS <= ids


def test_load_all_rules_is_idempotent():
    load_all_rules()
    before = len(registered_rule_classes())
    load_all_rules()
    assert len(registered_rule_classes()) == before


def test_registered_rule_ids_are_unique_and_complete():
    load_all_rules()
    rules = all_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for r in rules:
        assert r.category in {"daemon", "compose", "network"}
        assert r.title
        assert isinstance(r.severity, Severity)


def test_base_rule_classes_are_not_registered():
    """공통 베이스(DaemonRule, BooleanDaemonRule)는 @register가 없으므로 실행 대상이 아니다."""
    load_all_rules()
    names = {cls.__name__ for cls in registered_rule_classes()}
    assert "DaemonRule" not in names
    assert "BooleanDaemonRule" not in names


def test_register_rejects_duplicate_id(monkeypatch):
    monkeypatch.setattr(rule_module, "_REGISTRY", [])

    @register
    class First(Rule):
        id = "DUP-001"

    with pytest.raises(ValueError, match="중복"):

        @register
        class Second(Rule):
            id = "DUP-001"


def test_register_rejects_empty_id(monkeypatch):
    monkeypatch.setattr(rule_module, "_REGISTRY", [])
    with pytest.raises(ValueError):

        @register
        class NoId(Rule):
            pass


def test_register_same_class_twice_is_noop(monkeypatch):
    monkeypatch.setattr(rule_module, "_REGISTRY", [])

    class Once(Rule):
        id = "ONCE-001"

    register(Once)
    register(Once)
    assert registered_rule_classes() == [Once]


def test_base_rule_has_no_fix_by_default(context_factory):
    stub = _StubRule("STUB-1", "daemon", Status.FAIL)
    finding = stub.check(context_factory())[0]
    assert stub.plan_fix(finding, context_factory()) is None
    assert not finding.auto_fixable
    assert stub.no_autofix_reason


def test_base_rule_check_not_implemented(context_factory):
    with pytest.raises(NotImplementedError):
        Rule().check(context_factory())


# --------------------------------------------------------------------- 엔진


def test_engine_default_loads_registered_rules():
    engine = ScanEngine()
    assert DAEMON_RULE_IDS <= {r.id for r in engine.rules}


def test_engine_filters_by_category(context_factory):
    rules = [_StubRule("D-1", "daemon"), _StubRule("C-1", "compose"), _StubRule("N-1", "network")]
    engine = ScanEngine(rules=rules, categories={"daemon", "network"})
    assert [r.id for r in engine.rules] == ["D-1", "N-1"]

    result = engine.run(context_factory())
    assert {f.rule_id for f in result.findings} == {"D-1", "N-1"}
    assert result.rules_run == 2


def test_engine_runs_all_categories_by_default():
    rules = [_StubRule("D-1", "daemon"), _StubRule("C-1", "compose")]
    assert len(ScanEngine(rules=rules).rules) == 2


def test_engine_isolates_rule_exceptions(context_factory):
    """룰 하나가 예외를 던져도 나머지 룰은 계속 실행되고, 오류는 따로 기록된다."""
    rules = [_ExplodingRule(), _StubRule("D-1", "daemon", Status.FAIL)]
    result = ScanEngine(rules=rules).run(context_factory())

    assert [f.rule_id for f in result.findings] == ["D-1"]
    assert len(result.errors) == 1
    assert result.errors[0].rule_id == "TEST-BOOM"
    assert "의도된 실패" in result.errors[0].message
    assert result.rules_run == 2


def test_engine_with_real_rules_on_insecure_config(daemon_context):
    result = ScanEngine(categories={"daemon"}).run(daemon_context("insecure.json"))
    content = [f for f in result.findings if f.rule_id in DAEMON_CONTENT_RULE_IDS]
    assert len(content) == len(DAEMON_CONTENT_RULE_IDS)
    assert all(f.status == Status.FAIL for f in content)
    assert not result.errors


def test_engine_with_real_rules_on_secure_config(daemon_context):
    result = ScanEngine(categories={"daemon"}).run(daemon_context("secure.json"))
    assert not [f for f in result.findings if f.status == Status.FAIL]
    assert not result.errors


def test_scan_result_helpers(context_factory):
    rules = [
        _StubRule("A-1", "daemon", Status.PASS, Severity.HIGH),
        _StubRule("A-2", "daemon", Status.FAIL, Severity.LOW),
        _StubRule("A-3", "daemon", Status.FAIL, Severity.CRITICAL),
        _StubRule("A-4", "daemon", Status.WARN, Severity.MEDIUM),
        _StubRule("A-5", "daemon", Status.SKIP, Severity.MEDIUM),
    ]
    result = ScanEngine(rules=rules).run(context_factory())

    counts = result.status_counts()
    assert counts[Status.FAIL] == 2 and counts[Status.PASS] == 1
    assert counts[Status.WARN] == 1 and counts[Status.SKIP] == 1

    sev = result.failed_severity_counts()
    assert sev[Severity.CRITICAL] == 1 and sev[Severity.LOW] == 1 and sev[Severity.HIGH] == 0

    # FAIL(심각한 순) → WARN → SKIP → PASS
    assert [f.rule_id for f in result.sorted_findings()] == ["A-3", "A-2", "A-4", "A-5", "A-1"]


def test_finding_to_dict_serializes_enums():
    finding = Finding(
        rule_id="X-1",
        title="t",
        category="daemon",
        severity=Severity.HIGH,
        status=Status.FAIL,
        target="t",
        current_value="a",
        recommended="b",
        why="w",
        how_to_fix="h",
    )
    data = finding.to_dict()
    assert data["severity"] == "high"
    assert data["status"] == "fail"
    assert finding.is_problem
