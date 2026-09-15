"""보안 점수 계산 테스트."""

from __future__ import annotations

import pytest

from dockguard.core.models import Finding, Severity, Status
from dockguard.core.scoring import calculate_score, grade_for


def _f(severity: Severity, status: Status = Status.FAIL) -> Finding:
    return Finding(
        rule_id="T-1",
        title="t",
        category="daemon",
        severity=severity,
        status=status,
        target="t",
        current_value="",
        recommended="",
        why="",
        how_to_fix="",
    )


def test_no_findings_is_perfect_score():
    score = calculate_score([])
    assert score.value == 100
    assert score.grade == "A"
    assert str(score) == "100/100 (A)"


def test_each_fail_deducts_severity_weight():
    findings = [_f(Severity.HIGH), _f(Severity.MEDIUM), _f(Severity.LOW)]
    score = calculate_score(findings)
    assert score.value == 100 - 20 - 10 - 3
    assert score.deducted == 33


def test_only_fail_status_deducts():
    findings = [
        _f(Severity.CRITICAL, Status.PASS),
        _f(Severity.CRITICAL, Status.WARN),
        _f(Severity.CRITICAL, Status.SKIP),
    ]
    assert calculate_score(findings).value == 100


def test_info_severity_does_not_deduct():
    assert calculate_score([_f(Severity.INFO)]).value == 100


def test_score_has_floor_of_zero():
    score = calculate_score([_f(Severity.CRITICAL)] * 4)
    assert score.value == 0
    assert score.deducted == 160
    assert score.grade == "F"


@pytest.mark.parametrize(
    ("score", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"), (59, "D"), (40, "D"), (39, "F"), (0, "F")],
)
def test_grade_thresholds(score, grade):
    assert grade_for(score) == grade


def test_severity_weights_match_spec():
    assert Severity.CRITICAL.weight == 40
    assert Severity.HIGH.weight == 20
    assert Severity.MEDIUM.weight == 10
    assert Severity.LOW.weight == 3
    assert Severity.INFO.weight == 0
