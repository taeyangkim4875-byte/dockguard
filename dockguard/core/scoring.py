"""보안 점수 계산.

    시작 점수 100점
    FAIL Finding마다 severity.weight 만큼 감점 (하한 0)
    CRITICAL=40, HIGH=20, MEDIUM=10, LOW=3
    90+ A, 75+ B, 60+ C, 40+ D, 그 외 F
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from dockguard.core.models import Finding, Status

MAX_SCORE = 100

# (최저 점수, 등급) — 높은 점수부터
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
]
LOWEST_GRADE = "F"


@dataclass(frozen=True)
class Score:
    value: int
    grade: str
    deducted: int  # 실제 감점 합계 (하한 적용 전)

    def __str__(self) -> str:
        return f"{self.value}/{MAX_SCORE} ({self.grade})"


def grade_for(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return LOWEST_GRADE


def calculate_score(findings: Iterable[Finding]) -> Score:
    deducted = sum(f.severity.weight for f in findings if f.status == Status.FAIL)
    value = max(0, MAX_SCORE - deducted)
    return Score(value=value, grade=grade_for(value), deducted=deducted)
