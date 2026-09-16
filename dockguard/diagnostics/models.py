"""진단(diagnose) 결과 데이터 모델.

스캔(scan)이 "무엇이 위험한가"를 Finding으로 모은다면, 진단은 "이미 생긴 증상의 원인이 무엇인가"를
`DiagnosisStep`의 나열 — 즉 **검사 로그** — 로 남긴다. 사람이 손으로 하던 디버깅을 그대로 옮긴 것이라,
결과만이 아니라 "무엇을 어떤 순서로 확인했고 각 단계에서 무엇을 봤는지"가 결과물의 일부다.

상태 값은 스캔과 같은 `core.models.Status`를 쓴다 (PASS / FAIL / WARN / SKIP).
리포터가 쓰는 색·라벨을 그대로 재사용하기 위해서다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from dockguard.core.models import Status


@dataclass
class DiagnosisStep:
    """진단 단계 하나의 결과.

    FAIL인 단계는 그 자체가 근본 원인 후보이므로 `cause` · `fix` · `tradeoff`를 함께 담는다.
    `detail`과 `evidence`에는 **실제로 검사한 값**을 적는다. 사용자가 도구의 판단을 그대로 믿지 않고
    눈으로 확인할 수 있어야 하기 때문이다.
    """

    name: str  # 단계 이름 (질문 형태: "두 컨테이너가 실행 중인가?")
    status: Status
    detail: str  # 한 줄 판정 결과
    evidence: list[str] = field(default_factory=list)  # 판정 근거가 된 실제 값
    cause: str = ""  # FAIL일 때 근본 원인 한 줄 요약
    fix: str = ""  # 해결 방법 (마크다운)
    tradeoff: str = ""  # 해결 시 주의사항

    @property
    def failed(self) -> bool:
        return self.status == Status.FAIL

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class DiagnosisResult:
    """진단 하나의 전체 결과 (검사 로그 + 근본 원인)."""

    diagnosis_id: str  # 예: "connectivity"
    title: str  # 예: "컨테이너 연결 실패"
    symptom: str  # 사용자가 겪고 있다고 선언한 증상
    target: str = ""  # 진단 대상 (예: "backend → rabbitmq:5672")
    steps: list[DiagnosisStep] = field(default_factory=list)
    # 진단 자체를 수행하지 못한 사유 (예: Docker에 연결 불가). 있으면 steps는 비어 있다.
    error: str | None = None
    # 원인을 찾지 못했을 때 사용자가 다음으로 확인할 것들
    next_checks: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[DiagnosisStep]:
        return [s for s in self.steps if s.failed]

    @property
    def resolved(self) -> bool:
        """근본 원인을 찾았는지."""
        return bool(self.failures)

    @property
    def root(self) -> DiagnosisStep | None:
        """근본 원인 단계 — 가장 먼저 실패한 단계.

        진단 트리는 '앞 단계가 성립해야 뒤 단계가 의미를 갖는' 순서로 짜여 있으므로,
        첫 번째 실패가 근본 원인이고 뒤따르는 실패는 함께 고쳐야 할 추가 문제다.
        """
        return self.failures[0] if self.failures else None

    @property
    def also_failed(self) -> list[DiagnosisStep]:
        """근본 원인 외에 추가로 발견된 문제."""
        return self.failures[1:]

    @property
    def warnings(self) -> list[DiagnosisStep]:
        return [s for s in self.steps if s.status == Status.WARN]

    @property
    def root_cause(self) -> str:
        return self.root.cause if self.root else ""

    @property
    def evidence(self) -> list[str]:
        return self.root.evidence if self.root else []

    @property
    def fix(self) -> str:
        return self.root.fix if self.root else ""

    @property
    def tradeoff(self) -> str:
        return self.root.tradeoff if self.root else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "diagnosis": self.diagnosis_id,
            "title": self.title,
            "symptom": self.symptom,
            "target": self.target,
            "resolved": self.resolved,
            "error": self.error,
            "root_cause": self.root_cause,
            "evidence": self.evidence,
            "fix": self.fix,
            "tradeoff": self.tradeoff,
            "also_failed": [s.cause for s in self.also_failed],
            "next_checks": self.next_checks,
            "steps": [s.to_dict() for s in self.steps],
        }
