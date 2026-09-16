"""진단(Diagnosis) 베이스 클래스.

룰(Rule)이 "점검 항목 하나"라면, 진단은 "증상 하나를 추적하는 의사결정 트리"다.
하위 클래스는 `steps()` 제너레이터에서 검사 단계를 순서대로 yield 하기만 하면 된다.

설계 메모 — 첫 FAIL에서 멈추지 않고 로그를 끝까지 남기는 이유:
    근본 원인은 **가장 먼저 실패한 단계**다 (진단 트리가 인과 순서로 짜여 있으므로).
    하지만 거기서 검사를 멈추면 "함께 고쳐야 할 다른 문제"를 놓친다. 실제 사고에서도 원인은
    하나가 아니었다 — 네트워크가 분리돼 있었고, 접속 주소까지 잘못돼 있었다. 네트워크만 고치고
    재기동하면 또 안 되는 것이다.
    그래서 뒤 단계가 의미를 잃는 경우(컨테이너 자체가 없음)에만 제너레이터가 `return`으로 멈추고,
    나머지는 끝까지 검사해 로그를 남긴다. 리포터는 첫 FAIL을 근본 원인으로, 나머지 FAIL을
    "추가로 발견된 문제"로 보여준다.
"""

from __future__ import annotations

from typing import Iterator

from dockguard.core.context import DockerRuntime, ScanContext
from dockguard.core.models import Status
from dockguard.diagnostics.models import DiagnosisResult, DiagnosisStep


class Diagnosis:
    """모든 진단의 베이스 클래스."""

    id: str = ""
    title: str = ""

    # ------------------------------------------------------------------ 하위 클래스가 구현

    def symptom(self, context: ScanContext) -> str:
        """사용자가 겪고 있는 증상 한 줄."""
        raise NotImplementedError

    def target_label(self, context: ScanContext) -> str:
        """진단 대상 표시 (예: "backend → rabbitmq:5672")."""
        return ""

    def precheck(self, context: ScanContext) -> str | None:
        """진단을 시작할 수 없는 사유. None이면 진행."""
        return None

    def steps(self, context: ScanContext) -> Iterator[DiagnosisStep]:
        """검사 단계를 순서대로 yield 한다."""
        raise NotImplementedError

    def next_checks(self, context: ScanContext) -> list[str]:
        """모든 단계를 통과했을 때(원인 미발견) 사용자가 다음으로 확인할 것들."""
        return []

    # ------------------------------------------------------------------ 실행

    def run(self, context: ScanContext) -> DiagnosisResult:
        """진단을 실행하고 검사 로그와 근본 원인을 담은 결과를 반환한다."""
        result = DiagnosisResult(
            diagnosis_id=self.id,
            title=self.title,
            symptom=self.symptom(context),
            target=self.target_label(context),
        )
        error = self.precheck(context)
        if error is not None:
            result.error = error
            return result

        for step in self.steps(context):
            result.steps.append(step)
        if not result.resolved:
            result.next_checks = self.next_checks(context)
        return result

    # ------------------------------------------------------------------ 하위 클래스용 헬퍼

    @staticmethod
    def step(
        name: str,
        status: Status,
        detail: str,
        *,
        evidence: list[str] | None = None,
        cause: str = "",
        fix: str = "",
        tradeoff: str = "",
    ) -> DiagnosisStep:
        return DiagnosisStep(
            name=name,
            status=status,
            detail=detail,
            evidence=evidence or [],
            cause=cause,
            fix=fix,
            tradeoff=tradeoff,
        )


class DockerDiagnosis(Diagnosis):
    """실행 중인 Docker의 상태(DockerRuntime)를 보는 진단.

    Docker에 연결하지 못하면 크래시 대신 사유를 담은 결과를 돌려준다.
    """

    def precheck(self, context: ScanContext) -> str | None:
        runtime = context.docker
        if runtime is None:
            return "Docker 상태를 수집하지 않았습니다."
        if not runtime.available:
            return runtime.error or "Docker 상태를 수집하지 못했습니다."
        if not runtime.containers:
            return "이 호스트에서 컨테이너를 찾지 못했습니다. (docker ps -a 로 확인하세요)"
        return None

    @staticmethod
    def runtime(context: ScanContext) -> DockerRuntime:
        """precheck를 통과한 뒤에만 호출한다."""
        assert context.docker is not None and context.docker.available
        return context.docker
