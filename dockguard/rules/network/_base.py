"""네트워크 룰 공통 베이스.

네트워크 룰은 실행 중인 Docker의 실제 상태(DockerRuntime)를 본다.
Docker에 연결하지 못하면 룰마다 '건너뜀'을 하나씩 남겨, 점검되지 않았다는 사실이 표에 드러나게 한다.
"""

from __future__ import annotations

from dockguard.core.context import DockerRuntime, ScanContext
from dockguard.core.models import Category, Finding, Status
from dockguard.core.rule import Rule


class NetworkRule(Rule):
    category = Category.NETWORK.value
    no_autofix_reason = "네트워크 구성 변경은 서비스 연결에 직접 영향을 주므로 자동 수정하지 않습니다. 수정 방법을 참고해 직접 적용하세요."

    why: str = ""
    how_to_fix: str = ""
    tradeoff: str = ""
    learn_more: str = ""
    recommended: str = ""

    def check(self, context: ScanContext) -> list[Finding]:
        runtime = context.docker
        if runtime is None:
            return []
        if not runtime.available:
            return [self.make(Status.SKIP, target="Docker 호스트", current=f"점검 불가 — {runtime.error}")]
        return self.evaluate(runtime, context)

    def evaluate(self, runtime: DockerRuntime, context: ScanContext) -> list[Finding]:
        raise NotImplementedError

    def make(
        self,
        status: Status,
        *,
        target: str,
        current: str,
        why: str | None = None,
        how_to_fix: str | None = None,
        recommended: str | None = None,
    ) -> Finding:
        return self.finding(
            status,
            target=target,
            current_value=current,
            recommended=recommended if recommended is not None else self.recommended,
            why=why if why is not None else self.why,
            how_to_fix=how_to_fix if how_to_fix is not None else self.how_to_fix,
            tradeoff=self.tradeoff,
            learn_more=self.learn_more,
        )


def host_target(runtime: DockerRuntime) -> str:
    """호스트 전체를 대상으로 하는 Finding의 target 표시."""
    source = f", {runtime.source}" if runtime.source and runtime.source != "Docker SDK" else ""
    return f"Docker 호스트 (컨테이너 {len(runtime.running_containers)}개 실행 중{source})"
