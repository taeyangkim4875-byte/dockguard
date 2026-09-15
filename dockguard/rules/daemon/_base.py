"""daemon.json 룰 공통 베이스.

- `DaemonRule`: 모든 daemon 룰의 공통 처리 (수집 안 됨 / 파싱 실패 시 SKIP, Finding 생성 도우미)
- `BooleanDaemonRule`: "키 하나가 권장 불리언 값인가"를 보는 룰. 개별 룰 파일은
  키/권장값/Docker 기본값과 설명 텍스트만 선언하면 된다.

핵심 원칙: **daemon.json에 키가 없으면 Docker 기본값으로 동작한다.**
파일이 없거나 키가 없다고 안전한 게 아니므로, 기본값 기준으로 판정한다.
"""

from __future__ import annotations

import json

from dockguard.core.context import DaemonConfig, ScanContext
from dockguard.core.models import ApplyMethod, Category, ConfigPatch, Finding, FixRisk, Status
from dockguard.core.rule import Rule


def to_json(value: object) -> str:
    """설정 값을 daemon.json에 적는 형태로 표시한다."""
    return json.dumps(value, ensure_ascii=False)


class DaemonRule(Rule):
    """daemon.json 룰의 공통 베이스."""

    category = Category.DAEMON.value

    # 설명 텍스트 (하위 클래스에서 채운다)
    why: str = ""
    how_to_fix: str = ""
    tradeoff: str = ""
    learn_more: str = ""
    recommended: str = ""  # 권장 상태 표시 문자열

    # False면 파일 내용 파싱에 실패해도 evaluate()를 호출한다 (예: 파일 권한 점검)
    requires_content: bool = True

    def check(self, context: ScanContext) -> list[Finding]:
        daemon = context.daemon
        if daemon is None:
            return [self.make(Status.SKIP, target="daemon.json", current="수집되지 않음")]
        if self.requires_content and not daemon.usable:
            return [self.make(Status.SKIP, target=str(daemon.path), current=f"점검 불가 — {daemon.error}")]
        return self.evaluate(daemon)

    def evaluate(self, daemon: DaemonConfig) -> list[Finding]:
        """수집된 daemon.json을 판정한다."""
        raise NotImplementedError

    def make(self, status: Status, *, target: str, current: str, recommended: str | None = None) -> Finding:
        return self.finding(
            status,
            target=target,
            current_value=current,
            recommended=recommended if recommended is not None else self.recommended,
            why=self.why,
            how_to_fix=self.how_to_fix,
            tradeoff=self.tradeoff,
            learn_more=self.learn_more,
        )


class BooleanDaemonRule(DaemonRule):
    """daemon.json의 불리언 키 하나를 점검하는 룰."""

    key: str = ""
    recommended_value: bool = True
    docker_default: bool = False  # 키가 없을 때 Docker의 실제 동작

    # 자동 수정 시 반영 방법과 주의사항 (fix_risk가 NONE이 아닐 때만 사용)
    apply_with: ApplyMethod = ApplyMethod.RESTART
    fix_note: str = ""
    fix_requires_recreate: bool = False  # 기존 컨테이너는 재생성해야 반영되는 설정인지

    @property
    def recommended(self) -> str:  # type: ignore[override]
        return f'"{self.key}": {to_json(self.recommended_value)}'

    def evaluate(self, daemon: DaemonConfig) -> list[Finding]:
        if not daemon.has(self.key):
            # 파일이 없는 경우는 target에 "(파일 없음)"으로 표시된다
            effective = self.docker_default
            current = f"미설정 (Docker 기본값 {to_json(self.docker_default)})"
        else:
            raw = daemon.get(self.key)
            if not isinstance(raw, bool):
                # "false"(문자열)처럼 잘못된 타입이면 dockerd가 시작에 실패할 수 있다
                return [
                    self.make(
                        Status.WARN,
                        target=daemon.target_label,
                        current=f"{to_json(raw)} (불리언이 아님 — 따옴표 없는 true/false만 허용)",
                    )
                ]
            effective = raw
            current = to_json(raw)

        status = Status.PASS if effective == self.recommended_value else Status.FAIL
        return [self.make(status, target=daemon.target_label, current=current)]

    def plan_fix(self, finding: Finding, context: ScanContext) -> ConfigPatch | None:
        if self.fix_risk == FixRisk.NONE or not finding.is_problem:
            return None
        return ConfigPatch(
            rule_id=self.id,
            summary=self.recommended,
            set_values={self.key: self.recommended_value},
            apply_with=self.apply_with,
            risk=self.fix_risk,
            note=self.fix_note,
            requires_recreate=self.fix_requires_recreate,
        )
