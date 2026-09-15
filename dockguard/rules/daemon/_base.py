"""daemon.json 룰 공통 베이스.

대부분의 데몬 룰은 "키 하나가 권장 불리언 값인가"를 본다. 여기서 공통 로직을 처리하고,
개별 룰 파일은 키/권장값/Docker 기본값과 설명 텍스트만 선언한다.

핵심 원칙: **daemon.json에 키가 없으면 Docker 기본값으로 동작한다.**
파일이 없거나 키가 없다고 안전한 게 아니므로, 기본값 기준으로 판정한다.
"""

from __future__ import annotations

import json

from dockguard.core.context import ScanContext
from dockguard.core.models import Category, Finding, Status
from dockguard.core.rule import Rule


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


class BooleanDaemonRule(Rule):
    """daemon.json의 불리언 키 하나를 점검하는 룰."""

    category = Category.DAEMON.value

    key: str = ""
    recommended_value: bool = True
    docker_default: bool = False  # 키가 없을 때 Docker의 실제 동작

    # 설명 텍스트 (하위 클래스에서 채운다)
    why: str = ""
    how_to_fix: str = ""
    tradeoff: str = ""
    learn_more: str = ""
    auto_fixable: bool = False

    def check(self, context: ScanContext) -> list[Finding]:
        daemon = context.daemon
        if daemon is None:
            return [self._make(Status.SKIP, target="daemon.json", current="수집되지 않음")]
        if not daemon.usable:
            return [self._make(Status.SKIP, target=str(daemon.path), current=f"점검 불가 — {daemon.error}")]

        if not daemon.has(self.key):
            # 파일이 없는 경우는 target에 "(파일 없음)"으로 표시된다
            effective = self.docker_default
            current = f"미설정 (Docker 기본값 {_json(self.docker_default)})"
        else:
            raw = daemon.get(self.key)
            if not isinstance(raw, bool):
                # "false"(문자열)처럼 잘못된 타입이면 dockerd가 시작에 실패할 수 있다
                return [
                    self._make(
                        Status.WARN,
                        target=daemon.target_label,
                        current=f"{_json(raw)} (불리언이 아님 — 따옴표 없는 true/false만 허용)",
                    )
                ]
            effective = raw
            current = _json(raw)

        status = Status.PASS if effective == self.recommended_value else Status.FAIL
        return [self._make(status, target=daemon.target_label, current=current)]

    def _make(self, status: Status, *, target: str, current: str) -> Finding:
        return self.finding(
            status,
            target=target,
            current_value=current,
            recommended=f'"{self.key}": {_json(self.recommended_value)}',
            why=self.why,
            how_to_fix=self.how_to_fix,
            tradeoff=self.tradeoff,
            auto_fixable=self.auto_fixable,
            learn_more=self.learn_more,
        )
