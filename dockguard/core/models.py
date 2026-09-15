"""dockguard의 핵심 데이터 모델.

룰(Rule)은 점검 결과를 `Finding`으로 반환하고, 엔진은 이를 모아 `ScanResult`로 묶는다.
리포터(터미널/HTML/JSON)는 오직 이 모델만 보고 출력을 만든다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Category(str, Enum):
    """점검 영역."""

    DAEMON = "daemon"
    COMPOSE = "compose"
    NETWORK = "network"


class Severity(Enum):
    """취약점 심각도."""

    CRITICAL = "critical"  # 즉시 조치 (호스트 장악 가능 등)
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """점수 계산용 감점 가중치."""
        return _SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """정렬 순서 (0이 가장 심각)."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Status(Enum):
    """점검 결과 상태."""

    PASS = "pass"  # 통과
    FAIL = "fail"  # 취약점 발견
    WARN = "warn"  # 주의 (설정이 비정상적이거나 판단에 사람의 확인이 필요)
    SKIP = "skip"  # 점검 불가 (대상 없음, 파싱 실패 등)

    @property
    def rank(self) -> int:
        """정렬 순서 (조치가 필요한 것이 먼저)."""
        return _STATUS_ORDER.index(self)


_STATUS_ORDER: list[Status] = [Status.FAIL, Status.WARN, Status.SKIP, Status.PASS]


class FixRisk(str, Enum):
    """자동 수정의 위험도."""

    NONE = "none"  # 자동 수정 미지원 (수정 방법만 안내)
    SAFE = "safe"  # 부작용이 작아 기본 수정 대상
    RISKY = "risky"  # 부작용이 커서 사용자가 룰 ID를 명시해야만 포함 (강경고)


class ApplyMethod(str, Enum):
    """daemon.json 변경을 Docker에 반영하는 방법."""

    RELOAD = "reload"  # SIGHUP 리로드로 반영 (컨테이너 영향 없음)
    RESTART = "restart"  # 데몬 재시작 필요


@dataclass
class ConfigPatch:
    """룰이 제안하는 설정 파일 수정 계획.

    룰은 '무엇을 바꿀지'만 선언하고, 실제 파일 쓰기·백업·검증은 Remediator가 전담한다.
    그래서 어떤 룰도 백업/검증 절차를 우회할 수 없다.
    """

    rule_id: str
    summary: str  # 사람이 읽는 변경 요약 (예: '"live-restore": true')
    set_values: dict[str, Any] = field(default_factory=dict)  # 최상위 키 설정 (값 통째로 교체)
    remove_keys: list[str] = field(default_factory=list)
    apply_with: ApplyMethod = ApplyMethod.RESTART
    risk: FixRisk = FixRisk.SAFE
    note: str = ""  # 적용 시 주의사항 (RISKY면 강경고로 표시)
    requires_recreate: bool = False  # 기존 컨테이너는 재생성해야 반영되는지


@dataclass
class Finding:
    """룰 하나가 대상 하나를 점검한 결과."""

    rule_id: str  # 예: "DAEMON-001"
    title: str  # 짧은 제목
    category: str  # daemon / compose / network
    severity: Severity
    status: Status
    target: str  # 발견 위치 (파일 경로, 컨테이너명 등)
    current_value: str  # 현재 상태
    recommended: str  # 권장 상태
    why: str  # 왜 위험한가 (교육용, 상세하게)
    how_to_fix: str  # 어떻게 고치나 (구체적 명령/설정)
    tradeoff: str = ""  # 고쳤을 때 부작용/주의 (dockguard의 차별점!)
    reference: str = ""  # 근거 (CIS Docker Benchmark 항목 번호 등)
    auto_fixable: bool = False
    learn_more: str = ""  # 심화 학습 링크/설명

    @property
    def is_problem(self) -> bool:
        """조치가 필요한 결과인지 (FAIL 또는 WARN)."""
        return self.status in (Status.FAIL, Status.WARN)

    def sort_key(self) -> tuple[int, int, str, str]:
        """리포트 정렬 키: 상태(FAIL 먼저) → 심각도 → 룰 ID → 대상."""
        return (self.status.rank, self.severity.rank, self.rule_id, self.target)

    def to_dict(self) -> dict[str, Any]:
        """JSON 직렬화용 딕셔너리."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data


@dataclass
class RuleError:
    """룰 실행 중 발생한 예외. 한 룰의 버그가 전체 진단을 멈추지 않도록 따로 기록한다."""

    rule_id: str
    message: str


@dataclass
class ScanResult:
    """엔진 실행 결과."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[RuleError] = field(default_factory=list)
    rules_run: int = 0

    def by_status(self, status: Status) -> list[Finding]:
        return [f for f in self.findings if f.status == status]

    def status_counts(self) -> dict[Status, int]:
        return {s: len(self.by_status(s)) for s in Status}

    def failed_severity_counts(self) -> dict[Severity, int]:
        """FAIL 결과의 심각도별 개수."""
        counts = {s: 0 for s in Severity}
        for f in self.by_status(Status.FAIL):
            counts[f.severity] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=Finding.sort_key)
