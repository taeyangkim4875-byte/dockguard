"""터미널 리포터 렌더링 테스트."""

from __future__ import annotations

from rich.console import Console

from dockguard.core.models import Finding, RuleError, ScanResult, Severity, Status
from dockguard.core.scoring import calculate_score
from dockguard.reporters.terminal import TerminalReporter


def _finding(rule_id: str, target: str, status: Status, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"title {rule_id}",
        category="daemon",
        severity=severity,
        status=status,
        target=target,
        current_value="cur",
        recommended="rec",
        why="이유 설명",
        how_to_fix="```bash\necho fix\n```",
        tradeoff="부작용 설명",
        reference="CIS X",
        learn_more="https://example.com",
    )


def _render(result: ScanResult, context, explain: bool = False) -> str:
    console = Console(record=True, width=140, force_terminal=False)
    TerminalReporter(console=console, explain=explain).render(context, result, calculate_score(result.findings))
    return console.export_text()


def test_multiple_targets_adds_target_column(context_factory):
    result = ScanResult(
        findings=[_finding("A-1", "/srv/a/compose.yml", Status.FAIL), _finding("A-2", "/srv/b/compose.yml", Status.PASS)],
        rules_run=2,
    )
    out = _render(result, context_factory())
    assert "대상" in out
    assert "/srv/a/compose.yml" in out and "/srv/b/compose.yml" in out


def test_rule_errors_are_shown(context_factory):
    result = ScanResult(findings=[], errors=[RuleError("BOOM-1", "RuntimeError: x")], rules_run=1)
    out = _render(result, context_factory())
    assert "룰 실행 오류" in out
    assert "BOOM-1" in out
    assert "발견된 취약점이 없습니다" not in out


def test_explain_only_shows_problem_findings(context_factory):
    result = ScanResult(
        findings=[_finding("F-1", "t", Status.FAIL), _finding("P-1", "t", Status.PASS)],
        rules_run=2,
    )
    out = _render(result, context_factory(), explain=True)
    assert out.count("■ 부작용 / 주의사항") == 1
    assert "echo fix" in out
    assert "https://example.com" in out


def test_notices_are_rendered(context_factory):
    context = context_factory()
    context.notices.append("안내 메시지입니다")
    out = _render(ScanResult(rules_run=0), context)
    assert "안내 메시지입니다" in out
