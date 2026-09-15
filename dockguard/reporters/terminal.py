"""rich 기반 터미널 리포트.

기본은 요약(점수 + 결과 테이블)만 보여주고, `--explain`을 붙이면
조치가 필요한 항목마다 why / how_to_fix / tradeoff를 상세히 보여준다 (정보 과부하 방지).
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dockguard import __version__
from dockguard.core.context import ScanContext
from dockguard.core.models import Finding, ScanResult, Severity, Status
from dockguard.core.scoring import MAX_SCORE, Score
from dockguard.knowledge.explanations import Topic, topic_for_rule

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
SEVERITY_BADGE_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold black on dark_orange",
    Severity.MEDIUM: "bold black on yellow",
    Severity.LOW: "bold black on cyan",
    Severity.INFO: "black on grey70",
}
STATUS_LABELS: dict[Status, tuple[str, str]] = {
    Status.FAIL: ("취약", "bold red"),
    Status.WARN: ("주의", "bold yellow"),
    Status.SKIP: ("건너뜀", "dim"),
    Status.PASS: ("통과", "green"),
}
GRADE_STYLES: dict[str, str] = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "F": "bold red",
}
GAUGE_WIDTH = 30


class TerminalReporter:
    """진단 결과를 터미널에 출력한다."""

    def __init__(self, console: Console | None = None, explain: bool = False) -> None:
        self.console = console or Console()
        self.explain = explain

    def render(self, context: ScanContext, result: ScanResult, score: Score) -> None:
        c = self.console
        c.print(self._header(context))
        c.print(self._score_panel(result, score))
        if context.errors:
            body = Text("\n".join(f"• {e}" for e in context.errors))
            c.print(Panel(body, title="점검하지 못한 대상", title_align="left", border_style="red"))
        if context.notices:
            notices = Table.grid(padding=(0, 1))
            notices.add_column(no_wrap=True)
            notices.add_column()
            for notice in context.notices:
                notices.add_row(Text("  !", style="bold yellow"), Text(notice, style="yellow"))
            c.print(notices)
            c.print()

        findings = result.sorted_findings()
        targets = {f.target for f in findings}
        if not findings:
            c.print(Text("  점검 결과가 없습니다 (점검 대상을 찾지 못했습니다).", style="yellow"))
        elif len(targets) == 1:
            target_line = Table.grid(padding=(0, 1))
            target_line.add_column(no_wrap=True, style="bold")
            target_line.add_column(overflow="fold")
            target_line.add_row("  대상", next(iter(targets)))
            c.print(target_line)
        if findings:
            c.print(self._findings_table(findings, show_target=len(targets) > 1))

        if result.errors:
            c.print(self._errors_panel(result))

        problems = [f for f in findings if f.is_problem]
        if self.explain:
            for finding in problems:
                c.print(self._explain_panel(finding))
        elif problems:
            c.print(
                Text.assemble(
                    ("  TIP ", "bold cyan"),
                    ("각 항목의 위험 이유 · 수정 방법 · ", ""),
                    ("부작용", "bold yellow"),
                    ("은 ", ""),
                    ("--explain", "bold"),
                    (" 옵션으로 확인하세요.", ""),
                )
            )
        if not problems and not result.errors and not context.errors and findings:
            c.print(Text("  발견된 취약점이 없습니다. 잘 관리되고 있어요!", style="bold green"))
        c.print()

    # ------------------------------------------------------------------ 헤더 / 점수

    def _header(self, context: ScanContext) -> Panel:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold")
        grid.add_column()
        grid.add_row("호스트", context.hostname)
        grid.add_row("점검 시각", context.scanned_at.strftime("%Y-%m-%d %H:%M:%S (UTC%z)"))
        grid.add_row("점검 영역", ", ".join(sorted(context.categories)))
        return Panel(
            grid,
            title=f"[bold]dockguard[/bold] 보안 진단 [dim]v{__version__}[/dim]",
            title_align="left",
            border_style="blue",
            box=box.ROUNDED,
        )

    def _score_panel(self, result: ScanResult, score: Score) -> Panel:
        grade_style = GRADE_STYLES.get(score.grade, "bold")
        filled = round(GAUGE_WIDTH * score.value / MAX_SCORE)
        score_line = Text.assemble(
            ("전체 점수: ", "bold"),
            (str(score.value), f"{grade_style}"),
            (f"/{MAX_SCORE}", "dim"),
            "   ",
            (f" 등급 {score.grade} ", f"reverse {grade_style}"),
        )
        gauge = Text.assemble(
            ("█" * filled, grade_style),
            ("░" * (GAUGE_WIDTH - filled), "dim"),
        )

        badges = Text()
        sev_counts = result.failed_severity_counts()
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            count = sev_counts[sev]
            badges.append(f" {sev.name} {count} ", style=SEVERITY_BADGE_STYLES[sev] if count else "dim")
            badges.append(" ")

        status_counts = result.status_counts()
        summary = Text()
        for i, status in enumerate((Status.PASS, Status.FAIL, Status.WARN, Status.SKIP)):
            label, style = STATUS_LABELS[status]
            if i:
                summary.append(" · ", style="dim")
            summary.append(f"{label} {status_counts[status]}", style=style if status_counts[status] else "dim")
        summary.append(f"   (룰 {result.rules_run}개 실행)", style="dim")

        return Panel(
            Group(score_line, gauge, Text(), badges, summary),
            border_style=grade_style.replace("bold ", ""),
            box=box.HEAVY,
            padding=(1, 2),
        )

    # ------------------------------------------------------------------ 결과 테이블

    def _findings_table(self, findings: list[Finding], show_target: bool) -> Table:
        table = Table(box=box.SIMPLE_HEAVY, header_style="bold", expand=True, pad_edge=False)
        table.add_column("심각도", no_wrap=True)
        table.add_column("ID", no_wrap=True, style="bold")
        table.add_column("제목", ratio=3, overflow="fold")
        table.add_column("상태", no_wrap=True)
        if show_target:
            table.add_column("대상", ratio=2, overflow="fold")
        table.add_column("현재값", ratio=3, overflow="fold")
        table.add_column("권장값", ratio=2, overflow="fold")

        for f in findings:
            label, status_style = STATUS_LABELS[f.status]
            dim = f.status in (Status.PASS, Status.SKIP)
            row: list[RenderableType] = [
                Text(f.severity.name, style="dim" if dim else SEVERITY_STYLES[f.severity]),
                f.rule_id,
                Text(f.title, style="dim" if dim else ""),
                Text(label, style=status_style),
            ]
            if show_target:
                row.append(Text(f.target, style="dim"))
            row.append(Text(f.current_value, style="dim" if dim else ""))
            # 통과한 항목은 권장값을 반복할 필요 없음
            row.append(Text("" if f.status == Status.PASS else f.recommended, style="green"))
            table.add_row(*row)
        return table

    def _errors_panel(self, result: ScanResult) -> Panel:
        body = Text()
        for err in result.errors:
            body.append(f"{err.rule_id}: ", style="bold")
            body.append(f"{err.message}\n")
        body.append("룰 실행 중 오류가 발생해 해당 항목은 점검되지 않았습니다.", style="dim")
        return Panel(body, title="룰 실행 오류", title_align="left", border_style="red")

    # ------------------------------------------------------------------ 상세 설명

    def _explain_panel(self, f: Finding) -> Panel:
        sev_style = SEVERITY_STYLES[f.severity]
        parts: list[RenderableType] = [
            Text.assemble(("대상    ", "bold"), f.target),
            Text.assemble(("현재값  ", "bold"), (f.current_value, "red"), ("  →  ", "dim"), (f.recommended, "green")),
        ]
        parts += self._section("왜 위험한가", f.why, "bold red")
        parts += self._section("어떻게 고치나", f.how_to_fix, "bold green")
        parts += self._section("부작용 / 주의사항", f.tradeoff, "bold yellow")

        meta = Text()
        if f.reference:
            meta.append("근거  ", style="bold")
            meta.append(f.reference + "\n", style="dim")
        if f.learn_more:
            meta.append("참고  ", style="bold")
            meta.append(f.learn_more + "\n", style="dim underline")
        topic = topic_for_rule(f.rule_id)
        if topic:
            meta.append("학습  ", style="bold")
            meta.append(f"dockguard learn {topic.key}", style="cyan")
            meta.append(f"  — {topic.title}", style="dim")
        meta.rstrip()
        if meta:
            parts += [Text(), meta]

        title = Text.assemble((f" {f.severity.name} ", SEVERITY_BADGE_STYLES[f.severity]), " ", (f"{f.rule_id}  {f.title}", "bold"))
        return Panel(Group(*parts), title=title, title_align="left", border_style=sev_style.replace("bold ", ""), padding=(1, 2))

    @staticmethod
    def _section(heading: str, body: str, style: str) -> list[RenderableType]:
        if not body:
            return []
        return [Text(), Text(f"■ {heading}", style=style), Markdown(body, code_theme="monokai")]


# ---------------------------------------------------------------------- dockguard learn

_SECTION_STYLES = {
    "concept": "bold cyan",
    "detail": "bold blue",
    "attack_scenario": "bold red",
    "best_practice": "bold green",
    "real_world": "bold yellow",
}


def render_topic_list(console: Console, topics: list[Topic]) -> None:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", pad_edge=False, title="dockguard learn — 보안 학습 주제", title_justify="left")
    table.add_column("주제", no_wrap=True, style="bold cyan")
    table.add_column("제목", no_wrap=True)
    table.add_column("요약", ratio=1)
    table.add_column("관련 룰", style="dim")
    for t in topics:
        table.add_row(t.key, t.title, t.summary, ", ".join(t.related_rules))
    console.print(table)
    console.print(Text("  dockguard learn <주제>  또는  dockguard learn <룰 ID>  (예: dockguard learn icc, dockguard learn COMPOSE-004)", style="dim"))


def render_topic(console: Console, topic: Topic) -> None:
    header = Text.assemble((topic.title, "bold"), "\n", (topic.summary, "dim"))
    console.print(Panel(header, title=f"[bold]dockguard learn[/] {topic.key}", title_align="left", border_style="cyan", padding=(1, 2)))
    for field_name, heading in Topic.SECTIONS:
        body = getattr(topic, field_name)
        console.print(Text(f"\n■ {heading}", style=_SECTION_STYLES[field_name]))
        console.print(Markdown(body, code_theme="monokai"))
    if topic.related_rules:
        console.print()
        console.print(
            Text.assemble(
                ("관련 점검  ", "bold"),
                (", ".join(topic.related_rules), "cyan"),
                ("   →  dockguard scan --explain 으로 내 환경의 해당 항목을 확인하세요", "dim"),
            )
        )
    console.print()
