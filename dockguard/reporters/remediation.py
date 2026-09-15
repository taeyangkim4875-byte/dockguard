"""`dockguard fix` 화면 (수정 계획 · diff · 적용 전 경고 · 적용 결과)과 `dockguard rules` 목록."""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dockguard.core.models import ApplyMethod, FixRisk
from dockguard.core.rule import Rule
from dockguard.knowledge.references import short_reference
from dockguard.remediators.daemon_remediator import ApplyResult, NextStep, RemediationPlan
from dockguard.reporters.terminal import SEVERITY_STYLES

APPLY_LABELS = {ApplyMethod.RELOAD: ("리로드", "green"), ApplyMethod.RESTART: ("재시작", "yellow")}
RISK_LABELS = {
    FixRisk.SAFE: ("안전", "green"),
    FixRisk.RISKY: ("주의 (명시 필요)", "bold red"),
    FixRisk.NONE: ("미지원", "dim"),
}


def render_plan(console: Console, plan: RemediationPlan, *, dry_run: bool) -> None:
    mode = "[bold cyan]미리보기 (dry-run)[/]" if dry_run else "[bold yellow]적용 모드[/]"
    state = "" if plan.daemon.exists else " [dim](파일 없음 — 새로 생성)[/]"
    console.print(
        Panel(
            f"[bold]대상[/]  {plan.daemon.path}{state}",
            title=f"[bold]dockguard fix daemon[/] — {mode}",
            title_align="left",
            border_style="cyan" if dry_run else "yellow",
        )
    )

    if plan.fixes:
        table = Table(title="자동 수정 항목", title_justify="left", box=box.SIMPLE_HEAVY, expand=True, pad_edge=False)
        table.add_column("ID", no_wrap=True, style="bold")
        table.add_column("제목", ratio=2, overflow="fold")
        table.add_column("변경 내용", ratio=3, overflow="fold")
        table.add_column("반영", no_wrap=True)
        table.add_column("위험도", no_wrap=True)
        for fix in plan.fixes:
            apply_label, apply_style = APPLY_LABELS[fix.patch.apply_with]
            risk_label, risk_style = RISK_LABELS[fix.patch.risk]
            table.add_row(
                fix.finding.rule_id,
                Text(fix.finding.title, style=SEVERITY_STYLES[fix.finding.severity]),
                Text(fix.patch.summary, style="green"),
                Text(apply_label, style=apply_style),
                Text(risk_label, style=risk_style),
            )
        console.print(table)
        console.print(Text("변경 미리보기 (diff)", style="bold"))
        console.print(Panel(_colored_diff(plan.diff()), box=box.SQUARE, border_style="dim"))

        notes = [(f.finding.rule_id, f.patch.note) for f in plan.fixes if f.patch.note and f.patch.risk != FixRisk.RISKY]
        if notes:
            grid = Table.grid(padding=(0, 1))
            grid.add_column(no_wrap=True, style="bold cyan")
            grid.add_column(no_wrap=True, style="bold")
            grid.add_column()
            for rule_id, note in notes:
                grid.add_row("  참고", rule_id, note)
            console.print(grid)
    else:
        console.print(Text("  자동으로 수정할 항목이 없습니다.", style="bold green"))

    if plan.skipped:
        console.print()
        table = Table(title="수동 조치 필요 (자동 수정 대상 아님)", title_justify="left", box=box.SIMPLE, expand=True, pad_edge=False)
        table.add_column("ID", no_wrap=True, style="bold")
        table.add_column("제목", ratio=2, overflow="fold")
        table.add_column("이유", ratio=5, overflow="fold")
        for skipped in plan.skipped:
            table.add_row(
                skipped.finding.rule_id,
                Text(skipped.finding.title, style=SEVERITY_STYLES[skipped.finding.severity]),
                Text(skipped.reason, style="dim"),
            )
        console.print(table)
        console.print(Text("  각 항목의 수정 방법과 부작용: dockguard scan --category daemon --explain", style="dim"))


def render_dry_run_footer(console: Console, plan: RemediationPlan, selected_ids: list[str] | None) -> None:
    console.print()
    if not plan.has_changes:
        return
    rule_args = "".join(f" --rule {rid}" for rid in selected_ids or [])
    console.print(
        Text.assemble(
            ("  미리보기입니다. 파일은 변경되지 않았습니다. ", "bold"),
            ("적용하려면: ", ""),
            (f"dockguard fix daemon --apply{rule_args}", "bold cyan"),
        )
    )


def render_apply_warnings(console: Console, plan: RemediationPlan) -> None:
    """적용 직전의 경고. 재시작 영향과 RISKY 항목의 부작용을 강하게 보여준다."""
    lines = Text()
    if plan.daemon.exists:
        lines.append("• 원본은 ", style="")
        lines.append(f"{plan.daemon.path.name}.bak.<시각>", style="bold")
        lines.append(" 파일로 같은 폴더에 백업됩니다.\n")
    else:
        lines.append("• daemon.json이 없어 새로 생성합니다.\n")
    lines.append("• dockguard는 파일만 수정합니다. Docker 재시작/리로드는 적용 후 안내에 따라 직접 실행하세요.\n")

    if plan.apply_with == ApplyMethod.RESTART:
        if plan.live_restore_after:
            lines.append("• 데몬 재시작이 필요하지만, live-restore가 켜지므로 안내 순서대로 하면 컨테이너는 유지됩니다.")
        else:
            lines.append(
                "• 변경을 반영하려면 Docker 데몬을 재시작해야 하며, 이때 모든 컨테이너가 재기동됩니다.",
                style="bold yellow",
            )
    else:
        lines.append("• 리로드만으로 반영되어 실행 중인 컨테이너에는 영향이 없습니다.")
    console.print(Panel(lines, title="적용 전 확인", title_align="left", border_style="yellow"))

    for fix in plan.fixes:
        if fix.patch.risk == FixRisk.RISKY:
            console.print(
                Panel(
                    Group(
                        Text(f"{fix.finding.rule_id} {fix.finding.title} — {fix.patch.summary}", style="bold"),
                        Text(),
                        Text(fix.patch.note),
                    ),
                    title="[bold white on red] 부작용이 큰 수정이 포함되어 있습니다 [/]",
                    title_align="left",
                    border_style="red",
                    box=box.HEAVY,
                )
            )


def render_apply_result(console: Console, result: ApplyResult, steps: list[NextStep]) -> None:
    body = Text()
    body.append("수정 완료  ", style="bold green")
    body.append(f"{result.path}\n")
    body.append("백업      ", style="bold")
    body.append(f"{result.backup_path}\n" if result.backup_path else "(새 파일 생성 — 백업 없음)\n")
    body.append("검증      ", style="bold")
    body.append(result.validation)
    console.print(Panel(body, border_style="green", box=box.ROUNDED))

    console.print(Text("다음 단계", style="bold"))
    for step in steps:
        console.print(Text.assemble(("  • ", "dim"), (step.description, "bold yellow" if step.warning else "")))
        if step.command:
            console.print(Text(f"      {step.command}", style="bold cyan"))


def render_rule_list(console: Console, rules: list[Rule]) -> None:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", pad_edge=False)
    table.add_column("ID", no_wrap=True, style="bold")
    table.add_column("영역", no_wrap=True)
    table.add_column("심각도", no_wrap=True)
    table.add_column("제목")
    table.add_column("자동 수정", no_wrap=True)
    table.add_column("근거", style="dim")
    for rule in rules:
        risk_label, risk_style = RISK_LABELS[rule.fix_risk]
        table.add_row(
            rule.id,
            rule.category,
            Text(rule.severity.name, style=SEVERITY_STYLES[rule.severity]),
            rule.title,
            Text(risk_label, style=risk_style),
            short_reference(rule.reference),
        )
    console.print(table)
    console.print(Text(f"  등록된 룰 {len(rules)}개", style="dim"))


def _colored_diff(diff: str) -> Text:
    text = Text()
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            style = "bold"
        elif line.startswith("+"):
            style = "green"
        elif line.startswith("-"):
            style = "red"
        elif line.startswith("@@"):
            style = "cyan"
        else:
            style = "dim"
        text.append(line + "\n", style=style)
    text.rstrip()
    return text
