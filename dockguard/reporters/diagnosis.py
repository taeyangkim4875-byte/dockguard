"""rich 기반 진단(diagnose) 리포트.

출력의 목적은 "정답만 알려주기"가 아니라 **추론 과정을 보여주기**다.
숙련된 엔지니어가 옆에서 하나씩 짚어 주듯, 무엇을 어떤 순서로 확인했고 각 단계에서 실제로 무엇을
봤는지(근거)를 남기고, 마지막에 근본 원인·해결책·주의사항을 강조한다.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group, RenderableType
from rich.markdown import Markdown
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dockguard import __version__
from dockguard.core.context import ScanContext
from dockguard.core.models import Status
from dockguard.diagnostics.models import DiagnosisResult, DiagnosisStep
from dockguard.reporters.terminal import STATUS_LABELS

# 단계 판정 표시 (색과 함께 쓴다 — 색을 못 쓰는 터미널·캡처에서도 읽히도록 글자로도 구분한다)
STEP_MARKS: dict[Status, str] = {
    Status.PASS: "통과",
    Status.FAIL: "실패",
    Status.WARN: "주의",
    Status.SKIP: "생략",
}
STEP_STYLES: dict[Status, str] = {
    Status.PASS: "green",
    Status.FAIL: "bold red",
    Status.WARN: "yellow",
    Status.SKIP: "dim",
}


def render_diagnosis(console: Console, context: ScanContext, result: DiagnosisResult) -> None:
    """진단 결과를 터미널에 출력한다."""
    console.print(_header(context, result))

    if result.error is not None:
        console.print(
            Panel(
                Text.assemble(
                    ("진단을 실행할 수 없습니다.\n\n", "bold yellow"),
                    (result.error + "\n\n", ""),
                    ("Docker가 있는 호스트에서 실행하거나, 서버에서 떠 온 스냅샷을 ", "dim"),
                    ("--docker-snapshot", "bold dim"),
                    (" 으로 지정하세요.", "dim"),
                ),
                border_style="yellow",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )
        return

    console.print(_steps_table(result.steps))

    root = result.root
    if root is not None:
        console.print(_root_cause_panel(root))
        for extra in result.also_failed:
            console.print(_extra_failure_panel(extra))
    else:
        console.print(_unresolved_panel(result))
    console.print()


# ---------------------------------------------------------------------- 구성 요소


def _header(context: ScanContext, result: DiagnosisResult) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("증상", Text(result.symptom.replace("`", ""), style="bold yellow"))
    grid.add_row("대상", result.target)
    grid.add_row("호스트", context.hostname)
    grid.add_row("진단 시각", context.scanned_at.strftime("%Y-%m-%d %H:%M:%S (UTC%z)"))
    return Panel(
        grid,
        title=f"[bold]dockguard[/bold] 원인 진단 — {result.title} [dim]v{__version__}[/dim]",
        title_align="left",
        border_style="blue",
        box=box.ROUNDED,
    )


def _steps_table(steps: list[DiagnosisStep]) -> Group:
    """검사 로그 — 각 단계의 판정과 실제로 확인한 값.

    판정과 본문을 2열 그리드로 나눠, 긴 근거 줄이 접혀도 열이 흐트러지지 않게 한다.
    """
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True, justify="left")  # [통과] / [실패] ...
    grid.add_column(overflow="fold", ratio=1)
    for step in steps:
        _, status_style = STATUS_LABELS[step.status]
        body: list[RenderableType] = [
            Text(step.name, style="bold" if step.status == Status.FAIL else ""),
            Text.assemble(("→ ", "dim"), (step.detail, status_style if step.status == Status.FAIL else "")),
        ]
        body += [Text(f"· {line}", style="dim") for line in step.evidence]
        body.append(Text())
        grid.add_row(Text(f"[{STEP_MARKS[step.status]}]", style=STEP_STYLES[step.status]), Group(*body))
    return Group(Text("\n  검사 과정", style="bold"), Text(), Padding(grid, (0, 0, 0, 2)))


def _root_cause_panel(step: DiagnosisStep) -> Panel:
    body: list[RenderableType] = [Markdown(f"**{step.cause}**")]
    if step.evidence:
        body += [Text(), Text("■ 근거 (실제로 확인한 값)", style="bold")]
        body += [Text(f"  {line}", style="dim") for line in step.evidence]
    if step.fix:
        body += [Text(), Text("■ 해결", style="bold green"), Markdown(step.fix, code_theme="monokai")]
    if step.tradeoff:
        body += [Text(), Text("■ 주의사항 / 부작용", style="bold yellow"), Markdown(step.tradeoff)]
    return Panel(
        Group(*body),
        title=Text.assemble((" 근본 원인 ", "bold white on red"), " ", (step.name.split(". ", 1)[-1], "dim")),
        title_align="left",
        border_style="red",
        box=box.HEAVY,
        padding=(1, 2),
    )


def _extra_failure_panel(step: DiagnosisStep) -> Panel:
    """근본 원인 외에 함께 고쳐야 할 문제 — 이것까지 고쳐야 실제로 복구된다."""
    body: list[RenderableType] = [Markdown(f"**{step.cause}**")]
    if step.evidence:
        body += [Text()] + [Text(f"  {line}", style="dim") for line in step.evidence]
    if step.fix:
        body += [Text(), Text("■ 해결", style="bold green"), Markdown(step.fix, code_theme="monokai")]
    if step.tradeoff:
        body += [Text(), Text("■ 주의사항", style="bold yellow"), Markdown(step.tradeoff)]
    return Panel(
        Group(*body),
        title=Text.assemble((" 추가로 발견된 문제 ", "bold black on yellow"), " ", ("이것도 고쳐야 연결됩니다", "dim")),
        title_align="left",
        border_style="yellow",
        box=box.ROUNDED,
        padding=(1, 2),
    )


def _unresolved_panel(result: DiagnosisResult) -> Panel:
    warned = result.warnings
    body: list[RenderableType] = [
        Text("네트워크 레벨에서는 연결을 막는 원인을 찾지 못했습니다.", style="bold green"),
        Text(
            "두 컨테이너는 서로 도달할 수 있는 상태입니다. 남은 원인은 방화벽이나 애플리케이션 레벨일 가능성이 큽니다.",
            style="dim",
        ),
    ]
    if warned:
        body += [Text(), Text("■ 다만 다음은 확인해 보세요", style="bold yellow")]
        body += [Text(f"  · {s.detail}", style="yellow") for s in warned]
    if result.next_checks:
        checks = Table.grid(padding=(0, 1))
        checks.add_column(no_wrap=True, style="bold")
        checks.add_column(overflow="fold", ratio=1)
        for i, line in enumerate(result.next_checks, start=1):
            checks.add_row(f"{i}.", line)
        body += [Text(), Text("■ 다음으로 확인할 것", style="bold"), Padding(checks, (0, 0, 0, 2))]
    return Panel(Group(*body), border_style="green", box=box.ROUNDED, padding=(1, 2))
