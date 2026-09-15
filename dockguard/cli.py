"""dockguard CLI 진입점 (typer + rich)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from dockguard import __version__
from dockguard.core.collector import collect
from dockguard.core.engine import ScanEngine
from dockguard.core.models import Category
from dockguard.core.scoring import calculate_score
from dockguard.remediators.daemon_remediator import RemediationError, apply_plan, build_plan, next_steps
from dockguard.reporters.remediation import (
    render_apply_result,
    render_apply_warnings,
    render_dry_run_footer,
    render_plan,
    render_rule_list,
)
from dockguard.reporters.terminal import TerminalReporter

app = typer.Typer(
    name="dockguard",
    help="Docker 호스트 통합 보안 진단 도구 — 취약점의 위험 이유, 수정 방법, 부작용까지 알려줍니다.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        Console().print(f"dockguard {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", "-V", callback=_version_callback, is_eager=True, help="버전을 출력합니다."),
    ] = False,
) -> None:
    """Docker 호스트 통합 보안 진단 도구."""


@app.command()
def scan(
    category: Annotated[
        Optional[list[Category]],
        typer.Option("--category", "-c", help="점검할 영역 (여러 번 지정 가능). 기본: 전체", case_sensitive=False),
    ] = None,
    daemon_config: Annotated[
        Optional[Path],
        typer.Option("--daemon-config", help="daemon.json 경로. 기본: 플랫폼별 표준 위치 자동 탐색", dir_okay=False),
    ] = None,
    compose: Annotated[
        Optional[list[Path]],
        typer.Option(
            "--compose",
            "-f",
            help="compose 파일 또는 폴더 (여러 번 지정 가능). 기본: 현재 디렉터리와 하위 폴더 자동 탐색",
        ),
    ] = None,
    deps: Annotated[
        Optional[Path],
        typer.Option(
            "--deps",
            "-d",
            help="서비스 의존성 파일 (config/dependencies.example.yaml 참고). 기본: ./dependencies.yaml, ./config/dependencies.yaml 자동 탐색",
            dir_okay=False,
        ),
    ] = None,
    docker_snapshot: Annotated[
        Optional[Path],
        typer.Option(
            "--docker-snapshot",
            help="Docker에 직접 연결하는 대신 서버에서 떠 온 스냅샷 JSON을 분석합니다 (오프라인 분석).",
            dir_okay=False,
        ),
    ] = None,
    explain: Annotated[
        bool,
        typer.Option("--explain", "-e", help="각 항목의 위험 이유 · 수정 방법 · 부작용을 상세히 표시합니다."),
    ] = False,
) -> None:
    """Docker 호스트의 보안 설정을 진단합니다."""
    console = Console()
    categories = {c.value for c in category} if category else {c.value for c in Category}
    # 대상 파일을 직접 지정했다면 해당 영역 점검은 당연히 포함
    if compose:
        categories.add(Category.COMPOSE.value)
    if deps or docker_snapshot:
        categories.add(Category.NETWORK.value)

    missing_files = [
        (label, path)
        for label, path in (("daemon.json", daemon_config), ("의존성 파일", deps), ("스냅샷 파일", docker_snapshot))
        if path is not None and not path.is_file()
    ]
    for label, path in missing_files:
        console.print(f"[bold red]오류:[/] 지정한 {label}을(를) 찾을 수 없습니다: {path}")
    missing = [p for p in compose or [] if not p.exists()]
    if missing:
        console.print(f"[bold red]오류:[/] 지정한 compose 파일/폴더를 찾을 수 없습니다: {', '.join(map(str, missing))}")
    if missing_files or missing:
        raise typer.Exit(code=2)

    engine = ScanEngine(categories=categories)
    if not engine.rules:
        console.print(
            f"[yellow]선택한 영역({', '.join(sorted(categories))})에 등록된 룰이 없습니다.[/] "
            "[dim]`--category daemon`으로 다시 시도해 보세요.[/]"
        )
        raise typer.Exit(code=0)

    with console.status("[bold blue]Docker 설정을 수집하고 점검하는 중...[/]", spinner="dots"):
        context = collect(
            categories=categories,
            daemon_config_path=daemon_config,
            compose_paths=compose,
            deps_path=deps,
            docker_snapshot=docker_snapshot,
        )
        result = engine.run(context)
        score = calculate_score(result.findings)

    TerminalReporter(console=console, explain=explain).render(context, result, score)


@app.command("rules")
def list_rules(
    category: Annotated[
        Optional[list[Category]],
        typer.Option("--category", "-c", help="표시할 영역 (여러 번 지정 가능). 기본: 전체", case_sensitive=False),
    ] = None,
) -> None:
    """등록된 모든 점검 룰과 심각도, 자동 수정 지원 여부를 보여줍니다."""
    categories = {c.value for c in category} if category else None
    render_rule_list(Console(), ScanEngine(categories=categories).rules)


fix_app = typer.Typer(
    help="취약한 설정을 안전하게 수정합니다. 기본은 미리보기(dry-run)이며, --apply를 붙여야 실제로 적용됩니다.",
    no_args_is_help=True,
)
app.add_typer(fix_app, name="fix")


@fix_app.command("daemon")
def fix_daemon(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run/--apply", help="--dry-run: 변경 미리보기 (기본) / --apply: 백업 후 실제 적용 (재확인)"),
    ] = True,
    rule: Annotated[
        Optional[list[str]],
        typer.Option(
            "--rule",
            "-r",
            help="수정할 룰 ID (여러 번 지정 가능). 부작용이 큰 항목(예: DAEMON-001)은 여기에 명시해야만 포함됩니다.",
        ),
    ] = None,
    daemon_config: Annotated[
        Optional[Path],
        typer.Option("--daemon-config", help="daemon.json 경로. 기본: 플랫폼별 표준 위치 자동 탐색", dir_okay=False),
    ] = None,
) -> None:
    """daemon.json의 안전한 항목을 수정합니다 (백업 · 검증 · 자동 롤백)."""
    console = Console()
    if daemon_config is not None and not daemon_config.is_file():
        console.print(f"[bold red]오류:[/] 지정한 daemon.json 파일을 찾을 수 없습니다: {daemon_config}")
        raise typer.Exit(code=2)

    engine = ScanEngine(categories={Category.DAEMON.value})
    selected = [r.upper() for r in rule] if rule else None
    if selected:
        known = {r.id for r in engine.rules}
        unknown = [r for r in selected if r not in known]
        if unknown:
            console.print(f"[bold red]오류:[/] 알 수 없는 daemon 룰 ID: {', '.join(unknown)} [dim](dockguard rules로 확인)[/]")
            raise typer.Exit(code=2)

    context = collect(categories={Category.DAEMON.value}, daemon_config_path=daemon_config)
    for notice in context.notices:
        console.print(f"[yellow]! {notice}[/]")
    scan_result = engine.run(context)

    try:
        plan = build_plan(context, scan_result.findings, engine.rules, selected)
    except RemediationError as exc:
        console.print(f"[bold red]수정할 수 없습니다:[/] {exc}")
        raise typer.Exit(code=2) from exc

    if selected:
        problem_ids = {f.rule_id for f in scan_result.findings if f.is_problem}
        already_ok = [r for r in selected if r not in problem_ids]
        if already_ok:
            console.print(f"[green]이미 권장 상태이거나 점검 대상이 아닌 항목:[/] {', '.join(already_ok)}")

    render_plan(console, plan, dry_run=dry_run)
    if dry_run:
        render_dry_run_footer(console, plan, selected)
        return
    if not plan.has_changes:
        return

    render_apply_warnings(console, plan)
    if not typer.confirm("위 내용으로 daemon.json을 수정할까요?", default=False):
        console.print("취소했습니다. 파일은 변경되지 않았습니다.")
        raise typer.Exit(code=1)
    if plan.risky_patches:
        ids = ", ".join(p.rule_id for p in plan.risky_patches)
        if not typer.confirm(f"[재확인] {ids}의 부작용을 확인했고, 그래도 적용할까요?", default=False):
            console.print("취소했습니다. 파일은 변경되지 않았습니다.")
            raise typer.Exit(code=1)

    try:
        applied = apply_plan(plan)
    except RemediationError as exc:
        console.print(f"[bold red]수정 실패:[/] {exc}")
        raise typer.Exit(code=1) from exc
    render_apply_result(console, applied, next_steps(plan, applied))


@fix_app.command("compose")
def fix_compose() -> None:
    """compose 파일은 자동 수정하지 않습니다 (이유와 대안 안내)."""
    console = Console()
    console.print(
        "[bold yellow]compose 파일은 자동으로 수정하지 않습니다.[/]\n\n"
        "서비스 간 의존성(네트워크, 볼륨 소유권, 기동 순서)이 얽혀 있어, 설정 한 줄을 바꿔도 다른 서비스가 "
        "끊길 수 있기 때문입니다. 대신 영향받는 서비스 이름을 넣은 [bold]수정 예시 YAML[/]을 보여드립니다:\n\n"
        "  [bold cyan]dockguard scan --category compose --explain[/]\n\n"
        "[dim]예시를 반영한 뒤 `docker compose config`로 문법을 확인하고, "
        "`docker compose up -d --force-recreate <서비스>`로 하나씩 적용하세요.[/]"
    )


def _configure_stdio() -> None:
    """Windows에서 출력이 파이프/파일로 리다이렉트될 때 인코딩 오류로 죽지 않게 한다."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure") and (stream.encoding or "").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):  # pragma: no cover
                pass


def main() -> None:
    """콘솔 스크립트 진입점."""
    _configure_stdio()
    app()


if __name__ == "__main__":
    main()
