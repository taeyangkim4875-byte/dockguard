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
    explain: Annotated[
        bool,
        typer.Option("--explain", "-e", help="각 항목의 위험 이유 · 수정 방법 · 부작용을 상세히 표시합니다."),
    ] = False,
) -> None:
    """Docker 호스트의 보안 설정을 진단합니다."""
    console = Console()
    categories = {c.value for c in category} if category else {c.value for c in Category}

    if daemon_config is not None and not daemon_config.is_file():
        console.print(f"[bold red]오류:[/] 지정한 daemon.json 파일을 찾을 수 없습니다: {daemon_config}")
        raise typer.Exit(code=2)

    engine = ScanEngine(categories=categories)
    if not engine.rules:
        console.print(
            f"[yellow]선택한 영역({', '.join(sorted(categories))})에 등록된 룰이 없습니다.[/] "
            "[dim]`--category daemon`으로 다시 시도해 보세요.[/]"
        )
        raise typer.Exit(code=0)

    with console.status("[bold blue]Docker 설정을 수집하고 점검하는 중...[/]", spinner="dots"):
        context = collect(categories=categories, daemon_config_path=daemon_config)
        result = engine.run(context)
        score = calculate_score(result.findings)

    TerminalReporter(console=console, explain=explain).render(context, result, score)


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
