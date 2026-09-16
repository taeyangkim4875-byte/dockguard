"""dockguard CLI 진입점 (typer + rich)."""

from __future__ import annotations

import errno
import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from dockguard import __version__
from dockguard.core.collector import collect
from dockguard.core.engine import ScanEngine
from dockguard.core.models import Category, Severity, Status
from dockguard.core.rule import registered_rule_classes
from dockguard.core.ruleset import Ruleset, RulesetError, find_ruleset_file, load_ruleset
from dockguard.core.scoring import calculate_score
from dockguard.rules import load_all_rules
from dockguard.knowledge.explanations import EXPLANATIONS, get_topic, suggest_topics
from dockguard.remediators.daemon_remediator import RemediationError, apply_plan, build_plan, next_steps
from dockguard.reporters.html import render_html
from dockguard.reporters.json_reporter import render_json
from dockguard.reporters.remediation import (
    render_apply_result,
    render_apply_warnings,
    render_dry_run_footer,
    render_plan,
    render_rule_list,
)
from dockguard.reporters.diagnosis import render_diagnosis
from dockguard.reporters.terminal import TerminalReporter, render_topic, render_topic_list
from dockguard.diagnostics.connectivity import ConnectivityDiagnosis


class OutputFormat(str, Enum):
    TERMINAL = "terminal"
    JSON = "json"
    HTML = "html"


class FailOn(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

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
    output_format: Annotated[
        Optional[OutputFormat],
        typer.Option(
            "--format",
            help="출력 형식. 기본: terminal (--output의 확장자가 .html/.json이면 그 형식)",
            case_sensitive=False,
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="리포트를 파일로 저장 (예: report.html, result.json, scan.txt)", dir_okay=False),
    ] = None,
    fail_on: Annotated[
        Optional[FailOn],
        typer.Option(
            "--fail-on",
            help="이 심각도 이상의 취약 항목이 있으면 종료 코드 1 (CI 파이프라인용)",
            case_sensitive=False,
        ),
    ] = None,
    ruleset_path: Annotated[
        Optional[Path],
        typer.Option(
            "--ruleset",
            help="룰을 끄거나 심각도를 조정하는 파일 (config/ruleset.example.yaml 참고). 기본: ./ruleset.yaml, ./config/ruleset.yaml, /etc/dockguard/ruleset.yaml",
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """Docker 호스트의 보안 설정을 진단합니다."""
    fmt = resolve_format(output_format, output)
    # JSON을 표준 출력으로 내보낼 때는 진행 표시 · 안내를 stderr로 보내 파이프를 오염시키지 않는다
    console = Console(stderr=fmt == OutputFormat.JSON and output is None)
    categories = {c.value for c in category} if category else {c.value for c in Category}
    # 대상 파일을 직접 지정했다면 해당 영역 점검은 당연히 포함
    if compose:
        categories.add(Category.COMPOSE.value)
    if deps or docker_snapshot:
        categories.add(Category.NETWORK.value)

    missing_files = [
        (label, path)
        for label, path in (
            ("daemon.json", daemon_config),
            ("의존성 파일", deps),
            ("스냅샷 파일", docker_snapshot),
            ("룰셋 파일", ruleset_path),
        )
        if path is not None and not path.is_file()
    ]
    for label, path in missing_files:
        console.print(f"[bold red]오류:[/] 지정한 {label}을(를) 찾을 수 없습니다: {path}")
    missing = [p for p in compose or [] if not p.exists()]
    if missing:
        console.print(f"[bold red]오류:[/] 지정한 compose 파일/폴더를 찾을 수 없습니다: {', '.join(map(str, missing))}")
    if missing_files or missing:
        raise typer.Exit(code=2)

    ruleset = _load_ruleset(console, ruleset_path)
    engine = ScanEngine(categories=categories, ruleset=ruleset)
    if not engine.rules:
        console.print(
            f"[yellow]선택한 영역({', '.join(sorted(categories))})에 실행할 룰이 없습니다.[/] "
            "[dim]`--category daemon`으로 다시 시도하거나 룰셋의 disabled 목록을 확인하세요.[/]"
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
    if ruleset.path is not None:
        context.ruleset_path = ruleset.path
        context.notices.insert(0, f"룰셋 적용 ({ruleset.path}) — {ruleset.summary()}")
        context.ruleset_summary = ruleset.summary()

    _emit_report(console, fmt, output, explain, context, result, score)

    if fail_on is not None:
        threshold = Severity(fail_on.value)
        blocking = [f for f in result.findings if f.status == Status.FAIL and f.severity.rank <= threshold.rank]
        if blocking:
            # 경고는 stderr로 — cron에서 stdout을 버려도(> /dev/null) 이 메시지는 메일로 전달된다
            ids = ", ".join(dict.fromkeys(f.rule_id for f in sorted(blocking, key=lambda f: f.sort_key())))
            Console(stderr=True).print(
                f"[bold red]--fail-on {threshold.name}:[/] {context.hostname}에서 {threshold.name} 이상 "
                f"취약 항목 {len(blocking)}건 ({ids}) → 종료 코드 1"
            )
            raise typer.Exit(code=1)


def _load_ruleset(console: Console, explicit: Path | None) -> Ruleset:
    """룰셋 파일을 찾아 읽는다. 형식이 틀리면 조용히 무시하지 않고 종료한다 (끄려던 룰이 켜진 채 점수가 나오면 안 된다)."""
    path = explicit or find_ruleset_file(Path.cwd())
    if path is None:
        return Ruleset()
    load_all_rules()
    try:
        return load_ruleset(path, (cls.id for cls in registered_rule_classes()))
    except RulesetError as exc:
        console.print(f"[bold red]룰셋 파일 오류[/] ({path}): {exc}")
        raise typer.Exit(code=2) from exc


def resolve_format(explicit: OutputFormat | None, output: Path | None) -> OutputFormat:
    """--format이 없으면 --output 확장자로 형식을 정한다."""
    if explicit is not None:
        return explicit
    if output is not None:
        suffix = output.suffix.lower()
        if suffix in (".html", ".htm"):
            return OutputFormat.HTML
        if suffix == ".json":
            return OutputFormat.JSON
    return OutputFormat.TERMINAL


def _default_report_path(context, suffix: str) -> Path:
    stamp = context.scanned_at.strftime("%Y%m%d-%H%M%S")
    host = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in context.hostname)
    return Path(f"dockguard-{host}-{stamp}{suffix}")


def _emit_report(console: Console, fmt: OutputFormat, output: Path | None, explain: bool, context, result, score) -> None:
    if fmt == OutputFormat.TERMINAL:
        if output is None:
            TerminalReporter(console=console, explain=explain).render(context, result, score)
            return
        with output.open("w", encoding="utf-8") as fh:
            file_console = Console(file=fh, width=120, color_system=None, force_terminal=False)
            TerminalReporter(console=file_console, explain=explain).render(context, result, score)
        _saved(console, "텍스트 리포트", output, score, result)
        return

    if fmt == OutputFormat.JSON:
        text = render_json(context, result, score)
        if output is None:
            sys.stdout.write(text)
            sys.stdout.flush()
            return
        output.write_text(text, encoding="utf-8")
        _saved(console, "JSON 리포트", output, score, result)
        return

    path = output or _default_report_path(context, ".html")
    path.write_text(render_html(context, result, score), encoding="utf-8")
    _saved(console, "HTML 리포트", path, score, result)


def _saved(console: Console, label: str, path: Path, score, result) -> None:
    counts = result.status_counts()
    console.print(
        f"[bold green]{label}를 저장했습니다:[/] {path.resolve()}\n"
        f"  전체 점수 [bold]{score.value}/100[/] (등급 {score.grade}) · "
        f"취약 {counts[Status.FAIL]} · 주의 {counts[Status.WARN]} · 통과 {counts[Status.PASS]}"
    )


@app.command()
def learn(
    topic: Annotated[
        Optional[str],
        typer.Argument(help="학습 주제 (예: icc, seccomp) 또는 룰 ID (예: DAEMON-001). 생략하면 주제 목록"),
    ] = None,
) -> None:
    """Docker 보안 개념을 배웁니다 — 개념, 동작 원리, 공격 시나리오, 권장 방법, 실제 사례."""
    console = Console()
    if topic is None:
        render_topic_list(console, list(EXPLANATIONS.values()))
        return
    found = get_topic(topic)
    if found is None:
        suggestions = suggest_topics(topic)
        hint = f" 혹시 이것을 찾으셨나요? {', '.join(suggestions)}" if suggestions else ""
        console.print(f"[bold red]'{topic}' 주제를 찾을 수 없습니다.[/]{hint}\n[dim]dockguard learn 으로 전체 목록을 확인하세요.[/]")
        raise typer.Exit(code=2)
    render_topic(console, found)


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


diagnose_app = typer.Typer(
    help=(
        "이미 발생한 증상의 근본 원인을 추적합니다. scan이 '무엇이 위험한가'를 미리 찾는다면, "
        "diagnose는 '왜 안 되는가'를 단계별로 좁혀 나갑니다."
    ),
    no_args_is_help=True,
)
app.add_typer(diagnose_app, name="diagnose")


@diagnose_app.command("connectivity")
def diagnose_connectivity(
    source: Annotated[str, typer.Argument(help="연결을 시도하는 컨테이너 (이름 또는 compose 서비스 이름)")],
    target: Annotated[str, typer.Argument(help="연결 대상 컨테이너 (이름 또는 compose 서비스 이름)")],
    port: Annotated[
        Optional[int],
        typer.Option("--port", "-p", help="접속 포트 (예: 5672). 지정하면 대상이 그 포트를 여는지도 확인합니다."),
    ] = None,
    daemon_config: Annotated[
        Optional[Path],
        typer.Option("--daemon-config", help="daemon.json 경로 (icc 설정 확인용). 기본: 표준 위치 자동 탐색", dir_okay=False),
    ] = None,
    docker_snapshot: Annotated[
        Optional[Path],
        typer.Option(
            "--docker-snapshot",
            help="Docker에 직접 연결하는 대신 서버에서 떠 온 스냅샷 JSON으로 진단합니다 (오프라인 분석).",
            dir_okay=False,
        ),
    ] = None,
    output_format: Annotated[
        Optional[OutputFormat],
        typer.Option("--format", help="출력 형식 (terminal / json). 기본: terminal", case_sensitive=False),
    ] = None,
) -> None:
    """컨테이너 A가 컨테이너 B에 연결되지 않는 원인을 단계별로 추적합니다.

    실행 여부 → 포트 → 공유 네트워크 → icc → 접속 주소 순으로 좁혀 가며, 각 단계에서 실제로 확인한 값을
    함께 보여줍니다. 진단만 하고 설정을 바꾸지는 않습니다 (해결책은 제안으로 출력).

    종료 코드: 0 = 네트워크 레벨 원인 없음, 1 = 근본 원인 발견, 2 = 진단 불가
    """
    as_json = output_format == OutputFormat.JSON
    console = Console(stderr=as_json)
    for label, path in (("daemon.json", daemon_config), ("스냅샷 파일", docker_snapshot)):
        if path is not None and not path.is_file():
            console.print(f"[bold red]오류:[/] 지정한 {label}을(를) 찾을 수 없습니다: {path}")
            raise typer.Exit(code=2)
    if output_format == OutputFormat.HTML:
        console.print("[bold red]오류:[/] diagnose는 HTML 출력을 지원하지 않습니다 (terminal 또는 json).")
        raise typer.Exit(code=2)

    diagnosis = ConnectivityDiagnosis(source, target, port)
    with console.status("[bold blue]Docker 상태를 수집하고 원인을 추적하는 중...[/]", spinner="dots"):
        context = collect(
            categories={Category.NETWORK.value},
            daemon_config_path=daemon_config,
            docker_snapshot=docker_snapshot,
        )
        result = diagnosis.run(context)

    if as_json:
        sys.stdout.write(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
    else:
        render_diagnosis(console, context, result)

    if result.error is not None:
        raise typer.Exit(code=2)
    raise typer.Exit(code=1 if result.resolved else 0)


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
    try:
        app()
    except BrokenPipeError:
        _exit_on_closed_pipe()
    except OSError as exc:
        # Windows는 닫힌 파이프를 EINVAL로 알린다
        if exc.errno not in (errno.EPIPE, errno.EINVAL):
            raise
        _exit_on_closed_pipe()


def _exit_on_closed_pipe() -> None:
    """`dockguard learn icc | head`처럼 읽는 쪽이 먼저 끝나면 트레이스백 없이 조용히 종료한다."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):  # pragma: no cover
        pass
    sys.exit(1)


if __name__ == "__main__":
    main()
