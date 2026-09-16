"""README용 스크린샷과 샘플 리포트를 만든다 — 실제 출력 그대로 (정전 사고 재현 예시 기준).

    python scripts/make_screenshots.py --font path/to/D2Coding.ttf

생성물:
    docs/images/terminal-network.png   네트워크 · 의존성 진단 결과 (터미널)
    docs/images/terminal-diagnose.png  장애 원인 진단 (diagnose connectivity)
    docs/images/terminal-explain.png   NET-001 상세 설명 (--explain)
    docs/images/terminal-fix.png       daemon.json 안전 수정 미리보기 (fix daemon)
    docs/images/report.png             HTML 리포트 첫 화면
    docs/sample-report.html            HTML 리포트 샘플 (전체 영역)

터미널 화면은 rich의 HTML 내보내기를 브라우저(Edge/Chrome 헤드리스)로 캡처한다. 한글은 영문 두 칸 너비여야
표가 맞으므로, 한글 고정폭 글꼴(D2Coding 등)을 --font로 주는 것을 권장한다. (SVG 내보내기는 한글 폭을 맞추지 못한다.)
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from rich.console import Console
from rich.terminal_theme import MONOKAI

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dockguard.core.collector import collect, load_daemon_config  # noqa: E402
from dockguard.core.context import DaemonConfig  # noqa: E402
from dockguard.core.engine import ScanEngine  # noqa: E402
from dockguard.core.models import Status  # noqa: E402
from dockguard.core.scoring import calculate_score  # noqa: E402
from dockguard.diagnostics.connectivity import ConnectivityDiagnosis  # noqa: E402
from dockguard.reporters.diagnosis import render_diagnosis  # noqa: E402
from dockguard.remediators.daemon_remediator import build_plan  # noqa: E402
from dockguard.reporters.html import render_html  # noqa: E402
from dockguard.reporters.remediation import render_dry_run_footer, render_plan  # noqa: E402
from dockguard.reporters.terminal import TerminalReporter  # noqa: E402

INCIDENT = ROOT / "examples" / "rabbitmq-incident"
DOCS = ROOT / "docs"
IMAGES = DOCS / "images"

COLUMNS = 112
FONT_PX = 15
CELL_PX = FONT_PX / 2  # 한글 고정폭 글꼴: 영문 0.5em, 한글 1em
LINE_PX = 20
PAGE_PAD, WIN_PAD, TITLE_BAR = 28, 20, 34

# rich의 export_html은 str.format으로 채우므로 CSS 중괄호는 두 번 쓴다. @@...@@는 먼저 치환한다.
TERMINAL_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
@font-face {{ font-family: "Term"; src: url("@@FONT@@"); }}
@font-face {{ font-family: "Term"; font-weight: bold; src: url("@@FONT_BOLD@@"); }}
html, body {{ margin: 0; background: #d8dee6; }}
body {{ padding: @@PAGE@@px; }}
.win {{ background: {background}; border-radius: 10px; box-shadow: 0 12px 36px rgba(20, 30, 45, .35); overflow: hidden; }}
.bar {{ height: @@BAR@@px; display: flex; align-items: center; gap: 8px; padding: 0 14px; background: #1f2126; }}
.dot {{ width: 12px; height: 12px; border-radius: 50%; }}
.title {{ flex: 1; text-align: center; color: #9aa3ad; font: 13px system-ui, sans-serif; margin-right: 60px; }}
pre {{ margin: 0; padding: @@WIN@@px; color: {foreground}; font: @@FONT_PX@@px/@@LINE@@px "Term", "D2Coding", "GulimChe", monospace; }}
code {{ font-family: inherit; }}
{stylesheet}
</style></head><body><div class="win">
<div class="bar"><span class="dot" style="background:#ff5f57"></span><span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span><span class="title">@@TITLE@@</span></div>
<pre><code>{code}</code></pre></div></body></html>"""


def find_browser() -> str | None:
    if os.environ.get("DOCKGUARD_BROWSER"):
        return os.environ["DOCKGUARD_BROWSER"]
    for name in ("msedge", "google-chrome", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in (
        Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("ProgramFiles", "")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("ProgramFiles", "")) / "Google/Chrome/Application/chrome.exe",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def screenshot(browser: str, page: Path, out: Path, width: int, height: int) -> None:
    subprocess.run(
        [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--allow-file-access-from-files",
            "--force-device-scale-factor=2",  # 레티나 화면에서도 선명하게
            f"--window-size={width},{height}",
            f"--screenshot={out}",
            page.resolve().as_uri(),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )


def _console() -> Console:
    # 화면에는 출력하지 않고 기록만 한다
    return Console(record=True, width=COLUMNS, force_terminal=True, color_system="truecolor", file=io.StringIO())


def _incident_context(categories: set[str]):
    return collect(
        categories=categories,
        daemon_config_path=INCIDENT / "daemon.json",
        compose_paths=[INCIDENT],
        deps_path=INCIDENT / "dependencies.yaml",
        docker_snapshot=INCIDENT / "snapshot.json",
    )


def network_scan() -> Console:
    context = _incident_context({"network"})
    result = ScanEngine(categories={"network"}).run(context)
    console = _console()
    TerminalReporter(console=console).render(context, result, calculate_score(result.findings))
    return console


def diagnose_connectivity() -> Console:
    """정전 사고 스냅샷으로 backend → rabbitmq 연결 실패를 진단한 화면."""
    context = _incident_context({"network"})
    if context.daemon is not None:  # 실제 서버 경로처럼 보이도록 (예시 파일의 로컬 경로를 감춘다)
        context.daemon.path = PurePosixPath("/etc/docker/daemon.json")  # type: ignore[assignment]
    result = ConnectivityDiagnosis("backend-container", "rabbitmq", 5672).run(context)
    console = _console()
    render_diagnosis(console, context, result)
    return console


def explain_net001() -> Console:
    context = _incident_context({"network"})
    result = ScanEngine(categories={"network"}).run(context)
    finding = next(f for f in result.findings if f.rule_id == "NET-001" and f.status == Status.FAIL)
    console = _console()
    console.print(TerminalReporter(console=console)._explain_panel(finding))
    return console


def fix_preview() -> Console:
    # 실제 서버 경로처럼 보이도록 /etc/docker/daemon.json으로 표시
    fixture = load_daemon_config(ROOT / "tests" / "fixtures" / "daemon" / "insecure.json")
    context = _incident_context({"daemon"})
    context.daemon = DaemonConfig(path=Path("/etc/docker/daemon.json"), exists=True, data=fixture.data, raw_text=fixture.raw_text)
    engine = ScanEngine(categories={"daemon"})
    plan = build_plan(context, engine.run(context).findings, engine.rules)
    console = _console()
    render_plan(console, plan, dry_run=True)
    render_dry_run_footer(console, plan, None)
    return console


TERMINAL_SHOTS = {
    "terminal-network.png": (network_scan, "dockguard scan -c network --deps dependencies.yaml"),
    "terminal-diagnose.png": (
        diagnose_connectivity,
        "dockguard diagnose connectivity backend-container rabbitmq --port 5672",
    ),
    "terminal-explain.png": (explain_net001, "dockguard scan -c network --deps dependencies.yaml --explain"),
    "terminal-fix.png": (fix_preview, "dockguard fix daemon"),
}


def render_terminal_page(console: Console, title: str, font: Path | None, workdir: Path) -> tuple[Path, int, int]:
    lines = len(console.export_text(clear=False).rstrip("\n").splitlines())
    bold = font.with_name(font.name.replace("D2Coding-", "D2CodingBold-")) if font else None
    template = (
        TERMINAL_TEMPLATE.replace("@@FONT@@", font.resolve().as_uri() if font else "")
        .replace("@@FONT_BOLD@@", bold.resolve().as_uri() if bold and bold.is_file() else (font.resolve().as_uri() if font else ""))
        .replace("@@PAGE@@", str(PAGE_PAD))
        .replace("@@WIN@@", str(WIN_PAD))
        .replace("@@BAR@@", str(TITLE_BAR))
        .replace("@@FONT_PX@@", str(FONT_PX))
        .replace("@@LINE@@", str(LINE_PX))
        .replace("@@TITLE@@", title)
    )
    page = workdir / f"{abs(hash(title))}.html"
    page.write_text(console.export_html(theme=MONOKAI, inline_styles=True, code_format=template), encoding="utf-8")
    width = int(PAGE_PAD * 2 + WIN_PAD * 2 + COLUMNS * CELL_PX) + 2
    height = PAGE_PAD * 2 + TITLE_BAR + WIN_PAD * 2 + lines * LINE_PX + 2
    return page, width, height


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--font", type=Path, help="한글 고정폭 글꼴 파일 (예: D2Coding-Ver1.3.3.ttf)")
    args = parser.parse_args()

    IMAGES.mkdir(parents=True, exist_ok=True)
    context = _incident_context({"daemon", "compose", "network"})
    result = ScanEngine().run(context)
    sample = DOCS / "sample-report.html"
    sample.write_text(render_html(context, result, calculate_score(result.findings)), encoding="utf-8")
    print(f"✓ {sample.relative_to(ROOT)}")

    browser = find_browser()
    if browser is None:
        print("! Edge/Chrome을 찾지 못해 PNG는 만들지 않았습니다 (DOCKGUARD_BROWSER로 경로 지정 가능)")
        return
    if args.font is None:
        print("! --font 없이 만들면 한글 폭이 맞지 않을 수 있습니다 (D2Coding 권장)")

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for filename, (build, title) in TERMINAL_SHOTS.items():
            page, width, height = render_terminal_page(build(), title, args.font, workdir)
            screenshot(browser, page, IMAGES / filename, width, height)
            print(f"✓ docs/images/{filename}  ({width}×{height})")
    screenshot(browser, sample, IMAGES / "report.png", 1200, 1650)
    print("✓ docs/images/report.png")


if __name__ == "__main__":
    main()
