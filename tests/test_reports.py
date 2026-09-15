"""JSON · HTML · 텍스트 리포트와 --format / --output / --fail-on 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dockguard.cli import OutputFormat, app, resolve_format
from dockguard.core.context import Dependency, DockerRuntime
from dockguard.core.engine import ScanEngine
from dockguard.core.scoring import calculate_score
from dockguard.reporters.html import markdown_to_html, render_html
from dockguard.reporters.json_reporter import SCHEMA_VERSION, build_report, render_json

runner = CliRunner()


def _scan(*args: str):
    return runner.invoke(app, ["scan", *args], env={"COLUMNS": "140"})


@pytest.fixture
def incident_scan(incident_dir):
    """정전 사고 예시 전체(daemon · compose · network) 스캔 인자."""
    return [
        "--daemon-config", str(incident_dir / "daemon.json"),
        "-f", str(incident_dir),
        "--docker-snapshot", str(incident_dir / "snapshot.json"),
        "--deps", str(incident_dir / "dependencies.yaml"),
    ]  # fmt: skip


def _report_inputs(context):
    result = ScanEngine().run(context)
    return context, result, calculate_score(result.findings)


# ============================================================================ 형식 결정


@pytest.mark.parametrize(
    ("explicit", "output", "expected"),
    [
        (None, None, OutputFormat.TERMINAL),
        (None, Path("r.html"), OutputFormat.HTML),
        (None, Path("r.HTM"), OutputFormat.HTML),
        (None, Path("r.json"), OutputFormat.JSON),
        (None, Path("r.txt"), OutputFormat.TERMINAL),
        (OutputFormat.JSON, Path("r.html"), OutputFormat.JSON),  # 명시한 형식이 우선
    ],
)
def test_resolve_format(explicit, output, expected):
    assert resolve_format(explicit, output) == expected


# ============================================================================ JSON


class TestJson:
    def test_structure(self, daemon_context):
        report = build_report(*_report_inputs(daemon_context("insecure.json")))
        assert report["schema_version"] == SCHEMA_VERSION
        assert report["tool"]["name"] == "dockguard"
        assert report["score"] == {"value": 0, "max": 100, "grade": "F", "deducted": report["score"]["deducted"]}
        assert report["summary"]["status"]["fail"] >= 9
        assert set(report["summary"]["failed_by_severity"]) == {"critical", "high", "medium", "low", "info"}
        first = report["findings"][0]
        assert first["status"] == "fail" and first["severity"] in {"critical", "high"}
        assert {"why", "how_to_fix", "tradeoff", "reference", "learn_topic"} <= set(first)

    def test_learn_topic_is_linked(self, daemon_context):
        findings = {f["rule_id"]: f for f in build_report(*_report_inputs(daemon_context("insecure.json")))["findings"]}
        assert findings["DAEMON-001"]["learn_topic"] == "icc"
        assert findings["DAEMON-004"]["learn_topic"] is None

    def test_render_is_valid_json(self, daemon_context):
        text = render_json(*_report_inputs(daemon_context("secure.json")))
        assert json.loads(text)["score"]["grade"] in {"A", "B"}

    def test_cli_json_stdout_is_pure_json(self, daemon_fixture):
        result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "--format", "json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)  # 진행 표시나 안내가 섞이면 파싱 실패
        assert data["findings"]

    def test_cli_json_to_file(self, tmp_path, incident_scan):
        out = tmp_path / "result.json"
        result = _scan(*incident_scan, "-o", str(out))
        assert result.exit_code == 0, result.output
        assert "JSON 리포트를 저장했습니다" in result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["host"] == "prod-server-01 (스냅샷)"
        assert data["sources"]["docker"]["available"] is True
        assert any(f["rule_id"] == "NET-001" and f["status"] == "fail" for f in data["findings"])


# ============================================================================ HTML


class TestHtml:
    def test_cli_html_report(self, tmp_path, incident_scan):
        out = tmp_path / "report.html"
        result = _scan(*incident_scan, "-o", str(out))
        assert result.exit_code == 0, result.output
        html = out.read_text(encoding="utf-8")
        assert "<title>prod-server-01 (스냅샷) 보안 진단 리포트</title>" in html
        for text in ("NET-001", "COMPOSE-002", "DAEMON-006", "고치면 생기는 일", "조치가 필요한 항목", "docker network connect"):
            assert text in html
        assert 'href="#net-001-1"' in html and 'id="net-001-1"' in html  # 요약 표 → 카드 이동

    def test_report_is_self_contained(self, daemon_context):
        html = render_html(*_report_inputs(daemon_context("insecure.json")))
        assert "<link" not in html
        assert "<script src" not in html
        assert "@import" not in html

    def test_user_input_is_escaped(self, context_factory, make_runtime, make_container):
        """dependencies.yaml의 reason 같은 사용자 입력이 리포트에서 스크립트로 실행되면 안 된다."""
        runtime = make_runtime([make_container("a", ["x"]), make_container("b", ["y"])])
        dep = Dependency("a", "b", reason='<script>alert("xss")</script>', origin="<img src=x onerror=alert(1)>")
        context = context_factory(docker=runtime, dependencies=[dep], categories={"network"})
        html = render_html(*_report_inputs(context))
        assert "<script>alert" not in html
        assert "<img src=x" not in html
        assert "&lt;script&gt;alert" in html

    def test_markdown_rendering(self):
        html = str(markdown_to_html("**굵게** `code`\n\n```bash\necho hi\n```\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n<b>raw</b>"))
        assert "<strong>굵게</strong>" in html and "<code>code</code>" in html
        assert '<pre><code class="language-bash">echo hi' in html
        assert "<table>" in html
        assert "<b>raw</b>" not in html and "&lt;b&gt;raw&lt;/b&gt;" in html

    def test_empty_problems_message(self, daemon_context):
        html = render_html(*_report_inputs(daemon_context("secure.json")))
        assert "조치가 필요한 항목이 없습니다" in html or "취약" in html

    def test_collection_errors_are_shown(self, context_factory):
        context = context_factory(docker=DockerRuntime(available=False, error="연결 실패 테스트"), categories={"network"})
        context.errors.append("Docker 상태를 수집하지 못해 네트워크 점검을 건너뜁니다 — 연결 실패 테스트")
        html = render_html(*_report_inputs(context))
        assert "점검하지 못한 대상" in html and "연결 실패 테스트" in html

    def test_default_html_path(self, tmp_path, monkeypatch, daemon_fixture):
        monkeypatch.chdir(tmp_path)
        result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "--format", "html")
        assert result.exit_code == 0, result.output
        files = list(tmp_path.glob("dockguard-*.html"))
        assert len(files) == 1


# ============================================================================ 텍스트 / --fail-on


def test_terminal_report_to_text_file(tmp_path, daemon_fixture):
    out = tmp_path / "scan.txt"
    result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "-o", str(out), "--explain")
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "전체 점수" in text and "왜 위험한가" in text
    assert "\x1b[" not in text  # 색상 코드 없이 저장


@pytest.mark.parametrize(
    ("fixture", "level", "code"),
    [
        ("insecure.json", "high", 1),  # HIGH 취약 있음
        ("insecure.json", "critical", 0),  # daemon 룰에는 CRITICAL이 없음
        ("secure.json", "low", 0),
    ],
)
def test_fail_on(daemon_fixture, fixture, level, code):
    result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture(fixture)), "--fail-on", level)
    assert result.exit_code == code, result.output
    if code:
        assert "종료 코드 1" in result.output


def test_fail_on_with_json_keeps_stdout_clean(daemon_fixture):
    result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "--format", "json", "--fail-on", "high")
    assert result.exit_code == 1
    json.loads(result.stdout)
