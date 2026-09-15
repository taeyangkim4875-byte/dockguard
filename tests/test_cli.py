"""CLI 통합 테스트 (typer CliRunner)."""

from __future__ import annotations

from typer.testing import CliRunner

from dockguard import __version__
from dockguard.cli import app
from dockguard.core import collector

runner = CliRunner()


def _scan(*args: str):
    return runner.invoke(app, ["scan", *args], env={"COLUMNS": "140"})


def test_scan_secure_config_scores_100(daemon_fixture):
    result = _scan("--category", "daemon", "--daemon-config", str(daemon_fixture("secure.json")))
    assert result.exit_code == 0, result.output
    assert "100" in result.output
    assert "등급 A" in result.output
    assert "발견된 취약점이 없습니다" in result.output


def test_scan_insecure_config_reports_failures(daemon_fixture):
    result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")))
    assert result.exit_code == 0, result.output
    # HIGH(20) + MEDIUM(10) + LOW(3) = 33점 감점
    assert "67" in result.output
    assert "등급 C" in result.output
    for rule_id in ("DAEMON-001", "DAEMON-002", "DAEMON-004"):
        assert rule_id in result.output
    assert "--explain" in result.output  # 상세 설명 안내


def test_scan_explain_shows_tradeoff(daemon_fixture):
    result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "--explain")
    assert result.exit_code == 0, result.output
    assert "왜 위험한가" in result.output
    assert "어떻게 고치나" in result.output
    assert "부작용 / 주의사항" in result.output
    assert "CIS Docker Benchmark" in result.output


def test_scan_invalid_json_does_not_crash(daemon_fixture):
    result = _scan("-c", "daemon", "--daemon-config", str(daemon_fixture("invalid.json")))
    assert result.exit_code == 0, result.output
    assert "건너뜀" in result.output
    assert "JSON 파싱 실패" in result.output


def test_scan_missing_explicit_path_exits_with_friendly_error(tmp_path):
    result = _scan("-c", "daemon", "--daemon-config", str(tmp_path / "nope.json"))
    assert result.exit_code == 2
    assert "찾을 수 없습니다" in result.output


def test_scan_auto_detect_without_daemon_json(monkeypatch):
    monkeypatch.setattr(collector, "find_daemon_config", lambda: None)
    result = _scan("-c", "daemon")
    assert result.exit_code == 0, result.output
    assert "Docker 기본값 기준으로 점검" in result.output


def test_scan_category_without_rules_is_friendly():
    result = _scan("--category", "network")
    assert result.exit_code == 0, result.output
    assert "등록된 룰이 없습니다" in result.output


def test_scan_rejects_unknown_category():
    result = _scan("--category", "kernel")
    assert result.exit_code != 0


def test_version_option():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
