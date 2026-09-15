"""CLI 통합 테스트 (typer CliRunner)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dockguard import __version__
from dockguard.cli import app
from dockguard.core import collector
from dockguard.remediators import daemon_remediator as rem

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
    # HIGH 4개(80) + MEDIUM 3개(30) + LOW 2개(6) = 116점 감점 → 하한 0
    assert "전체 점수: 0/100" in result.output
    assert "등급 F" in result.output
    for n in (1, 2, 3, 4, 5, 6, 8, 9, 10):
        assert f"DAEMON-{n:03d}" in result.output
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


def test_scan_compose_file(compose_fixture):
    result = _scan("--compose", str(compose_fixture("insecure.yml")))
    assert result.exit_code == 0, result.output
    assert "COMPOSE-001" in result.output and "COMPOSE-004" in result.output
    assert "compose" in result.output  # 점검 영역에 compose 포함


def test_scan_compose_explain_shows_service_specific_example(compose_fixture):
    result = _scan("-c", "compose", "-f", str(compose_fixture("insecure.yml")), "--explain")
    assert result.exit_code == 0, result.output
    assert "이 프로젝트에 적용할 수정 예시" in result.output
    assert "admin123" not in result.output  # 시크릿 값은 절대 출력하지 않는다


def test_scan_compose_auto_discovery(tmp_path, monkeypatch, compose_fixture):
    project = tmp_path / "app"
    project.mkdir()
    shutil.copy(compose_fixture("insecure.yml"), project / "docker-compose.yml")
    monkeypatch.chdir(tmp_path)
    result = _scan("-c", "compose")
    assert result.exit_code == 0, result.output
    assert "COMPOSE-001" in result.output


def test_scan_compose_parse_error_is_reported(compose_fixture):
    result = _scan("-c", "compose", "-f", str(compose_fixture("broken.yml")))
    assert result.exit_code == 0, result.output
    assert "점검하지 못한 대상" in result.output
    assert "YAML 문법 오류" in result.output
    assert "발견된 취약점이 없습니다" not in result.output


def test_scan_compose_nothing_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _scan("-c", "compose")
    assert result.exit_code == 0, result.output
    assert "compose 파일을 찾지 못했습니다" in result.output
    assert "점검 결과가 없습니다" in result.output


def test_scan_missing_compose_path(tmp_path):
    result = _scan("--compose", str(tmp_path / "nope.yml"))
    assert result.exit_code == 2
    assert "찾을 수 없습니다" in result.output


def test_fix_compose_explains_no_autofix():
    result = runner.invoke(app, ["fix", "compose"], env={"COLUMNS": "160"})
    assert result.exit_code == 0
    assert "자동으로 수정하지 않습니다" in result.output


def test_scan_category_without_rules_is_friendly(monkeypatch):
    from dockguard import cli

    class NoRules:
        def __init__(self, categories=None):
            self.rules = []

    monkeypatch.setattr(cli, "ScanEngine", NoRules)
    result = _scan("--category", "network")
    assert result.exit_code == 0, result.output
    assert "등록된 룰이 없습니다" in result.output


# ============================================================================ 네트워크 / 의존성 (Phase 4)


def test_incident_scenario_from_snapshot(incident_dir):
    """README · 데모의 핵심 시나리오: 정전 후 backend → rabbitmq 통신 불가를 즉시 발견."""
    result = _scan(
        "-c", "network",
        "--docker-snapshot", str(incident_dir / "snapshot.json"),
        "--deps", str(incident_dir / "dependencies.yaml"),
        "--daemon-config", str(incident_dir / "daemon.json"),
        "--explain",
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "공유 네트워크 없음" in result.output
    assert "docker network connect messaging_mq-net backend-container" in result.output
    assert "재시작 정책이 없어" in result.output
    assert "RabbitMQ 관리 UI" in result.output


def test_snapshot_option_implies_network_category(incident_dir):
    result = _scan("-c", "daemon", "--docker-snapshot", str(incident_dir / "snapshot.json"))
    assert result.exit_code == 0, result.output
    assert "NET-004" in result.output


def test_network_scan_without_docker_is_friendly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _scan("-c", "network")
    assert result.exit_code == 0, result.output
    assert "Docker 상태를 수집하지 못해" in result.output
    assert "건너뜀" in result.output


def test_missing_deps_file(tmp_path):
    result = _scan("--deps", str(tmp_path / "nope.yaml"))
    assert result.exit_code == 2
    assert "의존성 파일" in result.output


def test_missing_snapshot_file(tmp_path):
    result = _scan("--docker-snapshot", str(tmp_path / "nope.json"))
    assert result.exit_code == 2


def test_scan_rejects_unknown_category():
    result = _scan("--category", "kernel")
    assert result.exit_code != 0


def test_version_option():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


# ============================================================================ dockguard rules


def test_rules_lists_registered_rules():
    result = runner.invoke(app, ["rules"], env={"COLUMNS": "160"})
    assert result.exit_code == 0, result.output
    for n in range(1, 11):
        assert f"DAEMON-{n:03d}" in result.output
    assert "주의 (명시 필요)" in result.output  # icc는 RISKY
    assert "CIS 2.2" in result.output


def test_rules_category_filter():
    result = runner.invoke(app, ["rules", "--category", "network"], env={"COLUMNS": "160"})
    assert result.exit_code == 0
    assert "DAEMON-001" not in result.output


# ============================================================================ dockguard fix daemon


@pytest.fixture
def daemon_copy(tmp_path, daemon_fixture, monkeypatch):
    """tmp에 복사한 daemon.json. dockerd 검증은 환경에 따라 달라지므로 비활성화한다."""
    monkeypatch.setattr(rem.shutil, "which", lambda name: None)

    def _copy(name: str = "insecure.json") -> Path:
        target = tmp_path / "daemon.json"
        shutil.copy(daemon_fixture(name), target)
        return target

    return _copy


def _fix(*args: str, input: str | None = None):
    return runner.invoke(app, ["fix", "daemon", *args], input=input, env={"COLUMNS": "160"})


def _backups(path: Path) -> list[Path]:
    return list(path.parent.glob("daemon.json.bak.*"))


def test_fix_defaults_to_dry_run(daemon_copy):
    path = daemon_copy()
    before = path.read_bytes()
    result = _fix("--daemon-config", str(path))
    assert result.exit_code == 0, result.output
    assert "미리보기" in result.output
    assert '+  "live-restore": true,' in result.output
    assert "dockguard fix daemon --apply" in result.output
    assert path.read_bytes() == before
    assert not _backups(path)


def test_fix_dry_run_lists_manual_items(daemon_copy):
    result = _fix("--daemon-config", str(daemon_copy()))
    assert "수동 조치 필요" in result.output
    assert "--rule DAEMON-001" in result.output


def test_fix_apply_with_confirmation(daemon_copy):
    path = daemon_copy()
    result = _fix("--apply", "--daemon-config", str(path), input="y\n")
    assert result.exit_code == 0, result.output
    assert "수정 완료" in result.output
    assert "다음 단계" in result.output
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["live-restore"] is True and data["no-new-privileges"] is True
    assert data["icc"] is True  # RISKY는 명시하지 않으면 건드리지 않는다
    assert len(_backups(path)) == 1


def test_fix_apply_declined_changes_nothing(daemon_copy):
    path = daemon_copy()
    before = path.read_bytes()
    result = _fix("--apply", "--daemon-config", str(path), input="n\n")
    assert result.exit_code == 1
    assert "취소했습니다" in result.output
    assert path.read_bytes() == before
    assert not _backups(path)


def test_fix_risky_rule_requires_second_confirmation(daemon_copy):
    path = daemon_copy()
    before = path.read_bytes()
    result = _fix("--apply", "-r", "DAEMON-001", "--daemon-config", str(path), input="y\nn\n")
    assert result.exit_code == 1
    assert "부작용이 큰 수정" in result.output
    assert path.read_bytes() == before


def test_fix_risky_rule_applied_after_double_confirmation(daemon_copy):
    path = daemon_copy()
    result = _fix("--apply", "-r", "DAEMON-001", "--daemon-config", str(path), input="y\ny\n")
    assert result.exit_code == 0, result.output
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["icc"] is False
    assert data["live-restore"] is False  # 선택하지 않은 룰은 그대로


def test_fix_unknown_rule_id(daemon_copy):
    result = _fix("-r", "DAEMON-999", "--daemon-config", str(daemon_copy()))
    assert result.exit_code == 2
    assert "알 수 없는" in result.output


def test_fix_refuses_broken_json(daemon_copy):
    result = _fix("--daemon-config", str(daemon_copy("invalid.json")))
    assert result.exit_code == 2
    assert "수정할 수 없습니다" in result.output


def test_fix_nothing_to_do(daemon_copy):
    result = _fix("--apply", "--daemon-config", str(daemon_copy("secure.json")))
    assert result.exit_code == 0
    assert "자동으로 수정할 항목이 없습니다" in result.output


def test_fix_selected_rule_already_ok(daemon_copy):
    result = _fix("-r", "DAEMON-004", "--daemon-config", str(daemon_copy("secure.json")))
    assert result.exit_code == 0
    assert "이미 권장 상태" in result.output


def test_fix_missing_explicit_path(tmp_path):
    result = _fix("--daemon-config", str(tmp_path / "nope.json"))
    assert result.exit_code == 2
