"""룰셋(룰 끄기 · 심각도 조정) 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dockguard.cli import app
from dockguard.core.engine import ScanEngine
from dockguard.core.models import Severity, Status
from dockguard.core.ruleset import Ruleset, RulesetError, find_ruleset_file, load_ruleset
from dockguard.core.scoring import calculate_score

KNOWN = ["DAEMON-001", "DAEMON-002", "COMPOSE-006", "COMPOSE-008"]
runner = CliRunner()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestLoad:
    def test_example_file_is_valid_and_empty(self):
        from dockguard.core.rule import registered_rule_classes
        from dockguard.rules import load_all_rules

        load_all_rules()
        example = Path(__file__).parent.parent / "config" / "ruleset.example.yaml"
        ruleset = load_ruleset(example, [c.id for c in registered_rule_classes()])
        assert ruleset.is_empty  # 예시는 전부 주석 처리되어 있다

    def test_disabled_and_severity(self, tmp_path):
        path = _write(tmp_path / "r.yaml", "disabled: [compose-006]\nseverity:\n  COMPOSE-008: LOW\n")
        ruleset = load_ruleset(path, KNOWN)
        assert ruleset.disabled == {"COMPOSE-006"}
        assert ruleset.severity == {"COMPOSE-008": Severity.LOW}
        assert ruleset.summary() == "비활성 COMPOSE-006 · 심각도 조정 COMPOSE-008→LOW"

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("disabled: [DAEMON-999]\n", "등록되지 않은 룰 ID: DAEMON-999"),
            ("severity: {DAEMON-001: urgent}\n", "알 수 없는 심각도 'urgent'"),
            ("disable: [DAEMON-001]\n", "알 수 없는 키: disable"),
            ("disabled: DAEMON-001\n", "룰 ID 목록"),
            ("severity: [DAEMON-001]\n", "매핑"),
            ("- a\n", "최상위"),
            ("disabled: [\n", "YAML 문법 오류"),
        ],
    )
    def test_invalid_files(self, tmp_path, text, message):
        with pytest.raises(RulesetError, match=message.replace("[", r"\[")):
            load_ruleset(_write(tmp_path / "r.yaml", text), KNOWN)

    def test_empty_file_is_allowed(self, tmp_path):
        assert load_ruleset(_write(tmp_path / "r.yaml", ""), KNOWN).is_empty

    def test_unreadable(self, tmp_path):
        with pytest.raises(RulesetError, match="읽을 수 없습니다"):
            load_ruleset(tmp_path / "nope.yaml", KNOWN)

    def test_find_order(self, tmp_path):
        system = tmp_path / "etc" / "ruleset.yaml"
        project = tmp_path / "p"
        project.mkdir()
        assert find_ruleset_file(project, system_file=system) is None
        _write(system, "")
        assert find_ruleset_file(project, system_file=system) == system
        local = _write(project / "config" / "ruleset.yaml", "")
        assert find_ruleset_file(project, system_file=system) == local


class TestEngine:
    def test_disabled_rules_do_not_run(self, daemon_context):
        engine = ScanEngine(categories={"daemon"}, ruleset=Ruleset(disabled={"DAEMON-001"}))
        assert "DAEMON-001" not in {r.id for r in engine.rules}
        assert [r.id for r in engine.disabled_rules] == ["DAEMON-001"]
        result = engine.run(daemon_context("insecure.json"))
        assert "DAEMON-001" not in {f.rule_id for f in result.findings}

    def test_severity_override_changes_score(self, daemon_context):
        context = daemon_context("insecure.json")
        base = ScanEngine(categories={"daemon"}).run(context)
        tuned = ScanEngine(categories={"daemon"}, ruleset=Ruleset(severity={"DAEMON-002": Severity.INFO})).run(context)
        nnp = next(f for f in tuned.findings if f.rule_id == "DAEMON-002")
        assert nnp.severity == Severity.INFO and nnp.status == Status.FAIL
        assert calculate_score(tuned.findings).deducted == calculate_score(base.findings).deducted - 20


class TestCli:
    def test_ruleset_is_applied_and_reported(self, tmp_path, daemon_fixture):
        ruleset = _write(tmp_path / "ruleset.yaml", "disabled: [DAEMON-001]\n")
        out = tmp_path / "r.json"
        result = runner.invoke(
            app,
            ["scan", "-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "--ruleset", str(ruleset), "-o", str(out)],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "DAEMON-001" not in {f["rule_id"] for f in data["findings"]}
        assert data["sources"]["ruleset"]["summary"] == "비활성 DAEMON-001"
        assert any("룰셋 적용" in n for n in data["notices"])  # 끈 룰이 리포트에 드러난다

    def test_auto_detected_in_current_directory(self, tmp_path, monkeypatch, daemon_fixture):
        _write(tmp_path / "config" / "ruleset.yaml", "severity: {DAEMON-004: high}\n")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scan", "-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json"))], env={"COLUMNS": "160"})
        assert result.exit_code == 0, result.output
        assert "룰셋 적용" in result.output

    def test_invalid_ruleset_stops_scan(self, tmp_path, daemon_fixture):
        ruleset = _write(tmp_path / "ruleset.yaml", "disabled: [NOPE-1]\n")
        result = runner.invoke(
            app, ["scan", "-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "--ruleset", str(ruleset)]
        )
        assert result.exit_code == 2
        assert "룰셋 파일 오류" in result.output
