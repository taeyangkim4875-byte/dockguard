"""daemon.json 안전 수정기 테스트 — 백업 · dry-run · 검증 · 롤백."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from dockguard.core.collector import load_daemon_config
from dockguard.core.context import DaemonConfig
from dockguard.core.engine import ScanEngine
from dockguard.core.models import ApplyMethod, ConfigPatch, FixRisk
from dockguard.remediators import daemon_remediator as rem
from dockguard.remediators.daemon_remediator import (
    ApplyResult,
    RemediationError,
    RemediationPlan,
    apply_plan,
    build_plan,
    dump_json,
    next_steps,
    validate_with_dockerd,
)

FIXED_NOW = datetime(2026, 9, 15, 10, 30, 0)


def ok_validator(path: Path):
    return True, "검증 통과(테스트)"


@pytest.fixture
def daemon_file(tmp_path: Path, daemon_fixture):
    """fixture daemon.json을 tmp로 복사해 경로를 돌려준다 (원본 fixture는 건드리지 않음)."""

    def _copy(name: str = "insecure.json") -> Path:
        target = tmp_path / "daemon.json"
        shutil.copy(daemon_fixture(name), target)
        return target

    return _copy


def _plan_for(path: Path, context_factory, selected=None) -> RemediationPlan:
    context = context_factory(load_daemon_config(path))
    engine = ScanEngine(categories={"daemon"})
    result = engine.run(context)
    return build_plan(context, result.findings, engine.rules, selected)


# ============================================================================ 계획 (dry-run)


class TestBuildPlan:
    def test_default_plan_includes_only_safe_fixes(self, daemon_file, context_factory):
        plan = _plan_for(daemon_file(), context_factory)
        assert {p.rule_id for p in plan.patches} == {"DAEMON-002", "DAEMON-004", "DAEMON-005"}
        assert all(p.risk == FixRisk.SAFE for p in plan.patches)

    def test_risky_fix_is_skipped_with_hint(self, daemon_file, context_factory):
        plan = _plan_for(daemon_file(), context_factory)
        icc = next(s for s in plan.skipped if s.finding.rule_id == "DAEMON-001")
        assert "--rule DAEMON-001" in icc.reason

    def test_non_fixable_rules_are_listed_with_reason(self, daemon_file, context_factory):
        plan = _plan_for(daemon_file(), context_factory)
        skipped = {s.finding.rule_id: s.reason for s in plan.skipped}
        for rule_id in ("DAEMON-003", "DAEMON-006", "DAEMON-008", "DAEMON-009", "DAEMON-010"):
            assert skipped[rule_id]
        assert "데이터 디렉터리" in skipped["DAEMON-006"]

    def test_explicit_selection_includes_risky_fix(self, daemon_file, context_factory):
        plan = _plan_for(daemon_file(), context_factory, selected=["daemon-001"])  # 소문자도 허용
        assert [p.rule_id for p in plan.patches] == ["DAEMON-001"]
        assert plan.risky_patches and plan.after["icc"] is False

    def test_plan_preserves_unrelated_keys_and_order(self, daemon_file, context_factory):
        path = daemon_file()
        original = json.loads(path.read_text(encoding="utf-8"))
        plan = _plan_for(path, context_factory)
        assert list(plan.after)[: len(original)] == list(original)  # 기존 키 순서 유지
        assert plan.after["insecure-registries"] == original["insecure-registries"]
        assert plan.after["seccomp-profile"] == "unconfined"  # 자동 수정 대상 아님 → 그대로

    def test_diff_shows_only_real_changes(self, daemon_file, context_factory):
        diff = _plan_for(daemon_file(), context_factory).diff()
        assert '-  "live-restore": false,' in diff
        assert '+  "live-restore": true,' in diff
        assert '+  "log-opts": {' in diff
        changed = [line for line in diff.splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---"))]
        assert not any("insecure-registries" in line for line in changed)

    def test_building_plan_does_not_touch_file(self, daemon_file, context_factory):
        path = daemon_file()
        before = path.read_bytes()
        _plan_for(path, context_factory).diff()
        assert path.read_bytes() == before
        assert list(path.parent.iterdir()) == [path]

    def test_refuses_unparseable_file(self, daemon_file, context_factory):
        with pytest.raises(RemediationError, match="안전하게 수정할 수 없습니다"):
            _plan_for(daemon_file("invalid.json"), context_factory)

    def test_refuses_when_daemon_not_collected(self, context_factory):
        with pytest.raises(RemediationError):
            build_plan(context_factory(daemon=None), [], [])

    def test_secure_config_has_nothing_to_fix(self, daemon_file, context_factory):
        plan = _plan_for(daemon_file("secure.json"), context_factory)
        assert not plan.has_changes
        assert plan.apply_with is None

    def test_apply_method_aggregation(self, tmp_path):
        daemon = DaemonConfig(path=tmp_path / "d.json", exists=False)
        reload_only = RemediationPlan(daemon=daemon, fixes=[_fix("A", ApplyMethod.RELOAD)])
        mixed = RemediationPlan(daemon=daemon, fixes=[_fix("A", ApplyMethod.RELOAD), _fix("B", ApplyMethod.RESTART)])
        assert reload_only.apply_with == ApplyMethod.RELOAD
        assert mixed.apply_with == ApplyMethod.RESTART


def _fix(rule_id: str, apply_with: ApplyMethod, **patch_kwargs):
    from dockguard.core.models import Finding, Severity, Status

    finding = Finding(
        rule_id=rule_id,
        title=rule_id,
        category="daemon",
        severity=Severity.LOW,
        status=Status.FAIL,
        target="t",
        current_value="",
        recommended="",
        why="",
        how_to_fix="",
    )
    patch = ConfigPatch(rule_id=rule_id, summary=rule_id, set_values={rule_id: True}, apply_with=apply_with, **patch_kwargs)
    return rem.PlannedFix(finding, patch)


# ============================================================================ 적용


class TestApplyPlan:
    def test_apply_writes_file_and_backup(self, daemon_file, context_factory):
        path = daemon_file()
        original = path.read_text(encoding="utf-8")
        plan = _plan_for(path, context_factory)

        result = apply_plan(plan, validator=ok_validator, now=FIXED_NOW)

        assert result.backup_path == path.with_name("daemon.json.bak.20260915-103000")
        assert result.backup_path.read_text(encoding="utf-8") == original  # 백업 = 원본
        assert json.loads(path.read_text(encoding="utf-8")) == plan.after
        assert result.validation == "검증 통과(테스트)"
        assert not list(path.parent.glob("*.tmp"))  # 임시 파일 정리

    def test_rescan_after_apply_passes_fixed_rules(self, daemon_file, context_factory):
        path = daemon_file()
        apply_plan(_plan_for(path, context_factory), validator=ok_validator)
        context = context_factory(load_daemon_config(path))
        findings = {f.rule_id: f for f in ScanEngine(categories={"daemon"}).run(context).findings}
        for rule_id in ("DAEMON-002", "DAEMON-004", "DAEMON-005"):
            assert not findings[rule_id].is_problem

    def test_apply_creates_new_file_without_backup(self, tmp_path, context_factory):
        path = tmp_path / "docker" / "daemon.json"
        plan = _plan_for(path, context_factory)
        result = apply_plan(plan, validator=ok_validator)
        assert result.backup_path is None
        assert json.loads(path.read_text(encoding="utf-8")) == plan.after

    def test_no_changes_is_rejected(self, daemon_file, context_factory):
        with pytest.raises(RemediationError, match="변경 사항이 없습니다"):
            apply_plan(_plan_for(daemon_file("secure.json"), context_factory), validator=ok_validator)

    def test_validation_failure_leaves_original_untouched(self, daemon_file, context_factory):
        path = daemon_file()
        before = path.read_bytes()
        plan = _plan_for(path, context_factory)

        with pytest.raises(RemediationError, match="원본은 변경되지 않았습니다"):
            apply_plan(plan, validator=lambda p: (False, "unknown option: bogus"))

        assert path.read_bytes() == before
        assert list(path.parent.iterdir()) == [path]  # 백업도 임시 파일도 남지 않음

    def test_validator_unavailable_still_applies(self, daemon_file, context_factory):
        path = daemon_file()
        result = apply_plan(_plan_for(path, context_factory), validator=lambda p: (None, "dockerd 없음"))
        assert result.validation == "dockerd 없음"

    def test_post_write_verification_failure_rolls_back(self, daemon_file, context_factory, monkeypatch):
        path = daemon_file()
        before = path.read_text(encoding="utf-8")
        plan = _plan_for(path, context_factory)
        broken = DaemonConfig(path=path, exists=True, error="다시 읽기 실패(테스트)")
        monkeypatch.setattr(rem, "load_daemon_config", lambda p: broken)

        with pytest.raises(RemediationError, match="원본으로 복원"):
            apply_plan(plan, validator=ok_validator)
        assert path.read_text(encoding="utf-8") == before

    def test_post_write_failure_on_new_file_removes_it(self, tmp_path, context_factory, monkeypatch):
        path = tmp_path / "daemon.json"
        plan = _plan_for(path, context_factory)
        monkeypatch.setattr(rem, "load_daemon_config", lambda p: DaemonConfig(path=p, exists=True, error="x"))
        with pytest.raises(RemediationError):
            apply_plan(plan, validator=ok_validator)
        assert not path.exists()

    def test_permission_error_is_friendly(self, daemon_file, context_factory, monkeypatch):
        path = daemon_file()
        plan = _plan_for(path, context_factory)

        def deny(*args, **kwargs):
            raise PermissionError(13, "denied", str(path))

        monkeypatch.setattr(Path, "write_text", deny)
        with pytest.raises(RemediationError, match="sudo"):
            apply_plan(plan, validator=ok_validator)

    def test_backup_never_overwrites_existing_backup(self, tmp_path):
        path = tmp_path / "daemon.json"
        first = rem._backup_path(path, FIXED_NOW)
        first.write_text("old backup", encoding="utf-8")
        second = rem._backup_path(path, FIXED_NOW)
        assert second != first
        assert second.name.startswith(first.name)


# ============================================================================ 직렬화


class TestSerialization:
    def test_short_scalar_arrays_stay_inline(self):
        text = dump_json({"a": ["x", "y"], "b": {"c": 1}}, 2)
        assert '"a": ["x", "y"]' in text
        assert json.loads(text) == {"a": ["x", "y"], "b": {"c": 1}}

    def test_long_or_nested_arrays_are_expanded(self):
        long_list = [f"registry-{i}.internal:5000" for i in range(6)]
        text = dump_json({"r": long_list, "n": [{"k": 1}]}, 2)
        assert '"r": [\n' in text
        assert json.loads(text) == {"r": long_list, "n": [{"k": 1}]}

    def test_empty_containers(self):
        assert dump_json({}) == "{}"
        assert json.loads(dump_json({"a": [], "b": {}})) == {"a": [], "b": {}}

    @pytest.mark.parametrize(("raw", "expected_prefix"), [('{\n    "icc": true\n}', "    "), ('{\n\t"icc": true\n}', "\t")])
    def test_original_indentation_is_preserved(self, tmp_path, context_factory, raw, expected_prefix):
        path = tmp_path / "daemon.json"
        path.write_text(raw, encoding="utf-8")
        plan = _plan_for(path, context_factory)
        assert plan.new_text().splitlines()[1].startswith(expected_prefix + '"')


# ============================================================================ dockerd 검증


class TestValidateWithDockerd:
    def test_unavailable_when_dockerd_missing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(rem.shutil, "which", lambda name: None)
        ok, message = validate_with_dockerd(tmp_path / "d.json")
        assert ok is None and "dockerd" in message

    @pytest.mark.parametrize(
        ("returncode", "output", "expected"),
        [
            (0, "configuration OK", True),
            (1, "unable to configure the Docker daemon: invalid option", False),
            (125, "unknown flag: --validate", None),
        ],
    )
    def test_result_interpretation(self, monkeypatch, tmp_path, returncode, output, expected):
        monkeypatch.setattr(rem.shutil, "which", lambda name: "/usr/bin/dockerd")
        monkeypatch.setattr(
            rem.subprocess,
            "run",
            lambda *a, **k: subprocess.CompletedProcess(a[0], returncode, stdout="", stderr=output),
        )
        ok, _ = validate_with_dockerd(tmp_path / "d.json")
        assert ok is expected

    def test_timeout_is_treated_as_unavailable(self, monkeypatch, tmp_path):
        monkeypatch.setattr(rem.shutil, "which", lambda name: "/usr/bin/dockerd")

        def timeout(*a, **k):
            raise subprocess.TimeoutExpired(cmd="dockerd", timeout=15)

        monkeypatch.setattr(rem.subprocess, "run", timeout)
        assert validate_with_dockerd(tmp_path / "d.json")[0] is None


# ============================================================================ 다음 단계 안내


class TestNextSteps:
    def _plan(self, tmp_path, fixes, before=None, after=None):
        daemon = DaemonConfig(path=tmp_path / "daemon.json", exists=True, data=before or {})
        return RemediationPlan(daemon=daemon, fixes=fixes, after=after or {})

    def _result(self, tmp_path, backup=True):
        path = tmp_path / "daemon.json"
        return ApplyResult(path=path, backup_path=path.with_name("daemon.json.bak.x") if backup else None, validation="")

    def _commands(self, steps):
        return [s.command for s in steps]

    def test_reload_only(self, tmp_path):
        plan = self._plan(tmp_path, [_fix("A", ApplyMethod.RELOAD)])
        steps = next_steps(plan, self._result(tmp_path), platform="linux")
        assert steps[0].command == "sudo systemctl reload docker"
        assert "sudo systemctl restart docker" not in self._commands(steps)

    def test_restart_without_live_restore_warns(self, tmp_path):
        plan = self._plan(tmp_path, [_fix("A", ApplyMethod.RESTART)])
        steps = next_steps(plan, self._result(tmp_path), platform="linux")
        assert steps[0].command == "sudo systemctl restart docker"
        assert steps[0].warning and "모든 컨테이너" in steps[0].description

    def test_newly_enabled_live_restore_reloads_before_restart(self, tmp_path):
        """live-restore를 먼저 리로드로 켜면 이후 재시작에서 컨테이너가 유지된다."""
        plan = self._plan(tmp_path, [_fix("A", ApplyMethod.RESTART)], after={"live-restore": True})
        commands = self._commands(next_steps(plan, self._result(tmp_path), platform="linux"))
        assert commands[:2] == ["sudo systemctl reload docker", "sudo systemctl restart docker"]

    def test_existing_live_restore_just_restarts(self, tmp_path):
        plan = self._plan(
            tmp_path, [_fix("A", ApplyMethod.RESTART)], before={"live-restore": True}, after={"live-restore": True}
        )
        steps = next_steps(plan, self._result(tmp_path), platform="linux")
        assert steps[0].command == "sudo systemctl restart docker" and not steps[0].warning

    def test_recreate_hint_and_rollback(self, tmp_path):
        plan = self._plan(tmp_path, [_fix("A", ApplyMethod.RESTART, requires_recreate=True)])
        commands = self._commands(next_steps(plan, self._result(tmp_path), platform="linux"))
        assert "docker compose up -d --force-recreate" in commands
        assert any(c.startswith("sudo cp ") and "daemon.json.bak.x" in c for c in commands)

    def test_rollback_for_new_file_removes_it(self, tmp_path):
        plan = self._plan(tmp_path, [_fix("A", ApplyMethod.RELOAD)])
        commands = self._commands(next_steps(plan, self._result(tmp_path, backup=False), platform="linux"))
        assert any(c.startswith("sudo rm ") for c in commands)

    def test_docker_desktop_platform(self, tmp_path):
        plan = self._plan(tmp_path, [_fix("A", ApplyMethod.RESTART)])
        steps = next_steps(plan, self._result(tmp_path), platform="win32")
        assert "Docker Desktop" in steps[0].description
        assert not any("systemctl" in s.command for s in steps)
