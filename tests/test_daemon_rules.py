"""daemon.json 룰 테스트 (DAEMON-001, 002, 004)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dockguard.core.context import DaemonConfig
from dockguard.core.models import Category, Severity, Status
from dockguard.rules.daemon.icc import IccRule
from dockguard.rules.daemon.live_restore import LiveRestoreRule
from dockguard.rules.daemon.no_new_privileges import NoNewPrivilegesRule

ALL_DAEMON_RULES = [IccRule, NoNewPrivilegesRule, LiveRestoreRule]


def _single(rule, context):
    findings = rule.check(context)
    assert len(findings) == 1
    return findings[0]


# --------------------------------------------------------------------- 공통 동작


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_secure_config_passes(rule_cls, daemon_context):
    finding = _single(rule_cls(), daemon_context("secure.json"))
    assert finding.status == Status.PASS


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_insecure_config_fails(rule_cls, daemon_context):
    finding = _single(rule_cls(), daemon_context("insecure.json"))
    assert finding.status == Status.FAIL
    assert finding.recommended.startswith(f'"{rule_cls.key}"')


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_missing_file_uses_docker_defaults(rule_cls, missing_daemon_context):
    """daemon.json이 없어도 '안전'이 아니다 — Docker 기본값은 세 항목 모두 취약하다."""
    finding = _single(rule_cls(), missing_daemon_context)
    assert finding.status == Status.FAIL
    assert "Docker 기본값" in finding.current_value
    assert "파일 없음" in finding.target


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_empty_object_uses_docker_defaults(rule_cls, daemon_context):
    finding = _single(rule_cls(), daemon_context("empty_object.json"))
    assert finding.status == Status.FAIL
    assert finding.current_value.startswith("미설정")


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_invalid_json_is_skipped(rule_cls, daemon_context):
    finding = _single(rule_cls(), daemon_context("invalid.json"))
    assert finding.status == Status.SKIP
    assert "JSON 파싱 실패" in finding.current_value


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_non_boolean_value_warns(rule_cls, daemon_context):
    """"false"(문자열)처럼 잘못된 타입은 dockerd 기동 실패 위험이 있어 WARN."""
    finding = _single(rule_cls(), daemon_context("wrong_types.json"))
    assert finding.status == Status.WARN
    assert "불리언이 아님" in finding.current_value


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_daemon_not_collected_is_skipped(rule_cls, context_factory):
    finding = _single(rule_cls(), context_factory(daemon=None))
    assert finding.status == Status.SKIP


@pytest.mark.parametrize("rule_cls", ALL_DAEMON_RULES)
def test_finding_metadata_is_complete(rule_cls, daemon_context):
    """교육용 필드(why / how_to_fix / tradeoff / reference)는 반드시 채워져 있어야 한다."""
    finding = _single(rule_cls(), daemon_context("insecure.json"))
    assert finding.rule_id == rule_cls.id
    assert finding.category == Category.DAEMON.value
    assert finding.title
    assert len(finding.why) > 100
    assert len(finding.how_to_fix) > 50
    assert len(finding.tradeoff) > 100
    assert finding.reference.startswith("CIS Docker Benchmark")
    assert finding.learn_more.startswith("https://")


# --------------------------------------------------------------------- 룰별 세부


def _context_with(context_factory, data: dict):
    return context_factory(DaemonConfig(path=Path("/etc/docker/daemon.json"), exists=True, data=data))


class TestIcc:
    def test_icc_false_passes(self, context_factory):
        finding = _single(IccRule(), _context_with(context_factory, {"icc": False}))
        assert finding.status == Status.PASS
        assert finding.current_value == "false"

    def test_icc_true_fails(self, context_factory):
        finding = _single(IccRule(), _context_with(context_factory, {"icc": True}))
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.MEDIUM
        assert finding.recommended == '"icc": false'

    def test_tradeoff_warns_about_service_connectivity(self, context_factory):
        """dockguard의 핵심 가치: icc:false의 통신 단절 부작용을 반드시 알려야 한다."""
        finding = _single(IccRule(), _context_with(context_factory, {}))
        assert "커스텀 네트워크" in finding.tradeoff
        assert "통신" in finding.tradeoff


class TestNoNewPrivileges:
    def test_enabled_passes(self, context_factory):
        finding = _single(NoNewPrivilegesRule(), _context_with(context_factory, {"no-new-privileges": True}))
        assert finding.status == Status.PASS

    def test_unset_fails_with_high_severity(self, context_factory):
        finding = _single(NoNewPrivilegesRule(), _context_with(context_factory, {"icc": False}))
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.HIGH
        assert finding.current_value == "미설정 (Docker 기본값 false)"


class TestLiveRestore:
    def test_enabled_passes(self, context_factory):
        finding = _single(LiveRestoreRule(), _context_with(context_factory, {"live-restore": True}))
        assert finding.status == Status.PASS

    def test_disabled_fails_with_low_severity(self, context_factory):
        finding = _single(LiveRestoreRule(), _context_with(context_factory, {"live-restore": False}))
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.LOW

    def test_tradeoff_mentions_host_reboot(self, context_factory):
        """정전(호스트 재부팅)에는 live-restore가 무력하다는 점을 알려야 한다."""
        finding = _single(LiveRestoreRule(), _context_with(context_factory, {}))
        assert "재부팅" in finding.tradeoff
