"""daemon.json 룰 테스트 (DAEMON-001 ~ 010)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dockguard.core.context import DaemonConfig, FileStat
from dockguard.core.models import ApplyMethod, Category, FixRisk, Severity, Status
from dockguard.rules.daemon.file_permissions import DaemonFilePermissionsRule
from dockguard.rules.daemon.icc import IccRule
from dockguard.rules.daemon.insecure_registry import InsecureRegistryRule, is_loopback_registry
from dockguard.rules.daemon.iptables import IptablesRule
from dockguard.rules.daemon.live_restore import LiveRestoreRule
from dockguard.rules.daemon.log_limit import LogLimitRule
from dockguard.rules.daemon.no_new_privileges import NoNewPrivilegesRule
from dockguard.rules.daemon.seccomp import SeccompProfileRule
from dockguard.rules.daemon.userland_proxy import UserlandProxyRule
from dockguard.rules.daemon.userns_remap import UsernsRemapRule

# 파일 '내용'을 보는 룰 (DAEMON-007은 파일 권한을 보므로 따로 테스트)
CONTENT_RULES = [
    IccRule,
    NoNewPrivilegesRule,
    UserlandProxyRule,
    LiveRestoreRule,
    LogLimitRule,
    UsernsRemapRule,
    SeccompProfileRule,
    IptablesRule,
    InsecureRegistryRule,
]
ALL_RULES = CONTENT_RULES + [DaemonFilePermissionsRule]
SYSTEM_PATH = Path("/etc/docker/daemon.json")


def _single(rule, context):
    findings = rule.check(context)
    assert len(findings) == 1
    return findings[0]


def _ctx(context_factory, data: dict | None = None, **kwargs):
    """시스템 경로(/etc/docker/daemon.json)에 있는 daemon.json 컨텍스트."""
    daemon = DaemonConfig(path=kwargs.pop("path", SYSTEM_PATH), exists=kwargs.pop("exists", True), data=data or {}, **kwargs)
    return context_factory(daemon)


# ============================================================================ 공통 동작


@pytest.mark.parametrize("rule_cls", CONTENT_RULES)
def test_secure_config_passes(rule_cls, daemon_context):
    assert _single(rule_cls(), daemon_context("secure.json")).status == Status.PASS


@pytest.mark.parametrize("rule_cls", CONTENT_RULES)
def test_insecure_config_fails(rule_cls, daemon_context):
    assert _single(rule_cls(), daemon_context("insecure.json")).status == Status.FAIL


# daemon.json이 없을 때 = Docker 기본값. 파일이 없다고 안전한 게 아니다.
MISSING_FILE_EXPECTED = {
    IccRule: Status.FAIL,  # 기본 icc=true
    NoNewPrivilegesRule: Status.FAIL,  # 기본 false
    UserlandProxyRule: Status.FAIL,  # 기본 true
    LiveRestoreRule: Status.FAIL,  # 기본 false
    LogLimitRule: Status.FAIL,  # 기본 json-file, 크기 제한 없음
    UsernsRemapRule: Status.FAIL,  # 기본 미사용
    SeccompProfileRule: Status.PASS,  # 기본 프로파일 적용
    IptablesRule: Status.PASS,  # 기본 true
    InsecureRegistryRule: Status.PASS,  # 기본 없음
    DaemonFilePermissionsRule: Status.SKIP,  # 점검할 파일 없음
}


@pytest.mark.parametrize(("rule_cls", "expected"), MISSING_FILE_EXPECTED.items())
def test_missing_file_uses_docker_defaults(rule_cls, expected, missing_daemon_context):
    finding = _single(rule_cls(), missing_daemon_context)
    assert finding.status == expected
    assert "파일 없음" in finding.target


@pytest.mark.parametrize("rule_cls", CONTENT_RULES)
def test_invalid_json_is_skipped(rule_cls, daemon_context):
    finding = _single(rule_cls(), daemon_context("invalid.json"))
    assert finding.status == Status.SKIP
    assert "JSON 파싱 실패" in finding.current_value


@pytest.mark.parametrize("rule_cls", CONTENT_RULES)
def test_wrong_value_types_warn(rule_cls, daemon_context):
    """"false"(문자열)처럼 잘못된 타입은 dockerd 기동 실패 위험이 있어 WARN."""
    assert _single(rule_cls(), daemon_context("wrong_types.json")).status == Status.WARN


@pytest.mark.parametrize("rule_cls", ALL_RULES)
def test_daemon_not_collected_is_skipped(rule_cls, context_factory):
    assert _single(rule_cls(), context_factory(daemon=None)).status == Status.SKIP


@pytest.mark.parametrize("rule_cls", ALL_RULES)
def test_finding_metadata_is_complete(rule_cls, daemon_context):
    """교육용 필드(why / how_to_fix / tradeoff / reference)는 반드시 충실히 채워져 있어야 한다."""
    finding = _single(rule_cls(), daemon_context("secure.json"))
    assert finding.rule_id == rule_cls.id
    assert finding.category == Category.DAEMON.value
    assert finding.title and finding.recommended
    assert len(finding.why) > 150
    assert len(finding.how_to_fix) > 80
    assert len(finding.tradeoff) > 150
    assert finding.reference.startswith("CIS Docker Benchmark v1.6.0")
    assert finding.learn_more.startswith("https://docs.docker.com/")


@pytest.mark.parametrize("rule_cls", ALL_RULES)
def test_non_fixable_rules_explain_why(rule_cls):
    if rule_cls.fix_risk == FixRisk.NONE:
        assert rule_cls.no_autofix_reason


# ============================================================================ 불리언 룰 + 자동 수정 계획


class TestBooleanRules:
    def test_icc_false_passes(self, context_factory):
        finding = _single(IccRule(), _ctx(context_factory, {"icc": False}))
        assert finding.status == Status.PASS
        assert finding.current_value == "false"

    def test_icc_true_fails(self, context_factory):
        finding = _single(IccRule(), _ctx(context_factory, {"icc": True}))
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.MEDIUM
        assert finding.recommended == '"icc": false'

    def test_icc_tradeoff_warns_about_service_connectivity(self, context_factory):
        """dockguard의 핵심 가치: icc:false의 통신 단절 부작용을 반드시 알려야 한다."""
        finding = _single(IccRule(), _ctx(context_factory))
        assert "커스텀 네트워크" in finding.tradeoff
        assert "NET-001" in finding.tradeoff

    def test_no_new_privileges_unset_fails_high(self, context_factory):
        finding = _single(NoNewPrivilegesRule(), _ctx(context_factory, {"icc": False}))
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.HIGH
        assert finding.current_value == "미설정 (Docker 기본값 false)"

    def test_live_restore_tradeoff_mentions_host_reboot(self, context_factory):
        """정전(호스트 재부팅)에는 live-restore가 무력하다는 점을 알려야 한다."""
        assert "재부팅" in _single(LiveRestoreRule(), _ctx(context_factory)).tradeoff

    def test_userland_proxy(self, context_factory):
        assert _single(UserlandProxyRule(), _ctx(context_factory, {"userland-proxy": False})).status == Status.PASS
        assert _single(UserlandProxyRule(), _ctx(context_factory, {})).status == Status.FAIL

    def test_iptables(self, context_factory):
        assert _single(IptablesRule(), _ctx(context_factory, {"iptables": False})).status == Status.FAIL
        assert _single(IptablesRule(), _ctx(context_factory, {"iptables": True})).status == Status.PASS

    def test_iptables_explains_icc_dependency_and_ufw_bypass(self, context_factory):
        finding = _single(IptablesRule(), _ctx(context_factory))
        assert "icc" in finding.why
        assert "UFW" in finding.tradeoff

    def test_safe_rule_plans_fix_when_failing(self, context_factory):
        context = _ctx(context_factory, {"live-restore": False})
        rule = LiveRestoreRule()
        patch = rule.plan_fix(_single(rule, context), context)
        assert patch is not None
        assert patch.set_values == {"live-restore": True}
        assert patch.risk == FixRisk.SAFE
        assert patch.apply_with == ApplyMethod.RELOAD

    def test_wrong_type_is_fixable(self, context_factory):
        context = _ctx(context_factory, {"no-new-privileges": "true"})
        rule = NoNewPrivilegesRule()
        finding = _single(rule, context)
        assert finding.status == Status.WARN and finding.auto_fixable
        assert rule.plan_fix(finding, context).set_values == {"no-new-privileges": True}

    def test_no_fix_when_passing(self, context_factory):
        context = _ctx(context_factory, {"live-restore": True})
        rule = LiveRestoreRule()
        finding = _single(rule, context)
        assert not finding.auto_fixable
        assert rule.plan_fix(finding, context) is None

    def test_icc_fix_is_risky(self, context_factory):
        context = _ctx(context_factory, {"icc": True})
        rule = IccRule()
        patch = rule.plan_fix(_single(rule, context), context)
        assert patch.risk == FixRisk.RISKY
        assert "커스텀 네트워크" in patch.note

    def test_non_fixable_rule_plans_nothing(self, context_factory):
        context = _ctx(context_factory, {})
        rule = UserlandProxyRule()
        finding = _single(rule, context)
        assert finding.status == Status.FAIL and not finding.auto_fixable
        assert rule.plan_fix(finding, context) is None


# ============================================================================ DAEMON-005 로그


class TestLogLimit:
    @pytest.mark.parametrize(
        ("data", "status"),
        [
            ({}, Status.FAIL),
            ({"log-driver": "json-file"}, Status.FAIL),
            ({"log-opts": {"max-file": "5"}}, Status.FAIL),  # max-file만으로는 제한 안 됨
            ({"log-opts": {"max-size": "50m"}}, Status.PASS),
            ({"log-driver": "local"}, Status.PASS),
            ({"log-driver": "journald"}, Status.PASS),
            ({"log-driver": "fluentd", "log-opts": {"fluentd-address": "x:24224"}}, Status.PASS),
            ({"log-driver": "none"}, Status.WARN),
            ({"log-driver": 1}, Status.WARN),
        ],
    )
    def test_evaluation(self, context_factory, data, status):
        assert _single(LogLimitRule(), _ctx(context_factory, data)).status == status

    def test_fix_adds_driver_and_rotation_when_unset(self, context_factory):
        context = _ctx(context_factory, {})
        rule = LogLimitRule()
        patch = rule.plan_fix(_single(rule, context), context)
        assert patch.set_values == {"log-driver": "json-file", "log-opts": {"max-file": "3", "max-size": "10m"}}
        assert patch.requires_recreate

    def test_fix_preserves_existing_log_opts(self, context_factory):
        context = _ctx(context_factory, {"log-driver": "json-file", "log-opts": {"max-file": "7", "labels": "app"}})
        rule = LogLimitRule()
        patch = rule.plan_fix(_single(rule, context), context)
        assert "log-driver" not in patch.set_values
        assert patch.set_values["log-opts"] == {"max-file": "7", "labels": "app", "max-size": "10m"}

    def test_no_fix_for_warn(self, context_factory):
        context = _ctx(context_factory, {"log-driver": "none"})
        rule = LogLimitRule()
        assert rule.plan_fix(_single(rule, context), context) is None


# ============================================================================ DAEMON-006 userns-remap


class TestUsernsRemap:
    @pytest.mark.parametrize("value", ["default", "dockremap", "testuser:testgroup"])
    def test_configured_passes(self, context_factory, value):
        assert _single(UsernsRemapRule(), _ctx(context_factory, {"userns-remap": value})).status == Status.PASS

    def test_empty_string_fails(self, context_factory):
        finding = _single(UsernsRemapRule(), _ctx(context_factory, {"userns-remap": ""}))
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.HIGH

    def test_rootless_mode_passes(self, context_factory):
        finding = _single(UsernsRemapRule(), _ctx(context_factory, {}, rootless=True))
        assert finding.status == Status.PASS
        assert "rootless" in finding.current_value

    def test_not_auto_fixable_and_warns_about_data_dir(self, context_factory):
        rule = UsernsRemapRule()
        context = _ctx(context_factory, {})
        finding = _single(rule, context)
        assert rule.plan_fix(finding, context) is None
        assert "데이터 디렉터리" in finding.tradeoff


# ============================================================================ DAEMON-007 파일 권한


class TestFilePermissions:
    @pytest.mark.parametrize(
        ("mode", "uid", "gid", "status", "problem"),
        [
            (0o644, 0, 0, Status.PASS, None),
            (0o600, 0, 0, Status.PASS, None),
            (0o664, 0, 0, Status.FAIL, "쓰기 가능"),
            (0o666, 0, 0, Status.FAIL, "쓰기 가능"),
            (0o755, 0, 0, Status.FAIL, "넓은 권한"),
            (0o644, 1000, 1000, Status.FAIL, "root:root"),
            (0o644, 0, 999, Status.FAIL, "root:root"),
        ],
    )
    def test_system_file(self, context_factory, mode, uid, gid, status, problem):
        context = _ctx(context_factory, {}, stat=FileStat(mode=mode, uid=uid, gid=gid))
        finding = _single(DaemonFilePermissionsRule(), context)
        assert finding.status == status
        assert f"{mode:04o}" in finding.current_value
        if problem:
            assert problem in finding.current_value

    def test_user_scoped_file_skips_owner_check(self, context_factory):
        """rootless/Docker Desktop 설정 파일은 사용자 소유가 정상이다."""
        context = _ctx(context_factory, {}, rootless=True, stat=FileStat(mode=0o644, uid=1000, gid=1000))
        assert _single(DaemonFilePermissionsRule(), context).status == Status.PASS

    def test_user_scoped_file_still_checks_write_bits(self, context_factory):
        context = _ctx(context_factory, {}, rootless=True, stat=FileStat(mode=0o666, uid=1000, gid=1000))
        assert _single(DaemonFilePermissionsRule(), context).status == Status.FAIL

    def test_file_under_home_is_user_scoped(self, context_factory):
        path = Path.home() / ".docker" / "daemon.json"
        context = _ctx(context_factory, {}, path=path, stat=FileStat(mode=0o644, uid=1000, gid=1000))
        assert _single(DaemonFilePermissionsRule(), context).status == Status.PASS

    def test_no_stat_is_skipped(self, context_factory):
        finding = _single(DaemonFilePermissionsRule(), _ctx(context_factory, {}, stat=None))
        assert finding.status == Status.SKIP
        assert "Windows" in finding.current_value

    def test_checked_even_when_json_is_broken(self, context_factory):
        """내용이 깨져 있어도 권한은 점검할 수 있다."""
        context = _ctx(context_factory, {}, error="JSON 파싱 실패", stat=FileStat(mode=0o666, uid=0, gid=0))
        assert _single(DaemonFilePermissionsRule(), context).status == Status.FAIL


# ============================================================================ DAEMON-008 seccomp


class TestSeccomp:
    @pytest.mark.parametrize("value", ["unconfined", "Unconfined"])
    def test_unconfined_fails(self, context_factory, value):
        finding = _single(SeccompProfileRule(), _ctx(context_factory, {"seccomp-profile": value}))
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.HIGH

    @pytest.mark.parametrize("data", [{}, {"seccomp-profile": ""}, {"seccomp-profile": "builtin"}])
    def test_default_profile_passes(self, context_factory, data):
        assert _single(SeccompProfileRule(), _ctx(context_factory, data)).status == Status.PASS

    def test_existing_custom_profile_passes(self, context_factory, tmp_path):
        profile = tmp_path / "seccomp.json"
        profile.write_text("{}", encoding="utf-8")
        finding = _single(SeccompProfileRule(), _ctx(context_factory, {"seccomp-profile": str(profile)}))
        assert finding.status == Status.PASS
        assert "커스텀" in finding.current_value

    def test_missing_custom_profile_warns(self, context_factory, tmp_path):
        missing = tmp_path / "nope.json"
        finding = _single(SeccompProfileRule(), _ctx(context_factory, {"seccomp-profile": str(missing)}))
        assert finding.status == Status.WARN
        assert "기동 실패" in finding.current_value


# ============================================================================ DAEMON-010 insecure registry


class TestInsecureRegistry:
    def test_external_registry_fails_and_lists_it(self, context_factory):
        finding = _single(InsecureRegistryRule(), _ctx(context_factory, {"insecure-registries": ["10.0.0.5:5000"]}))
        assert finding.status == Status.FAIL
        assert "10.0.0.5:5000" in finding.current_value

    def test_loopback_only_passes(self, context_factory):
        data = {"insecure-registries": ["localhost:5000", "127.0.0.0/8"]}
        finding = _single(InsecureRegistryRule(), _ctx(context_factory, data))
        assert finding.status == Status.PASS
        assert "루프백" in finding.current_value

    def test_http_mirror_fails(self, context_factory):
        finding = _single(InsecureRegistryRule(), _ctx(context_factory, {"registry-mirrors": ["http://mirror:5000"]}))
        assert finding.status == Status.FAIL
        assert "HTTP 미러" in finding.current_value

    def test_https_mirror_passes(self, context_factory):
        data = {"registry-mirrors": ["https://mirror.gcr.io"]}
        assert _single(InsecureRegistryRule(), _ctx(context_factory, data)).status == Status.PASS

    @pytest.mark.parametrize(
        ("entry", "expected"),
        [
            ("localhost:5000", True),
            ("localhost", True),
            ("127.0.0.1:5000", True),
            ("127.0.0.0/8", True),
            ("[::1]:5000", True),
            ("::1", True),
            ("http://localhost:5000", True),
            ("10.0.0.5:5000", False),
            ("10.0.0.0/8", False),
            ("registry.internal", False),
            ("registry.internal:5000", False),
            ("localhost.evil.com:5000", False),
        ],
    )
    def test_is_loopback_registry(self, entry, expected):
        assert is_loopback_registry(entry) is expected
