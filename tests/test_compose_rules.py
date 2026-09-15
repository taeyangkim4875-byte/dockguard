"""docker-compose 룰 테스트 (COMPOSE-001 ~ 012)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dockguard.core.context import ComposeProject, DaemonConfig
from dockguard.core.models import Category, FixRisk, Severity, Status
from dockguard.knowledge.compose_facts import is_secret_name
from dockguard.rules.compose._base import parse_image, parse_port, parse_volume, service_environment
from dockguard.rules.compose.capabilities import DangerousCapabilitiesRule, normalize_capability
from dockguard.rules.compose.docker_socket import DockerSocketMountRule
from dockguard.rules.compose.host_namespaces import HostNamespacesRule
from dockguard.rules.compose.host_network import HostNetworkRule
from dockguard.rules.compose.image_tag import ImageTagRule
from dockguard.rules.compose.no_new_privileges import ComposeNoNewPrivilegesRule, no_new_privileges_setting
from dockguard.rules.compose.non_root_user import NonRootUserRule, dockerfile_user, is_root_user
from dockguard.rules.compose.plaintext_secrets import PlaintextSecretsRule
from dockguard.rules.compose.privileged import PrivilegedRule
from dockguard.rules.compose.privileged_ports import PrivilegedPortsRule
from dockguard.rules.compose.read_only import ReadOnlyRootFsRule
from dockguard.rules.compose.resource_limits import ResourceLimitsRule

ALL_COMPOSE_RULES = [
    PrivilegedRule,
    NonRootUserRule,
    ComposeNoNewPrivilegesRule,
    DockerSocketMountRule,
    PlaintextSecretsRule,
    ReadOnlyRootFsRule,
    ResourceLimitsRule,
    HostNetworkRule,
    HostNamespacesRule,
    DangerousCapabilitiesRule,
    ImageTagRule,
    PrivilegedPortsRule,
]

INSECURE_EXPECTED = {
    PrivilegedRule: Status.FAIL,
    NonRootUserRule: Status.FAIL,
    ComposeNoNewPrivilegesRule: Status.FAIL,
    DockerSocketMountRule: Status.FAIL,
    PlaintextSecretsRule: Status.FAIL,
    ReadOnlyRootFsRule: Status.FAIL,
    ResourceLimitsRule: Status.FAIL,
    HostNetworkRule: Status.WARN,  # 정당한 사용처가 많아 '검토' 수준
    HostNamespacesRule: Status.FAIL,
    DangerousCapabilitiesRule: Status.FAIL,
    ImageTagRule: Status.FAIL,
    PrivilegedPortsRule: Status.WARN,  # 검토 항목
}


def _single(rule, context):
    findings = rule.check(context)
    assert len(findings) == 1
    return findings[0]


def _run(rule_cls, context_factory, services: dict, daemon: dict | None = None):
    """서비스 정의(dict)로 프로젝트를 만들어 룰을 실행한다."""
    project = ComposeProject(path=Path("docker-compose.yml"), services=services)
    daemon_cfg = DaemonConfig(path=Path("/etc/docker/daemon.json"), exists=True, data=daemon) if daemon is not None else None
    return _single(rule_cls(), context_factory(daemon_cfg, compose=[project]))


# ============================================================================ 공통 동작


@pytest.mark.parametrize("rule_cls", ALL_COMPOSE_RULES)
def test_secure_compose_passes(rule_cls, compose_context):
    finding = _single(rule_cls(), compose_context("secure.yml"))
    assert finding.status == Status.PASS, finding.current_value
    assert "3개 모두 통과" in finding.current_value


@pytest.mark.parametrize(("rule_cls", "expected"), INSECURE_EXPECTED.items())
def test_insecure_compose_is_flagged(rule_cls, expected, compose_context):
    finding = _single(rule_cls(), compose_context("insecure.yml"))
    assert finding.status == expected
    assert finding.target.endswith("insecure.yml")


@pytest.mark.parametrize("rule_cls", ALL_COMPOSE_RULES)
def test_one_finding_per_project(rule_cls, compose_context):
    findings = rule_cls().check(compose_context("secure.yml", "insecure.yml"))
    assert len(findings) == 2


@pytest.mark.parametrize("rule_cls", ALL_COMPOSE_RULES)
def test_no_findings_when_compose_not_collected(rule_cls, context_factory):
    assert rule_cls().check(context_factory(compose=None)) == []


@pytest.mark.parametrize("rule_cls", ALL_COMPOSE_RULES)
def test_broken_project_is_ignored_by_rules(rule_cls, compose_context):
    """파싱 실패는 수집 단계에서 오류로 보고되고, 룰은 건너뛴다."""
    assert rule_cls().check(compose_context("broken.yml")) == []


@pytest.mark.parametrize("rule_cls", ALL_COMPOSE_RULES)
def test_metadata_is_complete(rule_cls, compose_context):
    finding = _single(rule_cls(), compose_context("insecure.yml"))
    assert finding.rule_id == rule_cls.id
    assert finding.category == Category.COMPOSE.value
    assert finding.title and finding.recommended and finding.reference
    assert len(finding.why) > 150
    assert len(finding.how_to_fix) > 80
    assert len(finding.tradeoff) > 150
    assert finding.learn_more.startswith("https://docs.docker.com/")


@pytest.mark.parametrize("rule_cls", ALL_COMPOSE_RULES)
def test_compose_is_never_auto_fixed(rule_cls, compose_context):
    """CLAUDE.md §10.4 — compose 파일은 자동 수정하지 않는다."""
    finding = _single(rule_cls(), compose_context("insecure.yml"))
    assert rule_cls.fix_risk == FixRisk.NONE
    assert not finding.auto_fixable
    assert rule_cls().plan_fix(finding, compose_context("insecure.yml")) is None


@pytest.mark.parametrize("rule_cls", [r for r, s in INSECURE_EXPECTED.items() if s == Status.FAIL])
def test_failing_finding_includes_service_specific_example(rule_cls, compose_context):
    finding = _single(rule_cls(), compose_context("insecure.yml"))
    assert finding.how_to_fix.startswith("**이 프로젝트에 적용할 수정 예시**")
    assert "services:" in finding.how_to_fix


def test_identical_issues_are_grouped_by_service(compose_context):
    finding = _single(ReadOnlyRootFsRule(), compose_context("insecure.yml"))
    assert finding.current_value == "2/2개 서비스 — backend, rabbitmq: read_only 미설정"


def test_long_issue_lists_are_truncated(context_factory):
    services = {f"svc{i}": {"cap_add": [cap]} for i, cap in enumerate(["SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "ALL", "NET_ADMIN", "BPF"])}
    finding = _run(DangerousCapabilitiesRule, context_factory, services)
    assert "외 2건" in finding.current_value


# ============================================================================ 룰별 세부


class TestPrivileged:
    @pytest.mark.parametrize("value", [True, "true", "yes"])
    def test_privileged_variants(self, context_factory, value):
        finding = _run(PrivilegedRule, context_factory, {"app": {"privileged": value}})
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL

    def test_privileged_false_passes(self, context_factory):
        assert _run(PrivilegedRule, context_factory, {"app": {"privileged": False}}).status == Status.PASS


class TestNonRootUser:
    @pytest.mark.parametrize("user", ["root", "0", "0:0", "root:root", " ROOT "])
    def test_explicit_root_fails(self, context_factory, user):
        finding = _run(NonRootUserRule, context_factory, {"app": {"image": "x:1", "user": user}})
        assert finding.status == Status.FAIL
        assert "root 명시" in finding.current_value

    @pytest.mark.parametrize("user", ["1000", "1000:1000", "app", "${UID}:${GID}"])
    def test_non_root_passes(self, context_factory, user):
        assert _run(NonRootUserRule, context_factory, {"app": {"image": "x:1", "user": user}}).status == Status.PASS

    @pytest.mark.parametrize("image", ["postgres:16", "docker.io/library/redis:7", "mysql"])
    def test_privilege_dropping_official_images_warn(self, context_factory, image):
        finding = _run(NonRootUserRule, context_factory, {"db": {"image": image}})
        assert finding.status == Status.WARN
        assert "권한을 내림" in finding.current_value

    def test_bitnami_postgres_is_not_treated_as_official(self, context_factory):
        assert _run(NonRootUserRule, context_factory, {"db": {"image": "bitnami/postgresql:16"}}).status == Status.FAIL

    def test_userns_remap_softens_to_warn(self, context_factory):
        finding = _run(NonRootUserRule, context_factory, {"app": {"image": "x:1"}}, daemon={"userns-remap": "default"})
        assert finding.status == Status.WARN

    def test_dockerfile_user_is_respected(self, tmp_path, context_factory):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\nRUN adduser app\nUSER app\n", encoding="utf-8")
        project = ComposeProject(path=tmp_path / "docker-compose.yml", services={"app": {"build": "."}})
        finding = _single(NonRootUserRule(), context_factory(compose=[project]))
        assert finding.status == Status.PASS

    def test_dockerfile_root_user_fails(self, tmp_path, context_factory):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "Dockerfile.prod").write_text("FROM alpine\nUSER root\n", encoding="utf-8")
        build = {"context": "app", "dockerfile": "Dockerfile.prod"}
        project = ComposeProject(path=tmp_path / "docker-compose.yml", services={"app": {"build": build}})
        finding = _single(NonRootUserRule(), context_factory(compose=[project]))
        assert finding.status == Status.FAIL
        assert "Dockerfile USER root" in finding.current_value

    def test_dockerfile_user_resets_per_stage(self, tmp_path):
        text = "FROM golang AS build\nUSER builder\nRUN make\nFROM alpine\nCOPY --from=build /app /app\n"
        (tmp_path / "Dockerfile").write_text(text, encoding="utf-8")
        assert dockerfile_user(tmp_path, ".") is None  # 최종 스테이지에는 USER 없음

    def test_dockerfile_unreadable_or_remote(self, tmp_path):
        assert dockerfile_user(tmp_path, ".") is None
        assert dockerfile_user(tmp_path, "https://github.com/x/y.git") is None
        assert dockerfile_user(tmp_path, 123) is None

    def test_is_root_user(self):
        assert is_root_user("0:1000") and not is_root_user("1000:0")

    def test_example_only_for_failing_services(self, context_factory):
        finding = _run(NonRootUserRule, context_factory, {"db": {"image": "postgres:16"}})
        assert finding.status == Status.WARN
        assert "수정 예시" not in finding.how_to_fix


class TestNoNewPrivileges:
    @pytest.mark.parametrize(
        ("opts", "expected"),
        [
            (["no-new-privileges:true"], True),
            (["no-new-privileges=true"], True),
            (["no-new-privileges"], True),
            (["no-new-privileges:false"], False),
            (["seccomp:unconfined"], None),
            ([], None),
        ],
    )
    def test_setting_parser(self, opts, expected):
        assert no_new_privileges_setting({"security_opt": opts}) is expected

    def test_daemon_default_counts_as_applied(self, context_factory):
        finding = _run(ComposeNoNewPrivilegesRule, context_factory, {"app": {}}, daemon={"no-new-privileges": True})
        assert finding.status == Status.PASS

    def test_explicit_false_overrides_daemon_default(self, context_factory):
        services = {"app": {"security_opt": ["no-new-privileges:false"]}}
        finding = _run(ComposeNoNewPrivilegesRule, context_factory, services, daemon={"no-new-privileges": True})
        assert finding.status == Status.FAIL
        assert "명시적으로 해제" in finding.current_value


class TestDockerSocket:
    @pytest.mark.parametrize(
        "volume",
        [
            "/var/run/docker.sock:/var/run/docker.sock",
            "/run/docker.sock:/var/run/docker.sock",
            {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"},
        ],
    )
    def test_socket_mount_fails(self, context_factory, volume):
        finding = _run(DockerSocketMountRule, context_factory, {"traefik": {"volumes": [volume]}})
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL

    def test_read_only_socket_is_still_flagged(self, context_factory):
        finding = _run(DockerSocketMountRule, context_factory, {"t": {"volumes": ["/var/run/docker.sock:/s:ro"]}})
        assert finding.status == Status.FAIL
        assert "읽기 전용이어도" in finding.current_value

    def test_normal_volumes_pass(self, context_factory):
        services = {"db": {"volumes": ["db-data:/var/lib/postgresql/data", "./conf:/etc/app:ro", "/tmp"]}}
        assert _run(DockerSocketMountRule, context_factory, services).status == Status.PASS


class TestPlaintextSecrets:
    @pytest.mark.parametrize(
        "name",
        ["DB_PASSWORD", "RABBITMQ_DEFAULT_PASS", "JWT_SECRET", "GITHUB_TOKEN", "API_KEY", "AWS_SECRET_ACCESS_KEY",
         "MYSQL_ROOT_PASSWORD", "stripe_apikey", "SMTP_PASSWD", "CLIENT_CREDENTIALS"],
    )  # fmt: skip
    def test_secret_names(self, name):
        assert is_secret_name(name)

    @pytest.mark.parametrize(
        "name",
        ["POSTGRES_PASSWORD_FILE", "PWD", "PASSWORD_MIN_LENGTH", "TOKEN_URL", "JWT_TOKEN_TTL", "BYPASS_CACHE",
         "RABBITMQ_HOST", "DB_USER", "SECRET_KEY_PATH", "KEYCLOAK_REALM"],
    )  # fmt: skip
    def test_non_secret_names(self, name):
        assert not is_secret_name(name)

    def test_list_and_mapping_syntax(self, context_factory):
        services = {
            "a": {"environment": ["DB_PASSWORD=hunter2", "DEBUG=1"]},
            "b": {"environment": {"API_TOKEN": "abc", "PORT": 8080}},
        }
        finding = _run(PlaintextSecretsRule, context_factory, services)
        assert finding.status == Status.FAIL
        assert "a: DB_PASSWORD (평문 값)" in finding.current_value
        assert "b: API_TOKEN (평문 값)" in finding.current_value

    def test_secret_values_are_never_printed(self, context_factory):
        finding = _run(PlaintextSecretsRule, context_factory, {"a": {"environment": {"DB_PASSWORD": "hunter2-very-secret"}}})
        for text in (finding.current_value, finding.how_to_fix, finding.why, finding.tradeoff):
            assert "hunter2" not in text

    @pytest.mark.parametrize(
        "value",
        ["${DB_PASSWORD}", "$DB_PASSWORD", "${DB_PASSWORD:?required}", "/run/secrets/db_password", "", None],
    )
    def test_safe_values(self, context_factory, value):
        assert _run(PlaintextSecretsRule, context_factory, {"a": {"environment": {"DB_PASSWORD": value}}}).status == Status.PASS

    def test_escaped_dollar_is_still_plaintext(self, context_factory):
        """`$$`는 리터럴 `$` — 변수 참조가 아니므로 평문이다."""
        finding = _run(PlaintextSecretsRule, context_factory, {"a": {"environment": {"DB_PASSWORD": "pa$$word"}}})
        assert finding.status == Status.FAIL

    @pytest.mark.parametrize("value", ["${DB_PASSWORD:-changeme}", "${DB_PASSWORD-changeme}"])
    def test_plaintext_default_value_fails(self, context_factory, value):
        finding = _run(PlaintextSecretsRule, context_factory, {"a": {"environment": {"DB_PASSWORD": value}}})
        assert finding.status == Status.FAIL
        assert "기본값에 평문" in finding.current_value

    def test_fix_example_uses_variable_references(self, context_factory):
        finding = _run(PlaintextSecretsRule, context_factory, {"backend": {"environment": ["DB_PASSWORD=x"]}})
        assert "DB_PASSWORD: ${DB_PASSWORD}" in finding.how_to_fix
        assert "# DB_PASSWORD=..." in finding.how_to_fix

    def test_env_parser(self):
        assert service_environment({"environment": ["A=1", "B", "C="]}) == [("A", "1"), ("B", None), ("C", "")]
        assert service_environment({"environment": {"A": None}}) == [("A", None)]
        assert service_environment({}) == []


class TestResourceLimits:
    def test_deploy_limits_pass(self, context_factory):
        services = {"a": {"deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "256M"}}}}}
        assert _run(ResourceLimitsRule, context_factory, services).status == Status.PASS

    def test_legacy_keys_pass(self, context_factory):
        assert _run(ResourceLimitsRule, context_factory, {"a": {"mem_limit": "1g", "cpu_shares": 512}}).status == Status.PASS

    def test_no_limits_fail(self, context_factory):
        finding = _run(ResourceLimitsRule, context_factory, {"a": {}})
        assert finding.status == Status.FAIL
        assert "memory · cpu 제한 없음" in finding.current_value

    def test_memory_only_warns(self, context_factory):
        assert _run(ResourceLimitsRule, context_factory, {"a": {"mem_limit": "1g"}}).status == Status.WARN

    def test_cpu_only_fails(self, context_factory):
        finding = _run(ResourceLimitsRule, context_factory, {"a": {"cpus": 1}})
        assert finding.status == Status.FAIL
        assert "memory 제한 없음" in finding.current_value

    def test_malformed_deploy_is_tolerated(self, context_factory):
        assert _run(ResourceLimitsRule, context_factory, {"a": {"deploy": "x"}}).status == Status.FAIL
        assert _run(ResourceLimitsRule, context_factory, {"a": {"deploy": {"resources": 1}}}).status == Status.FAIL


class TestHostNetworkAndNamespaces:
    def test_host_network_is_warning_not_failure(self, context_factory):
        finding = _run(HostNetworkRule, context_factory, {"gpu": {"network_mode": "host"}})
        assert finding.status == Status.WARN
        assert "검토" in finding.current_value

    def test_other_network_modes_pass(self, context_factory):
        services = {"a": {"network_mode": "service:b"}, "b": {"network_mode": "bridge"}}
        assert _run(HostNetworkRule, context_factory, services).status == Status.PASS

    def test_pid_and_ipc_host(self, context_factory):
        finding = _run(HostNamespacesRule, context_factory, {"a": {"pid": "host", "ipc": "host"}})
        assert finding.status == Status.FAIL
        assert "pid: host" in finding.current_value and "ipc: host" in finding.current_value
        assert "shm_size" in finding.how_to_fix

    def test_service_scoped_sharing_passes(self, context_factory):
        services = {"a": {"ipc": "shareable"}, "b": {"ipc": "service:a", "pid": "service:a"}}
        assert _run(HostNamespacesRule, context_factory, services).status == Status.PASS


class TestCapabilities:
    @pytest.mark.parametrize("cap", ["SYS_ADMIN", "cap_sys_admin", "CAP_SYS_PTRACE", "ALL", "net_admin"])
    def test_dangerous(self, context_factory, cap):
        assert _run(DangerousCapabilitiesRule, context_factory, {"a": {"cap_add": [cap]}}).status == Status.FAIL

    def test_harmless_caps_pass(self, context_factory):
        services = {"a": {"cap_add": ["NET_BIND_SERVICE", "CHOWN"], "cap_drop": ["ALL"]}}
        assert _run(DangerousCapabilitiesRule, context_factory, services).status == Status.PASS

    def test_caps_are_listed_and_reasons_explained_in_example(self, context_factory):
        finding = _run(DangerousCapabilitiesRule, context_factory, {"a": {"cap_add": ["SYS_MODULE", "CAP_NET_ADMIN"]}})
        assert "cap_add SYS_MODULE, NET_ADMIN" in finding.current_value
        assert "커널 모듈" in finding.how_to_fix

    def test_normalize(self):
        assert normalize_capability(" cap_net_raw ") == "NET_RAW"


class TestImageTag:
    @pytest.mark.parametrize(
        ("image", "status"),
        [
            ("nginx", Status.FAIL),
            ("nginx:latest", Status.FAIL),
            ("nginx:LATEST", Status.FAIL),
            ("registry.internal:5000/team/app", Status.FAIL),  # 콜론은 포트, 태그 없음
            ("registry.internal:5000/team/app:2.1.0", Status.PASS),
            ("nginx:1.27-alpine", Status.PASS),
            ("nginx@sha256:abcdef", Status.PASS),
            ("app:${TAG}", Status.PASS),  # 배포 시 값에 달림
            ("app:${TAG:-latest}", Status.FAIL),
            ("${REGISTRY}/app:${TAG:-1.0}", Status.PASS),
        ],
    )
    def test_tags(self, context_factory, image, status):
        assert _run(ImageTagRule, context_factory, {"a": {"image": image}}).status == status

    def test_build_only_service_is_ignored(self, context_factory):
        assert _run(ImageTagRule, context_factory, {"a": {"build": "."}}).status == Status.PASS

    def test_fix_example_keeps_image_name(self, context_factory):
        finding = _run(ImageTagRule, context_factory, {"mq": {"image": "rabbitmq:latest"}})
        assert "image: rabbitmq:<버전>" in finding.how_to_fix

    @pytest.mark.parametrize(
        ("image", "name", "tag", "digest", "official"),
        [
            ("postgres:16", "postgres", "16", None, "postgres"),
            ("library/redis", "library/redis", None, None, "redis"),
            ("bitnami/redis:7", "bitnami/redis", "7", None, None),
            ("localhost:5000/app@sha256:ab", "localhost:5000/app", None, "sha256:ab", None),
        ],
    )
    def test_parse_image(self, image, name, tag, digest, official):
        ref = parse_image(image)
        assert (ref.name, ref.tag, ref.digest, ref.official_name) == (name, tag, digest, official)


class TestPrivilegedPorts:
    @pytest.mark.parametrize(
        ("ports", "status"),
        [
            (["22:22"], Status.WARN),
            (["127.0.0.1:53:53/udp"], Status.WARN),
            (["80:8080", "443:8443"], Status.PASS),  # 웹 표준 포트
            (["8080:80"], Status.PASS),  # 컨테이너 포트는 무관, 호스트 포트가 기준
            (["80"], Status.PASS),  # 호스트 포트 임의 할당
            ([{"target": 25, "published": 25}], Status.WARN),
            (["${PORT}:80"], Status.PASS),  # 알 수 없음
        ],
    )
    def test_ports(self, context_factory, ports, status):
        assert _run(PrivilegedPortsRule, context_factory, {"a": {"ports": ports}}).status == status

    @pytest.mark.parametrize(
        ("entry", "host_ip", "host_port", "end", "container", "proto"),
        [
            ("8080:80", None, 8080, 8080, "80", "tcp"),
            ("127.0.0.1:5672:5672", "127.0.0.1", 5672, 5672, "5672", "tcp"),
            ("[::1]:8080:80", "::1", 8080, 8080, "80", "tcp"),
            ("53:53/udp", None, 53, 53, "53", "udp"),
            ("9000-9002:9000-9002", None, 9000, 9002, "9000-9002", "tcp"),
            ("3000", None, None, None, "3000", "tcp"),
            (3000, None, None, None, "3000", "tcp"),
            ({"target": 80, "published": "8080", "host_ip": "0.0.0.0"}, "0.0.0.0", 8080, 8080, "80", "tcp"),
        ],
    )
    def test_parse_port(self, entry, host_ip, host_port, end, container, proto):
        p = parse_port(entry)
        assert (p.host_ip, p.host_port, p.host_port_end, p.container_port, p.protocol) == (
            host_ip, host_port, end, container, proto,
        )  # fmt: skip

    def test_parse_port_rejects_garbage(self):
        assert parse_port(None) is None and parse_port("  ") is None


def test_parse_volume_variants():
    assert parse_volume("/data").source is None
    assert parse_volume("./conf:/etc/app:ro").read_only
    assert not parse_volume("vol:/data:rw").read_only
    assert parse_volume({"source": "/a", "target": "/b", "read_only": True}).read_only
    assert parse_volume(42) is None
