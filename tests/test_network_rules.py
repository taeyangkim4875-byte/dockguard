"""네트워크 룰 테스트 (NET-001 ~ 004) — Docker 상태는 가짜 DockerRuntime으로 만든다."""

from __future__ import annotations

from pathlib import Path

import pytest

from dockguard.core.context import ComposeProject, DaemonConfig, Dependency, DockerRuntime
from dockguard.core.models import Category, Severity, Status
from dockguard.rules.daemon.userns_remap import UsernsRemapRule
from dockguard.rules.network.default_bridge import DefaultBridgeRule
from dockguard.rules.network.dependency import DependencyConnectivityRule
from dockguard.rules.network.exposed_ports import ExposedSensitivePortsRule
from dockguard.rules.network.orphan_containers import OrphanContainersRule

ALL_NETWORK_RULES = [DependencyConnectivityRule, OrphanContainersRule, DefaultBridgeRule, ExposedSensitivePortsRule]
ICC_OFF = {"com.docker.network.bridge.enable_icc": "false"}


def _daemon(data: dict) -> DaemonConfig:
    return DaemonConfig(path=Path("/etc/docker/daemon.json"), exists=True, data=data)


def _single(rule, context):
    findings = rule.check(context)
    assert len(findings) == 1, findings
    return findings[0]


# ============================================================================ 공통


@pytest.mark.parametrize("rule_cls", ALL_NETWORK_RULES)
def test_not_collected_returns_nothing(rule_cls, context_factory):
    assert rule_cls().check(context_factory(docker=None)) == []


@pytest.mark.parametrize("rule_cls", ALL_NETWORK_RULES)
def test_docker_unavailable_is_skipped_with_reason(rule_cls, context_factory):
    runtime = DockerRuntime(available=False, error="Docker 데몬에 연결할 수 없습니다")
    finding = _single(rule_cls(), context_factory(docker=runtime))
    assert finding.status == Status.SKIP
    assert "연결할 수 없습니다" in finding.current_value


@pytest.mark.parametrize("rule_cls", ALL_NETWORK_RULES)
def test_metadata_is_complete(rule_cls, context_factory, make_runtime):
    finding = rule_cls().check(context_factory(docker=make_runtime([])))[0]
    assert finding.category == Category.NETWORK.value
    assert finding.reference and finding.recommended
    assert len(finding.why) > 150 and len(finding.how_to_fix) > 80 and len(finding.tradeoff) > 150
    assert finding.learn_more.startswith("https://docs.docker.com/")
    assert not finding.auto_fixable


# ============================================================================ NET-001 의존성 통신


class TestDependencyConnectivity:
    def _check(self, context_factory, runtime, *deps: Dependency, daemon: dict | None = None):
        context = context_factory(_daemon(daemon) if daemon is not None else None, docker=runtime, dependencies=list(deps))
        return DependencyConnectivityRule().check(context)

    def _one(self, *args, **kwargs):
        findings = self._check(*args, **kwargs)
        assert len(findings) == 1
        return findings[0]

    DEP = Dependency("backend", "rabbitmq", 5672, "백엔드가 RabbitMQ 큐를 소비", "dependencies.yaml")

    def test_no_dependencies_is_skipped_with_hint(self, context_factory, make_runtime):
        finding = self._one(context_factory, make_runtime([]))
        assert finding.status == Status.SKIP
        assert "dependencies.example.yaml" in finding.current_value

    def test_shared_custom_network_passes(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend", ["mq-net"]), make_container("rabbitmq", ["mq-net"])])
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.PASS
        assert finding.current_value == "공유 네트워크: mq-net"
        assert finding.target == "backend → rabbitmq:5672 (dependencies.yaml)"

    def test_no_shared_network_fails_with_recovery_command(self, context_factory, make_runtime, make_container):
        """dockguard의 핵심 시나리오: 정전 후 백엔드가 기본 bridge로, RabbitMQ는 커스텀 네트워크로 분리."""
        runtime = make_runtime([make_container("backend", ["bridge"]), make_container("rabbitmq", ["mq-net"])])
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert "공유 네트워크 없음" in finding.current_value
        assert finding.why.startswith("**백엔드가 RabbitMQ 큐를 소비** — 하지만")
        assert "docker network connect mq-net backend" in finding.how_to_fix
        assert "재기동 시 풀린다" in finding.tradeoff

    def test_missing_container_fails(self, context_factory, make_runtime, make_container):
        finding = self._one(context_factory, make_runtime([make_container("backend")]), self.DEP)
        assert finding.status == Status.FAIL
        assert "컨테이너를 찾을 수 없음: rabbitmq" in finding.current_value
        assert "지금 바로 복구하려면" not in finding.how_to_fix  # 없는 컨테이너에 네트워크 연결을 제안하지 않는다

    def test_stopped_target_without_restart_policy(self, context_factory, make_runtime, make_container):
        """정전 후 restart 정책이 없는 컨테이너는 올라오지 않는다."""
        runtime = make_runtime([make_container("backend"), make_container("rabbitmq", state="exited", restart="no")])
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.FAIL
        assert "재시작 정책이 없어" in finding.current_value
        assert "docker update --restart unless-stopped rabbitmq" in finding.how_to_fix

    def test_stopped_target_with_restart_policy(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend"), make_container("rabbitmq", state="exited", restart="always")])
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.FAIL
        assert "재시작 정책이 없어" not in finding.current_value

    def test_default_bridge_blocked_by_daemon_icc(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend", ["bridge"]), make_container("rabbitmq", ["bridge"])])
        finding = self._one(context_factory, runtime, self.DEP, daemon={"icc": False})
        assert finding.status == Status.FAIL
        assert "통신이 차단됨" in finding.current_value

    def test_default_bridge_blocked_by_runtime_option(self, context_factory, make_runtime, make_container):
        """daemon.json이 없어도 Docker가 bridge 옵션에 기록한 실제 icc 상태로 판단한다."""
        runtime = make_runtime(
            [make_container("backend", ["bridge"]), make_container("rabbitmq", ["bridge"])],
            network_options={"bridge": ICC_OFF},
        )
        assert self._one(context_factory, runtime, self.DEP).status == Status.FAIL

    def test_default_bridge_with_icc_warns_about_dns(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend", ["bridge"]), make_container("rabbitmq", ["bridge"])])
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.WARN
        assert "DNS" in finding.current_value

    def test_custom_network_with_icc_disabled(self, context_factory, make_runtime, make_container):
        runtime = make_runtime(
            [make_container("backend", ["iso-net"]), make_container("rabbitmq", ["iso-net"])],
            network_options={"iso-net": ICC_OFF},
        )
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.FAIL
        assert "enable_icc=false" in finding.current_value

    def test_one_usable_network_is_enough(self, context_factory, make_runtime, make_container):
        runtime = make_runtime(
            [make_container("backend", ["bridge", "mq-net"]), make_container("rabbitmq", ["bridge", "mq-net"])],
            network_options={"bridge": ICC_OFF},
        )
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.PASS
        assert finding.current_value == "공유 네트워크: mq-net"

    def test_port_not_exposed_warns(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend"), make_container("rabbitmq", exposed=["15672/tcp", "5671/tcp"])])
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.WARN
        assert "5672 포트를 노출하지 않음" in finding.current_value

    def test_port_exposed_passes(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend"), make_container("rabbitmq", exposed=["5672/tcp"])])
        assert self._one(context_factory, runtime, self.DEP).status == Status.PASS

    def test_host_mode_source_uses_published_port(self, context_factory, make_runtime, make_container):
        runtime = make_runtime(
            [make_container("backend", [], mode="host"), make_container("rabbitmq", ports=[("127.0.0.1", 5672, 5672)])]
        )
        assert self._one(context_factory, runtime, self.DEP).status == Status.WARN

    def test_host_mode_source_without_published_port_fails(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend", [], mode="host"), make_container("rabbitmq")])
        assert self._one(context_factory, runtime, self.DEP).status == Status.FAIL

    def test_host_mode_target_warns(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend"), make_container("rabbitmq", [], mode="host")])
        assert self._one(context_factory, runtime, self.DEP).status == Status.WARN

    def test_network_mode_none_fails(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend", [], mode="none"), make_container("rabbitmq")])
        assert self._one(context_factory, runtime, self.DEP).status == Status.FAIL

    def test_container_network_mode_shares_owner_networks(self, context_factory, make_runtime, make_container):
        runtime = make_runtime(
            [
                make_container("vpn", ["mq-net"]),
                make_container("backend", [], mode="container:vpn"),
                make_container("rabbitmq", ["mq-net"]),
            ]
        )
        assert self._one(context_factory, runtime, self.DEP).status == Status.PASS

    def test_compose_service_names_are_resolved(self, context_factory, make_runtime, make_container):
        labels = lambda svc: {"com.docker.compose.project": "shop", "com.docker.compose.service": svc}  # noqa: E731
        runtime = make_runtime(
            [
                make_container("shop-backend-1", ["shop_default"], labels=labels("backend")),
                make_container("shop-rabbitmq-1", ["shop_default"], labels=labels("rabbitmq")),
            ]
        )
        dep = Dependency("backend", "rabbitmq", origin="compose depends_on", project="shop")
        assert self._one(context_factory, runtime, dep).status == Status.PASS

    def test_scaled_source_must_all_reach(self, context_factory, make_runtime, make_container):
        labels = lambda svc: {"com.docker.compose.project": "shop", "com.docker.compose.service": svc}  # noqa: E731
        runtime = make_runtime(
            [
                make_container("shop-worker-1", ["mq-net"], labels=labels("worker")),
                make_container("shop-worker-2", ["bridge"], labels=labels("worker")),  # 이 복제본만 분리됨
                make_container("rabbitmq", ["mq-net"]),
            ]
        )
        finding = self._one(context_factory, runtime, Dependency("worker", "rabbitmq", project="shop"))
        assert finding.status == Status.FAIL
        assert "shop-worker-2" in finding.current_value

    def test_stopped_source_is_noted(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("backend", state="exited"), make_container("rabbitmq")])
        finding = self._one(context_factory, runtime, self.DEP)
        assert finding.status == Status.PASS
        assert "backend 중지 상태" in finding.current_value

    def test_incident_snapshot(self, incident_dir, context_factory):
        """examples/rabbitmq-incident: 정전 후 재부팅된 서버의 실제 증상을 재현한다."""
        from dockguard.core.dependencies import load_dependency_file
        from dockguard.core.docker_runtime import collect_runtime

        runtime = collect_runtime(incident_dir / "snapshot.json")
        deps = load_dependency_file(incident_dir / "dependencies.yaml")
        findings = {f.target.split(" (")[0]: f for f in self._check(context_factory, runtime, *deps)}
        assert findings["backend-container → rabbitmq:5672"].status == Status.FAIL
        assert "공유 네트워크 없음" in findings["backend-container → rabbitmq:5672"].current_value
        assert findings["service-manager → rabbitmq:5672"].status == Status.PASS
        assert "재시작 정책이 없어" in findings["report-worker → redis:6379"].current_value


# ============================================================================ NET-002 / NET-003


class TestOrphanContainers:
    def test_container_without_custom_network(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("old-backend", ["bridge"]), make_container("api", ["app-net"])])
        finding = _single(OrphanContainersRule(), context_factory(docker=runtime))
        assert finding.status == Status.FAIL
        assert finding.current_value == "1개 — old-backend (bridge)"

    def test_host_none_and_stopped_are_excluded(self, context_factory, make_runtime, make_container):
        runtime = make_runtime(
            [
                make_container("agent", [], mode="host"),
                make_container("sandbox", [], mode="none"),
                make_container("stopped", ["bridge"], state="exited"),
                make_container("api", ["app-net"]),
            ]
        )
        assert _single(OrphanContainersRule(), context_factory(docker=runtime)).status == Status.PASS

    def test_long_list_is_truncated(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container(f"c{i}", ["bridge"]) for i in range(9)])
        assert "외 3개" in _single(OrphanContainersRule(), context_factory(docker=runtime)).current_value


class TestDefaultBridge:
    def test_single_container_on_bridge_passes(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("web", ["bridge"])])
        assert _single(DefaultBridgeRule(), context_factory(docker=runtime)).status == Status.PASS

    def test_shared_bridge_with_icc_fails(self, context_factory, make_runtime, make_container):
        runtime = make_runtime([make_container("web", ["bridge"]), make_container("db", ["bridge"])])
        finding = _single(DefaultBridgeRule(), context_factory(docker=runtime))
        assert finding.status == Status.FAIL
        assert "모든 포트로 통신 가능" in finding.current_value

    def test_shared_bridge_with_icc_off_warns(self, context_factory, make_runtime, make_container):
        """icc: false면 기본 bridge 컨테이너끼리 통신이 끊겨 있다 — 통신이 필요하다면 장애."""
        runtime = make_runtime(
            [make_container("web", ["bridge"]), make_container("db", ["bridge"])], network_options={"bridge": ICC_OFF}
        )
        finding = _single(DefaultBridgeRule(), context_factory(docker=runtime))
        assert finding.status == Status.WARN
        assert "통신 불가" in finding.current_value


# ============================================================================ NET-004 민감 포트


class TestExposedSensitivePorts:
    def test_rabbitmq_open_to_all_fails(self, context_factory, make_runtime, make_container):
        rabbit = make_container(
            "rabbitmq",
            ports=[("0.0.0.0", 5672, 5672), ("::", 5672, 5672), ("0.0.0.0", 15672, 15672)],
        )
        finding = _single(ExposedSensitivePortsRule(), context_factory(docker=make_runtime([rabbit])))
        assert finding.status == Status.FAIL
        assert finding.current_value.startswith("2건")  # IPv4/IPv6 중복 바인딩은 하나로
        assert "RabbitMQ 관리 UI" in finding.current_value

    def test_loopback_and_non_sensitive_ports_pass(self, context_factory, make_runtime, make_container):
        containers = [
            make_container("rabbitmq", ports=[("127.0.0.1", 15672, 15672)]),
            make_container("web", ports=[("0.0.0.0", 443, 8443)]),
        ]
        finding = _single(ExposedSensitivePortsRule(), context_factory(docker=make_runtime(containers)))
        assert finding.status == Status.PASS

    def test_container_port_is_what_matters(self, context_factory, make_runtime, make_container):
        """호스트 포트를 바꿔도(13306) 서비스는 여전히 MySQL이다."""
        mysql = make_container("db", ports=[("0.0.0.0", 13306, 3306)])
        finding = _single(ExposedSensitivePortsRule(), context_factory(docker=make_runtime([mysql])))
        assert finding.status == Status.FAIL
        assert "13306->3306" in finding.current_value

    def test_stopped_containers_are_ignored(self, context_factory, make_runtime, make_container):
        redis = make_container("redis", state="exited", ports=[("0.0.0.0", 6379, 6379)])
        assert _single(ExposedSensitivePortsRule(), context_factory(docker=make_runtime([redis]))).status == Status.PASS

    def test_falls_back_to_compose_when_docker_unavailable(self, context_factory, compose_context):
        compose = compose_context("insecure.yml").compose
        context = context_factory(docker=DockerRuntime(available=False, error="x"), compose=compose)
        finding = _single(ExposedSensitivePortsRule(), context)
        assert finding.status == Status.FAIL
        assert "compose 파일 기준" in finding.target
        assert "rabbitmq 5672:5672 (RabbitMQ AMQP)" in finding.current_value

    def test_compose_fallback_respects_loopback_binding(self, context_factory):
        project = ComposeProject(
            path=Path("docker-compose.yml"),
            services={"db": {"ports": ["127.0.0.1:5432:5432", "3000"]}, "mq": {"ports": ["5672"]}},
        )
        context = context_factory(docker=DockerRuntime(available=False, error="x"), compose=[project])
        assert _single(ExposedSensitivePortsRule(), context).status == Status.PASS


# ============================================================================ DAEMON-006 교차 확인


class TestUsernsRuntimeCrossCheck:
    def _finding(self, context_factory, make_runtime, options):
        context = context_factory(_daemon({}), docker=make_runtime([], security_options=options))
        return _single(UsernsRemapRule(), context)

    def test_userns_enabled_by_dockerd_flag(self, context_factory, make_runtime):
        """daemon.json에는 없지만 dockerd 실행 옵션으로 켠 경우도 docker info로 잡는다."""
        finding = self._finding(context_factory, make_runtime, ["name=seccomp,profile=builtin", "name=userns"])
        assert finding.status == Status.PASS
        assert "docker info" in finding.current_value

    def test_rootless_detected_from_docker_info(self, context_factory, make_runtime):
        assert self._finding(context_factory, make_runtime, ["name=rootless"]).status == Status.PASS

    def test_falls_back_to_daemon_json(self, context_factory, make_runtime):
        assert self._finding(context_factory, make_runtime, ["name=seccomp,profile=builtin"]).status == Status.FAIL
