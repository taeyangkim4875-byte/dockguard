"""Docker 상태 수집 테스트 — SDK / CLI / 스냅샷 경로와 오류 안내 (실제 Docker 없이)."""

from __future__ import annotations

import json
import subprocess
import sys
import types

import pytest

from dockguard.core import docker_runtime as dr
from dockguard.core.docker_runtime import (
    MSG_NOT_INSTALLED,
    MSG_NOT_RUNNING,
    MSG_PERMISSION,
    CliBackend,
    DockerUnavailable,
    SdkBackend,
    build_runtime,
    classify_docker_error,
    collect_runtime,
    parse_container,
    parse_network,
)

RABBIT_INSPECT = {
    "Id": "abc123" * 10,
    "Name": "/rabbitmq",
    "State": {"Status": "running"},
    "Config": {
        "Image": "rabbitmq:3.13",
        "ExposedPorts": {"5672/tcp": {}, "15672/tcp": {}},
        "Labels": {"com.docker.compose.project": "mq", "com.docker.compose.service": "rabbitmq"},
    },
    "HostConfig": {"NetworkMode": "mq_default", "RestartPolicy": {"Name": "unless-stopped"}},
    "NetworkSettings": {
        "Networks": {"mq_default": {"IPAddress": "172.20.0.2"}},
        "Ports": {
            "5672/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5672"}, {"HostIp": "::", "HostPort": "5672"}],
            "4369/tcp": None,
        },
    },
}
BRIDGE_INSPECT = {"Id": "n1", "Name": "bridge", "Driver": "bridge", "Options": {"com.docker.network.bridge.enable_icc": "false"}}


# ============================================================================ 파서


class TestParsers:
    def test_parse_full_container(self):
        c = parse_container(RABBIT_INSPECT)
        assert c.name == "rabbitmq" and c.running and c.restart_policy == "unless-stopped"
        assert c.networks == ["mq_default"]
        assert c.compose_project == "mq" and c.compose_service == "rabbitmq"
        assert [p.label for p in c.ports] == ["0.0.0.0:5672->5672/tcp", "[::]:5672->5672/tcp"]
        assert all(p.open_to_all for p in c.ports)
        assert c.exposes(15672) and not c.exposes(80)

    def test_parse_minimal_container_is_robust(self):
        c = parse_container({"Id": "x", "Name": "/lonely"})
        assert c.name == "lonely" and c.state == "unknown" and c.networks == [] and c.restart_policy == "no"

    def test_parse_skips_unparseable_ports(self):
        data = {"NetworkSettings": {"Ports": {"abc/tcp": [{"HostIp": "", "HostPort": "1"}], "80": [{"HostPort": ""}]}}}
        ports = parse_container(data).ports
        assert len(ports) == 1 and ports[0].host_port is None and ports[0].protocol == "tcp"

    def test_parse_network(self):
        n = parse_network(BRIDGE_INSPECT)
        assert n.name == "bridge" and n.icc_disabled

    def test_compose_config_files_label(self):
        c = parse_container({"Config": {"Labels": {"com.docker.compose.project.config_files": "/a/compose.yml,/a/override.yml"}}})
        assert [p.name for p in c.compose_config_files] == ["compose.yml", "override.yml"]


class TestRuntimeHelpers:
    def test_find_container_by_name_or_id_prefix(self):
        runtime = build_runtime(_FakeBackend([RABBIT_INSPECT]))
        assert runtime.find_container("rabbitmq").name == "rabbitmq"
        assert runtime.find_container("/rabbitmq") is not None
        assert runtime.find_container(RABBIT_INSPECT["Id"][:12]) is not None
        assert runtime.find_container("abc") is None  # 너무 짧은 ID 접두사는 매칭하지 않음

    def test_effective_networks_follow_container_mode(self):
        sidecar = {"Id": "s", "Name": "/sidecar", "HostConfig": {"NetworkMode": "container:rabbitmq"}}
        runtime = build_runtime(_FakeBackend([RABBIT_INSPECT, sidecar]))
        assert runtime.effective_networks(runtime.find_container("sidecar")) == ["mq_default"]

    def test_effective_networks_unknown_owner(self):
        orphan = {"Id": "s", "Name": "/sidecar", "HostConfig": {"NetworkMode": "container:gone"}}
        runtime = build_runtime(_FakeBackend([orphan]))
        assert runtime.effective_networks(runtime.containers[0]) == []

    def test_security_options(self):
        runtime = build_runtime(_FakeBackend([], info={"SecurityOptions": ["name=userns"], "ServerVersion": "27.0"}))
        assert runtime.has_security_option("userns") and not runtime.has_security_option("rootless")
        assert runtime.server_version == "27.0"


# ============================================================================ 오류 안내


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Got permission denied while trying to connect to the Docker daemon socket", MSG_PERMISSION),
        ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", MSG_NOT_RUNNING),
        ("Error while fetching server API version: ('Connection aborted.', FileNotFoundError(2))", MSG_NOT_RUNNING),
        ("open //./pipe/docker_engine: The system cannot find the file specified.", MSG_NOT_RUNNING),
    ],
)
def test_classify_docker_error(message, expected):
    assert classify_docker_error(message) == expected


def test_classify_unknown_error_keeps_first_line():
    assert classify_docker_error("weird failure\nstack trace") == "Docker 데몬과 통신하지 못했습니다: weird failure"
    assert "알 수 없는 오류" in classify_docker_error("")


# ============================================================================ 수집 경로 선택


class _FakeBackend:
    name = "fake"

    def __init__(self, containers, networks=None, info=None, fail_info=False):
        self._containers, self._networks, self._info, self._fail_info = containers, networks or [], info or {}, fail_info

    def containers(self):
        return self._containers

    def networks(self):
        return self._networks

    def info(self):
        if self._fail_info:
            raise RuntimeError("info 실패")
        return self._info


def _failing(message):
    def factory():
        raise DockerUnavailable(message)

    return factory


class TestCollectRuntime:
    def test_falls_back_to_next_backend(self):
        runtime = collect_runtime(backends=(_failing(MSG_NOT_INSTALLED), lambda: _FakeBackend([RABBIT_INSPECT])))
        assert runtime.available and runtime.source == "fake" and len(runtime.containers) == 1

    def test_permission_error_wins_over_other_reasons(self):
        runtime = collect_runtime(backends=(_failing(MSG_NOT_RUNNING), _failing(MSG_PERMISSION)))
        assert not runtime.available
        assert runtime.error.startswith(MSG_PERMISSION)
        assert "--docker-snapshot" in runtime.error

    def test_not_installed_everywhere(self):
        runtime = collect_runtime(backends=(_failing(MSG_NOT_INSTALLED), _failing(MSG_NOT_INSTALLED)))
        assert runtime.error.startswith(MSG_NOT_INSTALLED)

    def test_specific_error_preferred_over_not_installed(self):
        runtime = collect_runtime(backends=(_failing(MSG_NOT_INSTALLED), _failing("Docker 데몬과 통신하지 못했습니다: x")))
        assert runtime.error.startswith("Docker 데몬과 통신하지 못했습니다")

    def test_info_failure_is_tolerated(self):
        runtime = build_runtime(_FakeBackend([RABBIT_INSPECT], fail_info=True))
        assert runtime.available and runtime.security_options == []

    def test_data_fetch_failure_becomes_unavailable(self):
        class Broken(_FakeBackend):
            def containers(self):
                raise ConnectionError("connection refused")

        with pytest.raises(DockerUnavailable, match="연결할 수 없습니다"):
            build_runtime(Broken([]))

    def test_default_backends_are_used(self):
        """conftest가 실제 Docker 대신 '연결 불가'를 넣어 두었다."""
        runtime = collect_runtime()
        assert not runtime.available and runtime.error.startswith(MSG_NOT_RUNNING)


class TestSnapshot:
    def test_incident_snapshot(self, incident_dir):
        runtime = collect_runtime(incident_dir / "snapshot.json")
        assert runtime.available and runtime.source == "스냅샷 파일 (snapshot.json)"
        assert {c.name for c in runtime.containers} >= {"rabbitmq", "backend-container", "messaging-redis-1"}
        assert runtime.network("bridge").icc_disabled

    @pytest.mark.parametrize(
        ("content", "message"),
        [("{broken", "JSON 파싱 실패"), ("[1, 2]", "형식이 올바르지 않습니다"), ('{"containers": {}}', "형식이 올바르지 않습니다")],
    )
    def test_invalid_snapshot(self, tmp_path, content, message):
        path = tmp_path / "snap.json"
        path.write_text(content, encoding="utf-8")
        runtime = collect_runtime(path)
        assert not runtime.available and message in runtime.error

    def test_missing_snapshot(self, tmp_path):
        assert "읽을 수 없습니다" in collect_runtime(tmp_path / "nope.json").error


# ============================================================================ CLI 폴백


class _FakeDockerCli:
    """`docker` 명령 흉내. 명령 인자별로 (종료 코드, 출력)을 돌려준다."""

    def __init__(self, responses: dict[tuple[str, ...], tuple[int, str]]):
        self.responses = responses
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, cmd, **kwargs):
        args = tuple(cmd[1:])
        self.calls.append(args)
        for prefix, (code, out) in self.responses.items():
            if args[: len(prefix)] == prefix:
                return subprocess.CompletedProcess(cmd, code, stdout=out if code == 0 else "", stderr="" if code == 0 else out)
        raise AssertionError(f"예상하지 못한 docker 호출: {args}")


class TestCliBackend:
    def test_not_installed(self, monkeypatch):
        monkeypatch.setattr(dr.shutil, "which", lambda name: None)
        with pytest.raises(DockerUnavailable, match="찾을 수 없습니다"):
            CliBackend()

    def test_daemon_not_running(self, monkeypatch):
        monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/docker")
        fake = _FakeDockerCli({("version",): (1, "Cannot connect to the Docker daemon. Is the docker daemon running?")})
        with pytest.raises(DockerUnavailable) as exc:
            CliBackend(runner=fake)
        assert str(exc.value) == MSG_NOT_RUNNING

    def test_collects_inspect_json(self, monkeypatch):
        monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/docker")
        fake = _FakeDockerCli(
            {
                ("version",): (0, "27.3.1\n"),
                ("ps",): (0, "abc\n"),
                ("inspect", "abc"): (0, json.dumps([RABBIT_INSPECT])),
                ("network", "ls"): (0, "n1\n"),
                ("network", "inspect", "n1"): (0, json.dumps([BRIDGE_INSPECT])),
                ("info",): (0, json.dumps({"ServerVersion": "27.3.1"})),
            }
        )
        runtime = build_runtime(CliBackend(runner=fake))
        assert runtime.source == "docker CLI"
        assert runtime.containers[0].name == "rabbitmq" and runtime.networks[0].name == "bridge"

    def test_no_containers_skips_inspect(self, monkeypatch):
        monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/docker")
        fake = _FakeDockerCli({("version",): (0, "27"), ("ps",): (0, ""), ("network", "ls"): (0, ""), ("info",): (0, "{}")})
        runtime = build_runtime(CliBackend(runner=fake))
        assert runtime.containers == [] and not any(c[0] == "inspect" for c in fake.calls)

    def test_timeout_is_classified(self, monkeypatch):
        monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/docker")

        def timeout(*a, **k):
            raise subprocess.TimeoutExpired("docker", 30)

        with pytest.raises(DockerUnavailable):
            CliBackend(runner=timeout)


# ============================================================================ SDK


class TestSdkBackend:
    def _install_fake_sdk(self, monkeypatch, client=None, error: Exception | None = None):
        module = types.ModuleType("docker")

        def from_env(timeout=None):
            if error is not None:
                raise error
            return client

        module.from_env = from_env
        monkeypatch.setitem(sys.modules, "docker", module)

    def test_sdk_missing(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "docker", None)  # import 실패 흉내
        with pytest.raises(DockerUnavailable, match="찾을 수 없습니다"):
            SdkBackend()

    def test_sdk_connection_error(self, monkeypatch):
        self._install_fake_sdk(monkeypatch, error=Exception("Error while fetching server API version"))
        with pytest.raises(DockerUnavailable) as exc:
            SdkBackend()
        assert str(exc.value) == MSG_NOT_RUNNING

    def test_sdk_happy_path(self, monkeypatch):
        container = types.SimpleNamespace(attrs=RABBIT_INSPECT)
        client = types.SimpleNamespace(
            ping=lambda: True,
            containers=types.SimpleNamespace(list=lambda all, ignore_removed: [container]),
            api=types.SimpleNamespace(networks=lambda: [BRIDGE_INSPECT]),
            info=lambda: {"SecurityOptions": ["name=rootless"]},
        )
        self._install_fake_sdk(monkeypatch, client=client)
        runtime = build_runtime(SdkBackend())
        assert runtime.source == "Docker SDK"
        assert runtime.containers[0].name == "rabbitmq"
        assert runtime.has_security_option("rootless")
