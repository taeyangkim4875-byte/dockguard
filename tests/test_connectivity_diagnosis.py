"""diagnose connectivity — 진단 트리 테스트.

각 단계에서 FAIL이 나는 상황을 가짜 Docker 상태(mock)로 만들어, 진단이 그 단계를 근본 원인으로
지목하는지 확인한다. 실제 Docker 없이 전부 돌아간다 (conftest의 no_real_docker 픽스처).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dockguard.cli import app
from dockguard.core.context import DaemonConfig, DockerRuntime, ScanContext
from dockguard.core.models import Status
from dockguard.diagnostics.connectivity import (
    ConnectivityDiagnosis,
    extract_host,
    mask_credentials,
)

runner = CliRunner()


def make_context(runtime: DockerRuntime | None, daemon: dict | None = None) -> ScanContext:
    """가짜 Docker 상태와 daemon.json을 담은 ScanContext."""
    return ScanContext(
        hostname="test-host",
        scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        categories={"network"},
        daemon=DaemonConfig(path=Path("/etc/docker/daemon.json"), exists=True, data=daemon or {}),
        docker=runtime,
    )


def diagnose(runtime, source="backend", target="rabbitmq", port=5672, daemon: dict | None = None):
    """가짜 Docker 상태로 진단을 실행한다."""
    return ConnectivityDiagnosis(source, target, port).run(make_context(runtime, daemon))


def step(result, number: int):
    """`1. ...` 처럼 번호로 시작하는 단계를 찾는다."""
    return next(s for s in result.steps if s.name.startswith(f"{number}."))


@pytest.fixture
def pair(make_container, make_runtime):
    """정상 상태: 두 컨테이너가 같은 커스텀 네트워크에 있고 주소도 컨테이너 이름."""

    def _make(backend: dict | None = None, rabbitmq: dict | None = None, **runtime_kwargs):
        backend_kwargs = {
            "networks": ["mq-net"],
            "env": {"RABBITMQ_HOST": "rabbitmq", "RABBITMQ_PASSWORD": "s3cret"},
            **(backend or {}),
        }
        rabbit_kwargs = {"networks": ["mq-net"], "exposed": ["5672/tcp", "15672/tcp"], **(rabbitmq or {})}
        containers = [
            make_container("backend", backend_kwargs.pop("networks"), **backend_kwargs),
            make_container("rabbitmq", rabbit_kwargs.pop("networks"), **rabbit_kwargs),
        ]
        return make_runtime(containers, **runtime_kwargs)

    return _make


# ============================================================================ 전부 통과 (원인 미발견)


def test_healthy_pair_finds_no_network_cause(pair):
    result = diagnose(pair())

    assert not result.resolved
    assert result.root is None
    assert [s.status for s in result.steps] == [Status.PASS] * 5
    # 원인을 못 찾았으면 다음에 확인할 것을 안내한다 (방화벽 · 인증 · 애플리케이션)
    assert result.next_checks
    assert any("iptables" in c for c in result.next_checks)
    assert any("인증" in c for c in result.next_checks)


def test_steps_record_what_was_actually_checked(pair):
    """추론 과정이 보여야 한다 — 각 단계가 실제로 확인한 값을 근거로 남긴다."""
    result = diagnose(pair())

    assert all(s.name and s.detail for s in result.steps)
    assert "mq-net" in " ".join(step(result, 3).evidence)
    assert "5672/tcp" in " ".join(step(result, 2).evidence)


# ============================================================================ 1단계: 컨테이너 존재 · 실행


def test_missing_container_stops_diagnosis(pair):
    result = diagnose(pair(), source="backend-old")

    assert result.resolved
    assert result.root is result.steps[0]
    assert "backend-old" in result.root_cause
    assert len(result.steps) == 1  # 컨테이너가 없으면 뒤 단계는 검사하지 않는다
    assert "docker ps -a" in result.fix
    assert "backend" in " ".join(result.evidence)  # 비슷한 이름 안내


def test_stopped_target_without_restart_policy(pair):
    result = diagnose(pair(rabbitmq={"state": "exited", "restart": "no"}))

    assert result.root is result.steps[0]
    assert "멈춰 있다" in result.root_cause
    assert "재시작 정책이 없어" in result.root_cause
    assert "docker update --restart unless-stopped rabbitmq" in result.fix
    # 멈춘 컨테이너라도 네트워크 구성은 계속 검사해 함께 보여준다
    assert len(result.steps) == 5
    assert step(result, 2).status == Status.SKIP


def test_scaled_service_resolved_by_compose_service_name(make_container, make_runtime):
    labels = {"com.docker.compose.project": "app", "com.docker.compose.service": "worker"}
    runtime = make_runtime(
        [
            make_container("app-worker-1", ["mq-net"], state="exited", labels=labels),
            make_container("app-worker-2", ["mq-net"], labels=labels),
            make_container("rabbitmq", ["mq-net"], exposed=["5672/tcp"]),
        ]
    )
    result = diagnose(runtime, source="worker")

    assert step(result, 1).status == Status.PASS  # 실행 중인 컨테이너를 골라 진단
    assert "app-worker-2" in " ".join(step(result, 1).evidence)


# ============================================================================ 2단계: 대상 포트


def test_target_does_not_open_requested_port(pair):
    result = diagnose(pair(rabbitmq={"exposed": ["15672/tcp"]}), port=5672)

    assert result.root is step(result, 2)
    assert "5672번 포트를 열지 않는다" in result.root_cause
    assert "15672" in result.root_cause


def test_no_port_declaration_warns_instead_of_failing(pair):
    result = diagnose(pair(rabbitmq={"exposed": []}))

    assert step(result, 2).status == Status.WARN  # 선언이 없다고 단정하지 않는다
    assert not result.resolved


def test_port_check_skipped_when_port_not_given(pair):
    result = diagnose(pair(), port=None)

    assert step(result, 2).status == Status.SKIP
    assert "--port" in step(result, 2).detail


# ============================================================================ 3단계: 공유 네트워크 (핵심)


def test_network_isolation_is_the_root_cause(pair):
    """소유자가 실제로 며칠 헤맨 상황 — 같은 서버, 맞는 포트, 그런데 네트워크가 다르다."""
    result = diagnose(pair(backend={"networks": ["bridge"]}))

    assert result.resolved
    assert result.root is step(result, 3)
    assert "네트워크 격리" in result.root_cause
    # 근거로 양쪽 네트워크 목록을 보여준다
    evidence = " ".join(result.evidence)
    assert "backend 네트워크: bridge" in evidence
    assert "rabbitmq 네트워크: mq-net" in evidence
    # 해결책: 임시 복구 + compose 영구 반영
    assert "docker network connect mq-net backend" in result.fix
    assert "networks: [mq-net]" in result.fix
    assert "external: true" in result.fix
    # 부작용 설명 (dockguard의 차별점)
    assert "재기동 시 풀린다" in result.tradeoff
    assert "측면 이동" in result.tradeoff


def test_isolation_hint_warns_against_using_default_bridge(pair):
    """공유 네트워크가 없을 때, icc:false면 '둘 다 기본 bridge에 붙이면 되겠네'를 막아 준다."""
    result = diagnose(pair(backend={"networks": ["bridge"]}), daemon={"icc": False})

    hint = step(result, 4)
    assert hint.status == Status.SKIP
    assert "기본 bridge에 함께 붙여도 통신은 되지 않으니" in hint.detail


def test_default_bridge_only_is_a_warning(make_container, make_runtime):
    runtime = make_runtime(
        [
            make_container("backend", ["bridge"], env={"RABBITMQ_HOST": "rabbitmq"}),
            make_container("rabbitmq", ["bridge"], exposed=["5672/tcp"]),
        ]
    )
    result = diagnose(runtime)

    assert step(result, 3).status == Status.WARN
    assert "DNS" in step(result, 3).detail
    assert not result.resolved


def test_network_mode_none_is_reported(pair):
    result = diagnose(pair(backend={"mode": "none", "networks": []}))

    assert result.root is step(result, 3)
    assert "network_mode: none" in result.root_cause


def test_host_mode_source_without_published_port_fails(make_container, make_runtime):
    runtime = make_runtime(
        [
            make_container("backend", [], mode="host"),
            make_container("rabbitmq", ["mq-net"], exposed=["5672/tcp"]),
        ]
    )
    result = diagnose(runtime)

    assert result.root is step(result, 3)
    assert "host 네트워크" in result.root_cause


def test_host_mode_source_with_published_port_warns(make_container, make_runtime):
    runtime = make_runtime(
        [
            make_container("backend", [], mode="host"),
            make_container("rabbitmq", ["mq-net"], exposed=["5672/tcp"], ports=[("0.0.0.0", 5672, 5672)]),
        ]
    )
    result = diagnose(runtime)

    assert step(result, 3).status == Status.WARN
    assert not result.resolved


def test_container_network_mode_shares_owner_networks(make_container, make_runtime):
    runtime = make_runtime(
        [
            make_container("sidecar", [], mode="container:backend"),
            make_container("backend", ["mq-net"]),
            make_container("rabbitmq", ["mq-net"], exposed=["5672/tcp"]),
        ]
    )
    result = diagnose(runtime, source="sidecar")

    assert step(result, 3).status == Status.PASS


# ============================================================================ 4단계: icc


def test_icc_false_blocks_shared_default_bridge(make_container, make_runtime):
    runtime = make_runtime(
        [
            make_container("backend", ["bridge"], env={"RABBITMQ_HOST": "rabbitmq"}),
            make_container("rabbitmq", ["bridge"], exposed=["5672/tcp"]),
        ]
    )
    result = diagnose(runtime, daemon={"icc": False})

    assert result.resolved
    assert result.root is step(result, 4)
    assert "icc: false" in result.root_cause
    assert "docker network create app-net" in result.fix
    assert "icc: true" in result.tradeoff  # 되돌리는 선택의 부작용도 설명


def test_network_level_icc_option_blocks_custom_network(pair):
    result = diagnose(pair(network_options={"mq-net": {"com.docker.network.bridge.enable_icc": "false"}}))

    assert result.root is step(result, 4)
    assert "enable_icc=false" in result.root_cause


def test_icc_from_running_bridge_options_not_only_daemon_json(make_container, make_runtime):
    """daemon.json이 없어도, 실행 중인 기본 bridge의 옵션으로 icc 차단을 잡아낸다."""
    runtime = make_runtime(
        [
            make_container("backend", ["bridge"]),
            make_container("rabbitmq", ["bridge"], exposed=["5672/tcp"]),
        ],
        network_options={"bridge": {"com.docker.network.bridge.enable_icc": "false"}},
    )
    result = diagnose(runtime)

    assert result.root is step(result, 4)


# ============================================================================ 5단계: 접속 주소


def test_localhost_address_is_a_failure(pair):
    result = diagnose(pair(backend={"env": {"RABBITMQ_HOST": "localhost"}}))

    assert result.root is step(result, 5)
    assert "자기 자신" in result.root_cause
    assert "RABBITMQ_HOST: rabbitmq" in result.fix
    assert "같은 커스텀 네트워크" in result.tradeoff


def test_host_ip_without_published_port_is_a_failure(pair):
    result = diagnose(pair(backend={"env": {"RABBITMQ_HOST": "203.0.113.50"}}))

    assert result.root is step(result, 5)
    assert "203.0.113.50" in result.root_cause
    assert "닿지 않는다" in result.root_cause


def test_host_ip_with_published_port_only_warns(pair):
    result = diagnose(
        pair(
            backend={"env": {"RABBITMQ_HOST": "203.0.113.50"}},
            rabbitmq={"exposed": ["5672/tcp"], "ports": [("0.0.0.0", 5672, 5672)]},
        )
    )

    assert step(result, 5).status == Status.WARN
    assert not result.resolved  # 우회 접속이 될 수도 있으므로 단정하지 않는다


def test_unknown_hostname_warns(pair):
    result = diagnose(pair(backend={"env": {"RABBITMQ_HOST": "mq.internal"}}))

    assert step(result, 5).status == Status.WARN
    assert "mq.internal" in step(result, 5).detail


def test_url_style_address_is_understood(pair):
    result = diagnose(pair(backend={"env": {"AMQP_URL": "amqp://app:pa55w0rd@rabbitmq:5672/vhost"}}))

    assert step(result, 5).status == Status.PASS


def test_secrets_are_not_printed(pair):
    result = diagnose(
        pair(
            backend={
                "env": {
                    "RABBITMQ_HOST": "localhost",
                    "RABBITMQ_PASSWORD": "sup3rs3cret",
                    "AMQP_URL": "amqp://app:pa55w0rd@rabbitmq:5672",
                }
            }
        )
    )
    printed = " ".join(step(result, 5).evidence)

    assert "sup3rs3cret" not in printed  # 비밀번호 키는 아예 읽지 않는다
    assert "pa55w0rd" not in printed  # URL에 섞인 자격증명은 가린다
    assert "amqp://app:***@rabbitmq:5672" in printed


def test_address_check_skipped_without_env(pair):
    result = diagnose(pair(backend={"env": {"TZ": "Asia/Seoul"}}))

    assert step(result, 5).status == Status.SKIP


@pytest.mark.parametrize(
    "value, expected",
    [
        ("rabbitmq", "rabbitmq"),
        ("rabbitmq:5672", "rabbitmq"),
        ("amqp://user:pw@rabbitmq:5672/vhost", "rabbitmq"),
        ("redis://cache", "cache"),
        ("[::1]:6379", "::1"),
        ("http://10.0.0.5:8080/path?q=1", "10.0.0.5"),
        ("", None),
    ],
)
def test_extract_host(value, expected):
    assert extract_host(value) == expected


def test_mask_credentials():
    assert mask_credentials("amqp://app:pw@mq:5672") == "amqp://app:***@mq:5672"
    assert mask_credentials("amqp://mq:5672") == "amqp://mq:5672"  # 가릴 것이 없으면 그대로


# ============================================================================ Docker 접근 실패


def test_docker_unavailable_is_friendly():
    context = make_context(DockerRuntime(available=False, error="Docker 데몬에 연결할 수 없습니다."))
    result = ConnectivityDiagnosis("backend", "rabbitmq", 5672).run(context)

    assert result.error is not None
    assert not result.steps
    assert not result.resolved


def test_no_containers_is_friendly():
    context = make_context(DockerRuntime(available=True, source="test"))
    result = ConnectivityDiagnosis("backend", "rabbitmq", 5672).run(context)

    assert result.error is not None and "컨테이너를 찾지 못했습니다" in result.error


# ============================================================================ CLI


def _diagnose_cli(*args: str):
    return runner.invoke(app, ["diagnose", "connectivity", *args], env={"COLUMNS": "140"})


def test_cli_reproduces_the_incident(incident_dir):
    """정전 사고 재현: 백엔드와 RabbitMQ가 서로 다른 네트워크에 있다."""
    result = _diagnose_cli(
        "backend-container", "rabbitmq",
        "--port", "5672",
        "--daemon-config", str(incident_dir / "daemon.json"),
        "--docker-snapshot", str(incident_dir / "snapshot.json"),
    )  # fmt: skip

    assert result.exit_code == 1, result.output  # 근본 원인 발견 → 1
    assert "검사 과정" in result.output
    assert "근본 원인" in result.output
    assert "네트워크 격리" in result.output
    assert "docker network connect messaging_mq-net backend-container" in result.output
    assert "RABBITMQ_PASSWORD" not in result.output


def test_cli_json_output(incident_dir):
    result = _diagnose_cli(
        "backend-container", "rabbitmq",
        "--port", "5672",
        "--format", "json",
        "--docker-snapshot", str(incident_dir / "snapshot.json"),
    )  # fmt: skip

    import json

    data = json.loads(result.output)
    assert data["resolved"] is True
    assert data["diagnosis"] == "connectivity"
    assert "네트워크 격리" in data["root_cause"]
    assert [s["name"][:2] for s in data["steps"]] == ["1.", "2.", "3.", "4.", "5."]


def test_cli_without_docker_exits_2(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _diagnose_cli("backend", "rabbitmq")

    assert result.exit_code == 2, result.output
    assert "진단을 실행할 수 없습니다" in result.output
    assert "--docker-snapshot" in result.output


def test_cli_missing_snapshot_file(tmp_path):
    result = _diagnose_cli("a", "b", "--docker-snapshot", str(tmp_path / "nope.json"))

    assert result.exit_code == 2
    assert "찾을 수 없습니다" in result.output


# ============================================================================ 출력 (reporters/diagnosis.py)


def _render(result) -> str:
    """진단 리포터의 출력을 문자열로 받는다."""
    from io import StringIO

    from rich.console import Console

    from dockguard.reporters.diagnosis import render_diagnosis

    buffer = StringIO()
    console = Console(file=buffer, width=120, color_system=None, force_terminal=False)
    render_diagnosis(console, make_context(None), result)
    return buffer.getvalue()


def test_report_shows_every_step_in_order(pair):
    output = _render(diagnose(pair()))

    assert "검사 과정" in output
    for number in range(1, 6):
        assert f"{number}." in output
    assert "[통과]" in output
    # 원인을 못 찾았을 때는 다음 확인 사항을 안내한다
    assert "네트워크 레벨에서는 연결을 막는 원인을 찾지 못했습니다" in output
    assert "다음으로 확인할 것" in output


def test_report_separates_root_cause_from_additional_problems(pair):
    """원인이 하나가 아닐 때 — 네트워크도 분리돼 있고 접속 주소도 틀렸다 (실제 사고가 그랬다)."""
    result = diagnose(pair(backend={"networks": ["bridge"], "env": {"RABBITMQ_HOST": "localhost"}}))

    assert result.root is step(result, 3)
    assert [s.name for s in result.also_failed] == [step(result, 5).name]

    output = _render(result)
    assert "근본 원인" in output
    assert "네트워크 격리" in output
    assert "추가로 발견된 문제" in output
    assert "이것도 고쳐야 연결됩니다" in output


def test_report_explains_when_docker_is_unavailable():
    result = ConnectivityDiagnosis("a", "b").run(
        make_context(DockerRuntime(available=False, error="Docker 데몬에 연결할 수 없습니다."))
    )
    output = _render(result)

    assert "진단을 실행할 수 없습니다" in output
    assert "--docker-snapshot" in output
    assert "검사 과정" not in output
