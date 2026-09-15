"""서비스 의존성 파일 로드 · compose depends_on 추론 · 수집 통합 테스트."""

from __future__ import annotations

from pathlib import Path

import pytest

from dockguard.core.collector import collect
from dockguard.core.context import ComposeProject, ContainerInfo, DockerRuntime
from dockguard.core.dependencies import (
    DependencyFileError,
    find_dependency_file,
    infer_compose_dependencies,
    load_dependency_file,
    project_is_running,
)

REPO_ROOT = Path(__file__).parent.parent


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestDependencyFile:
    def test_example_file_is_valid(self):
        deps = load_dependency_file(REPO_ROOT / "config" / "dependencies.example.yaml")
        assert [(d.source, d.target, d.port) for d in deps] == [
            ("backend-container", "rabbitmq", 5672),
            ("service-manager", "rabbitmq", 5672),
        ]
        assert deps[0].reason == "백엔드가 RabbitMQ 큐를 소비"
        assert deps[0].origin == "dependencies.example.yaml"

    def test_port_is_optional_and_accepts_strings(self, tmp_path):
        path = _write(tmp_path / "d.yaml", "dependencies:\n  - {from: a, to: b}\n  - {from: a, to: c, port: '6379'}\n")
        assert [d.port for d in load_dependency_file(path)] == [None, 6379]

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("deps: []\n", "`dependencies:` 목록"),
            ("dependencies: {}\n", "`dependencies:` 목록"),
            ("dependencies:\n  - {from: a}\n", "1번째 항목: `from`과 `to`"),
            ("dependencies:\n  - {from: a, to: b}\n  - {from: '', to: b}\n", "2번째 항목"),
            ("dependencies:\n  - {from: a, to: b, port: amqp}\n", "port는 숫자"),
            ("dependencies:\n  - {from: a, to: b, port: 70000}\n", "범위"),
            ("dependencies: [\n", "YAML 문법 오류"),
        ],
    )
    def test_invalid_files_explain_what_is_wrong(self, tmp_path, text, message):
        with pytest.raises(DependencyFileError, match=message.replace("[", r"\[")):
            load_dependency_file(_write(tmp_path / "d.yaml", text))

    def test_unreadable_file(self, tmp_path):
        with pytest.raises(DependencyFileError, match="읽을 수 없습니다"):
            load_dependency_file(tmp_path / "nope.yaml")

    def test_find_dependency_file_order(self, tmp_path):
        assert find_dependency_file(tmp_path) is None
        config = _write(tmp_path / "config" / "dependencies.yaml", "dependencies: []")
        assert find_dependency_file(tmp_path) == config
        root = _write(tmp_path / "dependencies.yaml", "dependencies: []")
        assert find_dependency_file(tmp_path) == root


def _container(name: str, project: str, service: str, config_file: str = "") -> ContainerInfo:
    labels = {"com.docker.compose.project": project, "com.docker.compose.service": service}
    if config_file:
        labels["com.docker.compose.project.config_files"] = config_file
    return ContainerInfo(id=name, name=name, labels=labels)


class TestComposeInference:
    def _project(self, tmp_path, services, name="shop") -> ComposeProject:
        return ComposeProject(path=tmp_path / "docker-compose.yml", services=services, name=name)

    def test_depends_on_becomes_dependency(self, tmp_path):
        project = self._project(tmp_path, {"api": {"depends_on": ["db", "mq"]}, "worker": {"depends_on": {"mq": {"condition": "service_healthy"}}}})
        runtime = DockerRuntime(available=True, containers=[_container("shop-api-1", "shop", "api")])
        deps = infer_compose_dependencies([project], runtime)
        assert [(d.source, d.target) for d in deps] == [("api", "db"), ("api", "mq"), ("worker", "mq")]
        assert all(d.project == "shop" and d.origin == "compose depends_on" for d in deps)

    def test_project_not_running_on_this_host_is_skipped(self, tmp_path):
        project = self._project(tmp_path, {"api": {"depends_on": ["db"]}})
        runtime = DockerRuntime(available=True, containers=[_container("other-1", "other", "x")])
        assert infer_compose_dependencies([project], runtime) == []

    def test_shared_namespace_services_are_skipped(self, tmp_path):
        project = self._project(tmp_path, {"sidecar": {"network_mode": "service:api", "depends_on": ["api"]}})
        runtime = DockerRuntime(available=True, containers=[_container("shop-api-1", "shop", "api")])
        assert infer_compose_dependencies([project], runtime) == []

    def test_project_matched_by_config_file_label(self, tmp_path):
        project = self._project(tmp_path, {"api": {}}, name="renamed")
        runtime = DockerRuntime(
            available=True, containers=[_container("x", "original", "api", str(tmp_path / "docker-compose.yml"))]
        )
        assert project_is_running(project, runtime)

    def test_project_name_comes_from_compose_file(self, incident_dir):
        from dockguard.core.compose_loader import load_compose_project

        assert load_compose_project(incident_dir / "docker-compose.yml").name == "messaging"


class TestCollectIntegration:
    def _collect(self, incident_dir, **kwargs):
        return collect(
            categories={"network"},
            compose_paths=[incident_dir],
            docker_snapshot=incident_dir / "snapshot.json",
            **kwargs,
        )

    def test_declared_dependencies_take_precedence_over_inferred(self, incident_dir):
        context = self._collect(incident_dir, deps_path=incident_dir / "dependencies.yaml")
        pairs = [(d.source, d.target, d.origin) for d in context.dependencies]
        assert ("service-manager", "rabbitmq", "dependencies.yaml") in pairs
        assert ("service-manager", "rabbitmq", "compose depends_on") not in pairs  # 중복 제거
        assert ("report-worker", "rabbitmq", "compose depends_on") in pairs  # 선언 안 된 것은 추론으로 보완
        assert context.dependency_file == incident_dir / "dependencies.yaml"

    def test_inferred_only_without_file(self, incident_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        context = self._collect(incident_dir)
        assert context.dependencies and all(d.origin == "compose depends_on" for d in context.dependencies)

    def test_bad_dependency_file_is_reported(self, incident_dir, tmp_path):
        bad = _write(tmp_path / "deps.yaml", "dependencies: nope\n")
        context = self._collect(incident_dir, deps_path=bad)
        assert any("의존성 파일을 읽지 못했습니다" in e for e in context.errors)

    def test_docker_unavailable_is_reported(self, tmp_path):
        context = collect(categories={"network"}, search_root=tmp_path)
        assert context.docker is not None and not context.docker.available
        assert any("네트워크 점검을 건너뜁니다" in e for e in context.errors)
        assert context.dependencies == []

    def test_network_only_scan_collects_compose_silently(self, incident_dir):
        context = self._collect(incident_dir)
        assert context.compose_projects  # depends_on 추론용
        assert not any("compose 파일을 찾지 못했습니다" in n for n in context.notices)
