"""compose 파일 탐색 · 파싱 · override 병합 테스트."""

from __future__ import annotations

from pathlib import Path

import pytest

from dockguard.core.collector import collect
from dockguard.core.compose_loader import (
    collect_compose_projects,
    deep_merge,
    discover_compose_files,
    find_project_file,
    load_compose_project,
)

MINIMAL = "services:\n  app:\n    image: nginx:1.27\n"


def _write(path: Path, text: str = MINIMAL) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestDiscovery:
    def test_finds_files_in_subdirectories(self, tmp_path):
        a = _write(tmp_path / "docker-compose.yml")
        b = _write(tmp_path / "services" / "mq" / "compose.yaml")
        assert sorted(discover_compose_files(tmp_path)) == sorted([a.resolve(), b.resolve()])

    def test_respects_max_depth(self, tmp_path):
        _write(tmp_path / "a" / "b" / "c" / "d" / "docker-compose.yml")
        assert discover_compose_files(tmp_path, max_depth=3) == []
        assert len(discover_compose_files(tmp_path, max_depth=4)) == 1

    @pytest.mark.parametrize("skipped", ["node_modules", ".git", ".venv", "site-packages"])
    def test_skips_dependency_and_vcs_dirs(self, tmp_path, skipped):
        _write(tmp_path / skipped / "docker-compose.yml")
        assert discover_compose_files(tmp_path) == []

    def test_one_file_per_directory_with_compose_priority(self, tmp_path):
        """docker compose처럼 compose.yaml이 docker-compose.yml보다 우선한다."""
        _write(tmp_path / "docker-compose.yml")
        preferred = _write(tmp_path / "compose.yaml")
        assert find_project_file(tmp_path) == preferred
        assert discover_compose_files(tmp_path) == [preferred.resolve()]

    def test_variant_files_are_not_auto_discovered(self, tmp_path):
        """docker-compose.prod.yml 같은 부분 파일은 단독으로 점검하면 오탐이 많아 자동 탐색하지 않는다."""
        _write(tmp_path / "docker-compose.prod.yml")
        assert discover_compose_files(tmp_path) == []


class TestLoading:
    def test_load_valid_file(self, compose_fixture):
        project = load_compose_project(compose_fixture("secure.yml"))
        assert project.error is None
        assert list(project.services) == ["backend", "rabbitmq", "web"]

    def test_yaml_error_reports_location(self, compose_fixture):
        project = load_compose_project(compose_fixture("broken.yml"))
        assert "YAML 문법 오류" in project.error
        assert "행" in project.error

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("version: '3'\n", "services 항목이 없습니다"),
            ("", "services 항목이 없습니다"),
            ("- a\n- b\n", "매핑"),
            ("services: []\n", "services 항목이 없습니다"),
        ],
    )
    def test_not_a_compose_file(self, tmp_path, text, message):
        project = load_compose_project(_write(tmp_path / "docker-compose.yml", text))
        assert message in project.error

    def test_empty_service_definition_is_tolerated(self, tmp_path):
        project = load_compose_project(_write(tmp_path / "compose.yaml", "services:\n  app:\n"))
        assert project.services == {"app": {}}

    def test_yaml_anchors_and_merge_keys(self, tmp_path):
        text = (
            "x-common: &common\n  read_only: true\n  user: '1000'\n"
            "services:\n  a:\n    <<: *common\n    image: a:1\n"
        )
        project = load_compose_project(_write(tmp_path / "compose.yaml", text))
        assert project.services["a"]["read_only"] is True
        assert project.services["a"]["user"] == "1000"

    def test_unreadable_file(self, tmp_path, monkeypatch):
        path = _write(tmp_path / "compose.yaml")

        def deny(self, *a, **k):
            raise PermissionError()

        monkeypatch.setattr(Path, "read_text", deny)
        assert "권한" in load_compose_project(path).error


class TestOverride:
    def test_override_is_merged(self, tmp_path):
        base = _write(tmp_path / "docker-compose.yml", "services:\n  app:\n    image: app:1\n    ports: ['80:80']\n")
        override = _write(
            tmp_path / "docker-compose.override.yml",
            "services:\n  app:\n    user: '1000'\n    ports: ['443:443']\n",
        )
        project = load_compose_project(base, override)
        app = project.services["app"]
        assert app["user"] == "1000" and app["image"] == "app:1"
        assert app["ports"] == ["80:80", "443:443"]
        assert project.label.endswith("(+ docker-compose.override.yml)")

    def test_broken_override_is_reported(self, tmp_path):
        base = _write(tmp_path / "docker-compose.yml")
        override = _write(tmp_path / "docker-compose.override.yml", "services: [\n")
        project = load_compose_project(base, override)
        assert project.error.startswith("docker-compose.override.yml:")

    def test_deep_merge_rules(self):
        merged = deep_merge({"a": {"x": 1, "l": [1, 2]}, "s": "old"}, {"a": {"y": 2, "l": [2, 3]}, "s": "new"})
        assert merged == {"a": {"x": 1, "y": 2, "l": [1, 2, 3]}, "s": "new"}

    def test_auto_discovery_merges_override_but_explicit_file_does_not(self, tmp_path):
        """docker compose와 같은 규칙: -f로 파일을 지정하면 override를 자동으로 읽지 않는다."""
        base = _write(tmp_path / "docker-compose.yml")
        _write(tmp_path / "docker-compose.override.yml", "services:\n  app:\n    user: '1000'\n")

        discovered = collect_compose_projects(None, tmp_path)
        explicit = collect_compose_projects([base], tmp_path)
        assert discovered[0].override is not None and discovered[0].services["app"]["user"] == "1000"
        assert explicit[0].override is None and "user" not in explicit[0].services["app"]


class TestCollect:
    def test_explicit_directory_is_searched(self, tmp_path):
        _write(tmp_path / "deploy" / "compose.yaml")
        projects = collect_compose_projects([tmp_path / "deploy"], Path("/nonexistent"))
        assert len(projects) == 1

    def test_duplicates_are_removed(self, tmp_path):
        path = _write(tmp_path / "compose.yaml")
        assert len(collect_compose_projects([path, tmp_path, path], tmp_path)) == 1

    def test_collect_reports_missing_files_as_notice(self, tmp_path):
        context = collect(categories={"compose"}, search_root=tmp_path)
        assert context.compose == []
        assert any("compose 파일을 찾지 못했습니다" in n for n in context.notices)

    def test_collect_reports_parse_errors(self, tmp_path, compose_fixture):
        context = collect(categories={"compose"}, compose_paths=[compose_fixture("broken.yml")])
        assert len(context.errors) == 1 and "YAML 문법 오류" in context.errors[0]
        assert context.compose_projects == []

    def test_compose_scan_also_loads_daemon_for_cross_checks(self, tmp_path, monkeypatch):
        from dockguard.core import collector

        monkeypatch.setattr(collector, "find_daemon_config", lambda: None)
        context = collect(categories={"compose"}, search_root=tmp_path)
        assert context.daemon is not None
        # daemon 영역을 고르지 않았으므로 daemon.json 관련 안내는 띄우지 않는다
        assert not any("daemon.json" in n for n in context.notices)
