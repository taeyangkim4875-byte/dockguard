"""Collector(daemon.json 수집) 테스트."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from dockguard.core import collector
from dockguard.core.collector import (
    LINUX_DAEMON_CONFIG,
    collect,
    daemon_config_candidates,
    find_daemon_config,
    load_daemon_config,
)


def test_load_valid_file(daemon_fixture):
    config = load_daemon_config(daemon_fixture("secure.json"))
    assert config.exists and config.usable
    assert config.get("icc") is False
    assert config.has("log-opts")


def test_load_missing_file(tmp_path: Path):
    config = load_daemon_config(tmp_path / "daemon.json")
    assert not config.exists
    assert config.usable  # 파일 없음 = Docker 기본값으로 판단 가능
    assert config.data == {}
    assert config.target_label.endswith("(파일 없음)")


def test_load_invalid_json_reports_location(daemon_fixture):
    config = load_daemon_config(daemon_fixture("invalid.json"))
    assert config.exists and not config.usable
    assert "JSON 파싱 실패" in config.error
    assert "행" in config.error


def test_load_non_object_json(tmp_path: Path):
    path = tmp_path / "daemon.json"
    path.write_text('["icc", false]', encoding="utf-8")
    config = load_daemon_config(path)
    assert not config.usable
    assert "JSON 객체" in config.error


def test_load_empty_file_is_treated_as_no_settings(tmp_path: Path):
    path = tmp_path / "daemon.json"
    path.write_text("   \n", encoding="utf-8")
    config = load_daemon_config(path)
    assert config.exists and config.usable
    assert config.data == {}


def test_load_tolerates_utf8_bom(tmp_path: Path):
    path = tmp_path / "daemon.json"
    path.write_bytes(b'\xef\xbb\xbf{"icc": false}')
    assert load_daemon_config(path).get("icc") is False


def test_load_permission_denied_gives_friendly_message(tmp_path: Path, monkeypatch):
    path = tmp_path / "daemon.json"
    path.write_text("{}", encoding="utf-8")

    def _deny(self, *args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", _deny)
    config = load_daemon_config(path)
    assert not config.usable
    assert "sudo" in config.error


def test_find_daemon_config_returns_first_existing(tmp_path: Path):
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    second.write_text("{}", encoding="utf-8")
    first.write_text("{}", encoding="utf-8")
    assert find_daemon_config([tmp_path / "none.json", first, second]) == first


def test_find_daemon_config_none_when_absent(tmp_path: Path):
    assert find_daemon_config([tmp_path / "none.json"]) is None


@pytest.mark.parametrize(
    ("platform", "expected_suffix"),
    [
        ("linux", None),  # /etc/docker/daemon.json이 최우선
        ("darwin", Path(".docker") / "daemon.json"),
        ("win32", Path(".docker") / "daemon.json"),
    ],
)
def test_daemon_config_candidates_per_platform(monkeypatch, platform, expected_suffix):
    monkeypatch.setattr(sys, "platform", platform)
    candidates = daemon_config_candidates()
    if expected_suffix is None:
        assert candidates[0] == LINUX_DAEMON_CONFIG
        assert any("docker" in str(p) and ".config" in str(p) for p in candidates)  # rootless
    else:
        assert str(candidates[0]).endswith(str(expected_suffix))


def test_collect_with_explicit_path(daemon_fixture):
    context = collect(categories={"daemon"}, daemon_config_path=daemon_fixture("secure.json"))
    assert context.categories == {"daemon"}
    assert context.daemon is not None and context.daemon.exists
    assert context.notices == []
    assert context.hostname


def test_collect_auto_detect_finds_file(monkeypatch, daemon_fixture):
    monkeypatch.setattr(collector, "find_daemon_config", lambda: daemon_fixture("insecure.json"))
    context = collect(categories={"daemon"})
    assert context.daemon.get("icc") is True
    assert context.notices == []


def test_collect_auto_detect_missing_adds_notice(monkeypatch):
    monkeypatch.setattr(collector, "find_daemon_config", lambda: None)
    context = collect(categories={"daemon"})
    assert context.daemon is not None
    assert not context.daemon.exists
    assert any("찾지 못했습니다" in n for n in context.notices)


def test_collect_skips_daemon_when_not_requested():
    context = collect(categories={"compose"})
    assert context.daemon is None


def test_collect_defaults_to_all_categories(monkeypatch):
    monkeypatch.setattr(collector, "find_daemon_config", lambda: None)
    context = collect()
    assert context.categories == {"daemon", "compose", "network"}
