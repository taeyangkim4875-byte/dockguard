"""보안 학습 콘텐츠(knowledge/explanations.py)와 `dockguard learn` 테스트."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from dockguard.cli import app
from dockguard.core.rule import registered_rule_classes
from dockguard.knowledge.explanations import EXPLANATIONS, Topic, get_topic, suggest_topics, topic_for_rule
from dockguard.rules import load_all_rules

runner = CliRunner()

# CLAUDE.md §6에서 요구하는 최소 주제
REQUIRED_TOPICS = {
    "icc",
    "rootless",
    "userns-remap",
    "seccomp",
    "capabilities",
    "docker-sock",
    "lateral-movement",
    "privileged",
    "network-isolation",
    "secrets-management",
}


def test_required_topics_exist():
    assert REQUIRED_TOPICS <= set(EXPLANATIONS)


@pytest.mark.parametrize("topic", list(EXPLANATIONS.values()), ids=lambda t: t.key)
def test_topic_content_is_substantial(topic: Topic):
    assert topic.title and topic.summary
    assert "`" not in topic.summary and "**" not in topic.summary  # 요약은 일반 텍스트로 표시된다
    for field_name, _ in Topic.SECTIONS:
        assert len(getattr(topic, field_name)) > 120, f"{topic.key}.{field_name}이 너무 짧습니다"


@pytest.mark.parametrize("topic", list(EXPLANATIONS.values()), ids=lambda t: t.key)
def test_related_rules_are_real(topic: Topic):
    load_all_rules()
    registered = {cls.id for cls in registered_rule_classes()}
    assert topic.related_rules
    assert set(topic.related_rules) <= registered


def test_aliases_are_unique_and_not_topic_keys():
    aliases = [a for t in EXPLANATIONS.values() for a in t.aliases]
    assert len(aliases) == len(set(aliases))
    assert not set(aliases) & set(EXPLANATIONS)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("icc", "icc"),
        ("ICC", "icc"),
        ("docker.sock", "docker-sock"),
        ("userns", "userns-remap"),
        ("ufw", "port-exposure"),
        ("DAEMON-001", "icc"),
        ("compose-004", "docker-sock"),
        ("NET-001", "network-isolation"),
    ],
)
def test_get_topic(query, expected):
    assert get_topic(query).key == expected


def test_unknown_topic():
    assert get_topic("kubernetes") is None
    assert "seccomp" in suggest_topics("seccom")


def test_topic_for_rule_prefers_closest_topic():
    # DAEMON-001은 icc 주제의 첫 관련 룰이다
    assert topic_for_rule("DAEMON-001").key == "icc"
    assert topic_for_rule("DAEMON-004") is None


# ============================================================================ CLI


def test_learn_lists_topics():
    result = runner.invoke(app, ["learn"], env={"COLUMNS": "160"})
    assert result.exit_code == 0
    for key in REQUIRED_TOPICS:
        assert key in result.output


def test_learn_topic_shows_all_sections():
    result = runner.invoke(app, ["learn", "icc"], env={"COLUMNS": "160"})
    assert result.exit_code == 0
    for _, heading in Topic.SECTIONS:
        assert heading in result.output
    assert "DAEMON-001" in result.output


def test_learn_by_rule_id():
    result = runner.invoke(app, ["learn", "COMPOSE-004"], env={"COLUMNS": "160"})
    assert result.exit_code == 0
    assert "docker.sock의 위험" in result.output


def test_learn_unknown_topic_suggests():
    result = runner.invoke(app, ["learn", "seccom"], env={"COLUMNS": "160"})
    assert result.exit_code == 2
    assert "seccomp" in result.output


def test_explain_links_to_learn(daemon_fixture):
    result = runner.invoke(
        app,
        ["scan", "-c", "daemon", "--daemon-config", str(daemon_fixture("insecure.json")), "--explain"],
        env={"COLUMNS": "160"},
    )
    assert result.exit_code == 0
    assert "dockguard learn icc" in result.output
