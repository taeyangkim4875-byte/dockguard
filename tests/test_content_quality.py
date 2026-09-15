"""설명 텍스트(Markdown) 품질 검사 — 모든 룰과 학습 주제에 대해 자동으로 확인한다.

한국어 Markdown에서 흔한 함정: `**강조(괄호)**에`처럼 닫는 `**` 앞이 문장부호이고 뒤가 한글이면
CommonMark 규칙상 강조로 인식되지 않아 `**`가 그대로 보인다. 사람이 눈으로 찾기 어려워 테스트로 막는다.
"""

from __future__ import annotations

import re

import pytest

from dockguard.core.rule import registered_rule_classes
from dockguard.knowledge.explanations import EXPLANATIONS, Topic
from dockguard.reporters.html import markdown_to_html
from dockguard.rules import load_all_rules

load_all_rules()

RULE_TEXT_FIELDS = ("why", "how_to_fix", "tradeoff")
_TAGS = re.compile(r"<[^>]+>")
_CODE = re.compile(r"<code[^>]*>.*?</code>", re.S)


def _texts():
    for cls in registered_rule_classes():
        for name in RULE_TEXT_FIELDS:
            text = getattr(cls, name, "")
            if isinstance(text, str) and text:
                yield f"{cls.id}.{name}", text
    for topic in EXPLANATIONS.values():
        for name, _ in Topic.SECTIONS:
            yield f"learn:{topic.key}.{name}", getattr(topic, name)


ALL_TEXTS = list(_texts())


@pytest.mark.parametrize(("where", "text"), ALL_TEXTS, ids=[w for w, _ in ALL_TEXTS])
def test_no_unrendered_emphasis(where, text):
    html = str(markdown_to_html(text))
    visible = _TAGS.sub("", _CODE.sub("", html))  # 코드 안의 **는 의도된 것일 수 있으므로 제외
    leftovers = [m.start() for m in re.finditer(r"\*\*", visible)]
    snippet = visible[max(0, leftovers[0] - 30) : leftovers[0] + 30] if leftovers else ""
    assert not leftovers, f"{where}: 강조가 렌더링되지 않음 → …{snippet}…"


def test_every_rule_has_explanations():
    for cls in registered_rule_classes():
        for name in RULE_TEXT_FIELDS:
            assert getattr(cls, name, ""), f"{cls.id}.{name}이 비어 있습니다"
