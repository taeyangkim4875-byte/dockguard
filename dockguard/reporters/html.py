"""HTML 리포트 — 한 파일로 완결되는 보고서 (외부 CSS · 폰트 · 스크립트 없음).

서버에서 만들어 메일로 보내거나 오프라인으로 열어도 그대로 보이도록, 모든 스타일과 스크립트를 인라인으로 넣는다.
룰 설명(why · how_to_fix · tradeoff)은 Markdown이므로 markdown-it으로 HTML로 바꾸되, **원문 HTML은 허용하지 않는다**
(dependencies.yaml의 reason 같은 사용자 입력이 섞일 수 있어 리포트가 XSS 경로가 되면 안 된다).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache

from jinja2 import Environment, PackageLoader, select_autoescape
from markdown_it import MarkdownIt
from markupsafe import Markup

from dockguard import __version__
from dockguard.core.context import ScanContext
from dockguard.core.models import Category, Finding, ScanResult, Severity, Status
from dockguard.core.scoring import MAX_SCORE, Score
from dockguard.knowledge.explanations import topic_for_rule

CATEGORY_INFO: dict[str, tuple[str, str]] = {
    Category.DAEMON.value: ("Docker 데몬 설정", "daemon.json"),
    Category.COMPOSE.value: ("docker-compose 파일", "compose.yaml"),
    Category.NETWORK.value: ("네트워크 · 서비스 의존성", "docker network"),
}
STATUS_LABELS = {Status.FAIL: "취약", Status.WARN: "주의", Status.SKIP: "건너뜀", Status.PASS: "통과"}
GAUGE_RADIUS = 52


@lru_cache(maxsize=1)
def _markdown() -> MarkdownIt:
    # html=False: 원문 HTML 태그는 이스케이프된다
    return MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")


def markdown_to_html(text: str) -> Markup:
    return Markup(_markdown().render(text or ""))  # noqa: S704 — html=False로 렌더링한 결과


@lru_cache(maxsize=1)
def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("dockguard", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["markdown"] = markdown_to_html
    return env


@dataclass
class CategoryGroup:
    key: str
    title: str
    source: str
    problems: list[Finding]
    others: list[Finding]  # 통과 · 건너뜀

    @property
    def counts(self) -> dict[str, int]:
        all_findings = self.problems + self.others
        return {s.value: sum(1 for f in all_findings if f.status == s) for s in Status}


def _group(findings: list[Finding]) -> list[CategoryGroup]:
    groups = []
    for key, (title, source) in CATEGORY_INFO.items():
        items = [f for f in findings if f.category == key]
        if not items:
            continue
        groups.append(
            CategoryGroup(
                key=key,
                title=title,
                source=source,
                problems=[f for f in items if f.is_problem],
                others=[f for f in items if not f.is_problem],
            )
        )
    return groups


def render_html(context: ScanContext, result: ScanResult, score: Score) -> str:
    findings = result.sorted_findings()
    # 같은 룰이 여러 번 나올 수 있으므로(NET-001, 프로젝트별 compose 룰) 순번을 붙인 앵커를 만든다
    anchors = {id(f): f"{f.rule_id.lower()}-{i}" for i, f in enumerate(findings, start=1)}
    circumference = 2 * math.pi * GAUGE_RADIUS
    template = _environment().get_template("report.html.j2")
    return template.render(
        version=__version__,
        context=context,
        result=result,
        score=score,
        max_score=MAX_SCORE,
        gauge_radius=GAUGE_RADIUS,
        gauge_circumference=f"{circumference:.2f}",
        gauge_offset=f"{circumference * (1 - score.value / MAX_SCORE):.2f}",
        groups=_group(findings),
        problems=[f for f in findings if f.is_problem],
        status_counts={s.value: n for s, n in result.status_counts().items()},
        severity_counts={s.value: n for s, n in result.failed_severity_counts().items()},
        severities=[s for s in Severity if s != Severity.INFO],
        status_labels={s.value: label for s, label in STATUS_LABELS.items()},
        topic_for_rule=topic_for_rule,
        anchor=lambda f: anchors[id(f)],
    )
