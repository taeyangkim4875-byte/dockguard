"""JSON 리포트 — CI/CD 파이프라인이나 다른 도구와 연동하기 위한 구조화된 출력.

스키마는 `schema_version`으로 관리한다. 필드를 지우거나 의미를 바꾸면 버전을 올린다.
"""

from __future__ import annotations

import json
from typing import Any

from dockguard import __version__
from dockguard.core.context import ScanContext
from dockguard.core.models import ScanResult, Severity, Status
from dockguard.core.scoring import MAX_SCORE, Score
from dockguard.knowledge.explanations import topic_for_rule

SCHEMA_VERSION = 1


def build_report(context: ScanContext, result: ScanResult, score: Score) -> dict[str, Any]:
    status_counts = result.status_counts()
    severity_counts = result.failed_severity_counts()
    findings = []
    for finding in result.sorted_findings():
        data = finding.to_dict()
        topic = topic_for_rule(finding.rule_id)
        data["learn_topic"] = topic.key if topic else None
        findings.append(data)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "dockguard", "version": __version__},
        "host": context.hostname,
        "scanned_at": context.scanned_at.isoformat(),
        "categories": sorted(context.categories),
        "score": {"value": score.value, "max": MAX_SCORE, "grade": score.grade, "deducted": score.deducted},
        "summary": {
            "rules_run": result.rules_run,
            "status": {s.value: status_counts[s] for s in Status},
            "failed_by_severity": {s.value: severity_counts[s] for s in Severity},
        },
        "sources": {
            "daemon_config": str(context.daemon.path) if context.daemon else None,
            "compose_files": [p.label for p in context.compose or []],
            "docker": (
                {"available": context.docker.available, "source": context.docker.source, "error": context.docker.error}
                if context.docker
                else None
            ),
            "dependency_file": str(context.dependency_file) if context.dependency_file else None,
            "ruleset": (
                {"path": str(context.ruleset_path), "summary": context.ruleset_summary} if context.ruleset_path else None
            ),
        },
        "notices": list(context.notices),
        "collection_errors": list(context.errors),
        "rule_errors": [{"rule_id": e.rule_id, "message": e.message} for e in result.errors],
        "findings": findings,
    }


def render_json(context: ScanContext, result: ScanResult, score: Score) -> str:
    return json.dumps(build_report(context, result, score), ensure_ascii=False, indent=2) + "\n"
