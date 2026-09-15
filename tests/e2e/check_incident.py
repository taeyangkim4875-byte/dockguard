"""실제 Docker E2E 검증 — CI에서 reproduce.sh로 만든 사고 상태를 dockguard가 제대로 잡는지 확인한다.

    python tests/e2e/check_incident.py report.json --expect broken --source "Docker SDK"
    python tests/e2e/check_incident.py report.json --expect recovered

pytest 수집 대상이 아니다 (실제 Docker가 필요하므로 CI의 e2e 잡에서만 실행).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND = "backend-container → rabbitmq:5672"
MANAGER = "service-manager → rabbitmq:5672"
WORKER = "report-worker → redis:6379"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--expect", choices=["broken", "recovered"], required=True)
    parser.add_argument("--source", help="기대하는 수집 경로 (Docker SDK / docker CLI)")
    args = parser.parse_args()

    data = json.loads(args.report.read_text(encoding="utf-8"))
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        print(("  ✓ " if condition else "  ✗ ") + message)
        if not condition:
            failures.append(message)

    docker = data["sources"]["docker"] or {}
    check(bool(docker.get("available")), f"Docker 상태 수집 성공 ({docker})")
    if args.source:
        check(docker.get("source") == args.source, f"수집 경로 = {args.source} (실제: {docker.get('source')})")

    net001 = {f["target"].split(" (")[0]: f for f in data["findings"] if f["rule_id"] == "NET-001"}
    net004 = next((f for f in data["findings"] if f["rule_id"] == "NET-004"), {})

    def expect(label: str, status: str, contains: str = "") -> None:
        finding = net001.get(label)
        actual = finding["status"] if finding else "없음"
        detail = finding["current_value"] if finding else ""
        ok = finding is not None and actual == status and contains in detail
        check(ok, f"NET-001 {label} → {status}{f' ({contains})' if contains else ''} | 실제: {actual} {detail}")

    if args.expect == "broken":
        expect(BACKEND, "fail", "공유 네트워크 없음")
        expect(WORKER, "fail", "실행 중이 아님")
        expect(MANAGER, "pass")
        check(net004.get("status") == "fail" and "5672" in net004.get("current_value", ""), f"NET-004 5672 외부 노출 탐지 | {net004.get('current_value')}")
    else:
        for label in (BACKEND, WORKER, MANAGER):
            expect(label, "pass")

    print(f"\n점수 {data['score']['value']}/100 ({data['score']['grade']}) · 결과: {'실패 ' + str(len(failures)) + '건' if failures else '통과'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
