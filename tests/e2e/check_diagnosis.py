"""실제 Docker E2E 검증 — `dockguard diagnose connectivity`의 JSON 결과를 확인한다.

    python tests/e2e/check_diagnosis.py diagnosis.json --expect isolated
    python tests/e2e/check_diagnosis.py diagnosis.json --expect address
    python tests/e2e/check_diagnosis.py diagnosis.json --expect connected

`--networks A,B` 로 근거에 나와야 할 네트워크 이름을 지정한다 (기본: 정전 사고 예시).

pytest 수집 대상이 아니다 (실제 Docker가 필요하므로 CI의 e2e 잡에서만 실행).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--expect", choices=["isolated", "address", "connected"], required=True)
    parser.add_argument(
        "--networks",
        default="bridge,messaging_mq-net",
        help="3단계 근거에 나와야 할 네트워크 이름 (쉼표 구분)",
    )
    args = parser.parse_args()

    data = json.loads(args.report.read_text(encoding="utf-8"))
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        print(("  ✓ " if condition else "  ✗ ") + message)
        if not condition:
            failures.append(message)

    steps = {s["name"].split(".")[0]: s for s in data["steps"]}
    check(list(steps) == ["1", "2", "3", "4", "5"], f"5단계를 순서대로 검사 (실제: {list(steps)})")
    check(all(s["detail"] for s in data["steps"]), "모든 단계가 검사 결과를 남김")

    if args.expect == "isolated":
        check(data["resolved"] is True, "근본 원인을 찾았는가")
        check("네트워크 격리" in data["root_cause"], f"근본 원인 = 네트워크 격리 (실제: {data['root_cause']})")
        check(steps["1"]["status"] == "pass", "1단계(컨테이너 실행) 통과")
        check(steps["2"]["status"] == "pass", "2단계(포트) 통과")
        check(steps["3"]["status"] == "fail", "3단계(공유 네트워크) 실패")
        check("docker network connect" in data["fix"], "해결책에 docker network connect 안내")
        check("재기동 시 풀린다" in data["tradeoff"], "부작용(임시 연결은 재기동 시 풀림) 안내")
        evidence = " ".join(data["evidence"])
        expected_networks = [n.strip() for n in args.networks.split(",") if n.strip()]
        check(
            all(n in evidence for n in expected_networks),
            f"근거에 양쪽 네트워크 목록 {expected_networks} (실제: {evidence})",
        )
    elif args.expect == "address":
        # 네트워크를 연결한 뒤 — 남아 있던 접속 주소 문제가 근본 원인으로 올라와야 한다
        check(data["resolved"] is True, "아직 남은 원인을 찾았는가")
        check(steps["3"]["status"] == "pass", f"3단계(공유 네트워크) 통과 (실제: {steps['3']['detail']})")
        check(steps["4"]["status"] == "pass", f"4단계(icc) 통과 (실제: {steps['4']['detail']})")
        check(steps["5"]["status"] == "fail", f"5단계(접속 주소) 실패 (실제: {steps['5']['detail']})")
        check("127.0.0.1" in data["root_cause"], f"근본 원인 = 접속 주소 (실제: {data['root_cause']})")
    else:
        check(data["resolved"] is False, f"네트워크 레벨 원인 없음 (실제: {data['root_cause']})")
        check(steps["3"]["status"] == "pass", f"3단계(공유 네트워크) 통과 (실제: {steps['3']['detail']})")
        check(steps["4"]["status"] == "pass", f"4단계(icc) 통과 (실제: {steps['4']['detail']})")
        check(bool(data["next_checks"]), "다음으로 확인할 것 안내")

    print(f"\n결과: {'실패 ' + str(len(failures)) + '건' if failures else '통과'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
