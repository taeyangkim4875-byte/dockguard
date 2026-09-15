"""룰의 근거(reference) 표기를 한 곳에서 관리한다.

CIS Docker Benchmark는 버전마다 항목 번호가 달라진다 (예: icc는 이전 버전에서 2.1, v1.6.0에서 2.2).
dockguard는 docker-bench-security가 따르는 **v1.6.0** 번호로 통일한다.
"""

CIS_BENCHMARK = "CIS Docker Benchmark v1.6.0"


def cis(section: str, title: str, *, related: bool = False) -> str:
    """CIS 근거 문자열. related=True면 직접 대응이 아닌 '연관 항목'임을 표시한다."""
    suffix = " (연관 항목)" if related else ""
    return f"{CIS_BENCHMARK} {section}{suffix} — {title}"


def best_practice(title: str) -> str:
    """CIS에 직접 대응 항목이 없는 실무 권고의 근거 문자열."""
    return f"실무 베스트 프랙티스 — {title}"


def short_reference(reference: str) -> str:
    """목록 표시용 짧은 근거 (예: 'CIS 2.2'). CIS 형식이 아니면 원문 그대로."""
    prefix = f"{CIS_BENCHMARK} "
    if reference.startswith("실무 베스트 프랙티스"):
        return "베스트 프랙티스"
    if not reference.startswith(prefix):
        return reference
    section = reference[len(prefix) :].split(" — ")[0]
    return f"CIS {section}"
