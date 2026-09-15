"""compose 룰이 쓰는 보안 지식 상수. 하드코딩을 룰 파일에서 분리해 한 곳에서 관리한다."""

from __future__ import annotations

import re

# 컨테이너에 주면 위험한 Linux capability와 그 이유 (COMPOSE-010)
DANGEROUS_CAPABILITIES: dict[str, str] = {
    "ALL": "모든 capability — 사실상 privileged와 같음",
    "SYS_ADMIN": "mount·네임스페이스 조작 등 '사실상 root', 컨테이너 탈출에 가장 많이 쓰임",
    "SYS_MODULE": "커널 모듈 로드 = 호스트 커널 장악",
    "SYS_PTRACE": "다른 프로세스 메모리 읽기·코드 주입",
    "SYS_RAWIO": "raw I/O 포트·장치 메모리 직접 접근",
    "DAC_READ_SEARCH": "파일 권한 우회 읽기 (open_by_handle_at 기반 'Shocker' 탈출 공격)",
    "NET_ADMIN": "네트워크 설정·iptables 조작, 트래픽 가로채기",
    "SYS_BOOT": "호스트 재부팅",
    "MAC_ADMIN": "AppArmor/SELinux 정책 변경",
    "BPF": "eBPF 프로그램 로드 (커널 공격 표면)",
}

# 환경변수 이름을 '_'로 나눈 토큰 중 하나라도 이것이면 시크릿으로 본다 (COMPOSE-005)
SECRET_NAME_TOKENS: frozenset[str] = frozenset(
    {"PASSWORD", "PASSWD", "PASS", "PWD", "SECRET", "TOKEN", "APIKEY", "CREDENTIAL", "CREDENTIALS", "PRIVATEKEY"}
)
# 연속된 두 토큰이 이 조합이면 시크릿 (예: API_KEY, AWS_SECRET_ACCESS_KEY)
SECRET_NAME_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {("API", "KEY"), ("PRIVATE", "KEY"), ("ACCESS", "KEY"), ("SECRET", "KEY"), ("ENCRYPTION", "KEY"), ("SIGNING", "KEY")}
)
# 시크릿 토큰과 함께 있으면 '시크릿 값'이 아니라 '시크릿 관련 설정'으로 본다
# (예: PASSWORD_MIN_LENGTH, TOKEN_URL, JWT_TOKEN_TTL, SECRET_KEY_PATH)
NON_SECRET_NAME_TOKENS: frozenset[str] = frozenset(
    {
        "TTL", "EXPIRY", "EXPIRE", "EXPIRES", "EXPIRATION", "LIFETIME", "TIMEOUT",
        "LENGTH", "LEN", "MIN", "MAX", "SIZE", "ENABLED", "ENABLE", "DISABLED", "REQUIRED",
        "URL", "URI", "HOST", "PORT", "PATH", "DIR", "FILE",
        "TYPE", "MODE", "POLICY", "HEADER", "ALGORITHM", "ALG", "ISSUER", "AUDIENCE",
    }
)  # fmt: skip
# 셸이 쓰는 작업 디렉터리 변수 — PWD 토큰과 겹친다
NON_SECRET_NAMES: frozenset[str] = frozenset({"PWD", "OLDPWD"})
# 값 대신 파일 경로를 넘기는 Docker secrets 관례 (예: POSTGRES_PASSWORD_FILE) — 안전한 패턴
SECRET_FILE_SUFFIX = "_FILE"

# compose 변수 참조: `${VAR}`, `${VAR:-기본값}`, `$VAR` (`$$`는 리터럴 `$` 이스케이프라 제외)
VARIABLE_PATTERN = re.compile(r"(?<!\$)\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)")
# `${VAR:-기본값}` / `${VAR-기본값}` — 기본값이 파일에 평문으로 남는다
DEFAULT_VALUE_PATTERN = re.compile(r"\$\{[^}:\-]+:?-([^}]*)\}")

# 엔트리포인트가 root로 시작한 뒤 gosu 등으로 일반 사용자로 권한을 내리는 공식 이미지 (COMPOSE-002)
# 이 이미지들은 user:를 지정하지 않아도 메인 프로세스는 일반 사용자로 돈다.
PRIVILEGE_DROPPING_IMAGES: frozenset[str] = frozenset({"postgres", "mysql", "mariadb", "redis", "mongo"})

# docker.sock 경로 (COMPOSE-004)
DOCKER_SOCKET_NAMES: tuple[str, ...] = ("docker.sock",)

# 웹 서버가 정당하게 쓰는 특권 포트 (COMPOSE-012)
STANDARD_WEB_PORTS: frozenset[int] = frozenset({80, 443})
PRIVILEGED_PORT_LIMIT = 1024


def is_secret_name(name: str) -> bool:
    """환경변수 이름이 비밀번호/토큰/키처럼 보이는지."""
    upper = name.upper()
    if upper in NON_SECRET_NAMES or upper.endswith(SECRET_FILE_SUFFIX):
        return False
    tokens = [t for t in re.split(r"[_\-.]", upper) if t]
    if any(t in NON_SECRET_NAME_TOKENS for t in tokens):
        return False
    if any(t in SECRET_NAME_TOKENS for t in tokens):
        return True
    return any(pair in SECRET_NAME_PAIRS for pair in zip(tokens, tokens[1:]))
