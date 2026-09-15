"""DAEMON-007: daemon.json 파일 소유권 / 권한."""

from __future__ import annotations

from dockguard.core.context import DaemonConfig
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import DaemonRule

# "644 or more restrictive": 이 비트 밖의 권한이 하나라도 있으면 위반
MAX_ALLOWED_MODE = 0o644


@register
class DaemonFilePermissionsRule(DaemonRule):
    id = "DAEMON-007"
    title = "daemon.json 파일 권한"
    severity = Severity.MEDIUM
    reference = cis(
        "3.17 / 3.18",
        "Ensure that daemon.json file ownership is set to root:root / permissions are set to 644 or more restrictive",
    )
    recommended = "소유자 root:root, 권한 0644 이하"
    requires_content = False  # 내용 파싱에 실패해도 권한은 점검할 수 있다

    no_autofix_reason = "파일 권한은 아래 chown/chmod 명령으로 직접 수정하세요 (내용 변경이 아니라 자동 수정 대상에서 제외)."

    why = """\
`daemon.json`은 root 권한으로 도는 Docker 데몬의 동작을 결정한다. 이 파일을 수정할 수 있는 사람은 \
사실상 **호스트 root 권한을 가진 것과 같다.** 예를 들어:

- `"hosts": ["tcp://0.0.0.0:2375"]`를 추가해 **인증 없는 원격 Docker API**를 연다 → 네트워크의 누구나 \
컨테이너를 띄워 호스트를 장악할 수 있다.
- `"seccomp-profile": "unconfined"`, `"insecure-registries"` 등을 넣어 보안 기능을 조용히 끈다.

이런 변경은 다음 데몬 재시작 때 조용히 반영된다. 따라서 소유자는 `root:root`, 권한은 `0644` 이하 \
(root만 쓰기 가능)여야 한다. 그룹·기타 사용자에게 쓰기 권한이 있거나 일반 사용자가 소유자면, 그 계정 \
하나가 탈취됐을 때 호스트 전체가 넘어간다."""

    how_to_fix = """\
```bash
sudo chown root:root /etc/docker/daemon.json
sudo chmod 644 /etc/docker/daemon.json
ls -l /etc/docker/daemon.json    # -rw-r--r-- 1 root root ...
```

상위 디렉터리도 함께 점검한다 (CIS 3.5 / 3.6).

```bash
sudo chown root:root /etc/docker
sudo chmod 755 /etc/docker
```"""

    tradeoff = """\
- 권한 변경 자체의 부작용은 거의 없다. Docker 데몬은 root로 실행되므로 0644에서도 정상적으로 읽는다.
- 배포 자동화(Ansible, CI 스크립트 등)가 일반 계정으로 이 파일을 직접 쓰고 있었다면 실패하게 된다. \
`sudo`/`become`을 쓰도록 바꿔라.
- rootless 모드나 Docker Desktop의 설정 파일(홈 디렉터리 아래)은 해당 사용자 소유가 정상이다. \
이 경우 dockguard는 소유자 대신 쓰기 권한만 점검한다."""

    learn_more = "https://docs.docker.com/engine/daemon/"

    def evaluate(self, daemon: DaemonConfig) -> list[Finding]:
        target = daemon.target_label
        if not daemon.exists:
            return [self.make(Status.SKIP, target=target, current="파일 없음 — 새로 만들 때 root:root, 0644로 생성하세요")]
        if daemon.stat is None:
            return [self.make(Status.SKIP, target=target, current="POSIX 권한 정보 없음 (Windows 등에서는 점검 불가)")]

        st = daemon.stat
        current = f"소유자 {st.uid}:{st.gid}, 권한 {st.mode:04o}"
        problems: list[str] = []

        if not daemon.user_scoped and (st.uid != 0 or st.gid != 0):
            problems.append("소유자가 root:root가 아님")
        if st.mode & 0o022:
            problems.append("그룹/기타 사용자 쓰기 가능")
        elif st.mode & ~MAX_ALLOWED_MODE:
            problems.append("0644보다 넓은 권한")

        if problems:
            return [self.make(Status.FAIL, target=target, current=f"{current} — {', '.join(problems)}")]
        return [self.make(Status.PASS, target=target, current=current)]
