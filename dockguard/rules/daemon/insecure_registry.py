"""DAEMON-010: insecure-registry 미사용."""

from __future__ import annotations

import ipaddress
import re

from dockguard.core.context import DaemonConfig
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import cis
from dockguard.rules.daemon._base import DaemonRule, to_json


def is_loopback_registry(entry: str) -> bool:
    """localhost/127.0.0.0/8/::1 레지스트리인지. Docker는 이들을 원래 insecure로 허용한다."""
    value = re.sub(r"^[a-z]+://", "", entry.strip().lower())
    try:
        return ipaddress.ip_network(value, strict=False).is_loopback  # CIDR 표기 (예: 127.0.0.0/8)
    except ValueError:
        pass
    host = value.split("/")[0]
    if host.startswith("["):  # [::1]:5000
        host = host[1:].split("]")[0]
    elif host.count(":") == 1:  # host:port
        host = host.split(":")[0]
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@register
class InsecureRegistryRule(DaemonRule):
    id = "DAEMON-010"
    title = "insecure-registry 미사용"
    severity = Severity.HIGH
    reference = cis("2.5", "Ensure insecure registries are not used")
    recommended = "insecure-registries 비움, 미러는 https"

    no_autofix_reason = (
        "목록에서 빼는 즉시 해당 레지스트리의 pull/push가 실패합니다. "
        "레지스트리에 TLS를 먼저 적용한 뒤 수동으로 제거하세요."
    )

    why = """\
`insecure-registries`에 등록된 레지스트리와는 **TLS 인증서 검증 없이, 또는 평문 HTTP로** 통신한다.

- 네트워크 중간자(MITM)가 이미지 pull 응답을 가로채 **악성 코드가 심어진 이미지**로 바꿔치기할 수 있다. \
이 이미지는 운영 서버에서 그대로 실행된다 (공급망 공격).
- `docker login` 자격 증명이 평문으로 전송되어 탈취될 수 있고, 탈취된 계정으로 레지스트리의 이미지 \
자체를 오염시킬 수 있다.

"사내망이라 괜찮다"고 생각하기 쉽지만, 사내망에 한 번 들어온 공격자가 측면 이동하는 대표적인 경로다. \
`registry-mirrors`에 `http://` 주소를 쓰는 것도 같은 위험이 있다."""

    how_to_fix = """\
1. 레지스트리에 TLS를 적용한다. 사설 CA를 쓴다면 CA 인증서를 각 Docker 호스트에 배치하면 \
insecure 등록 없이 검증된 TLS로 통신할 수 있다.

```bash
sudo mkdir -p /etc/docker/certs.d/registry.internal:5000
sudo cp ca.crt /etc/docker/certs.d/registry.internal:5000/ca.crt
```

2. `/etc/docker/daemon.json`의 `insecure-registries`에서 해당 항목을 제거하고, `registry-mirrors`는 \
`https://` 주소로 바꾼다.

3. 이 설정은 데몬 재시작 없이 리로드로 반영된다. 이후 pull이 되는지 확인한다.

```bash
sudo systemctl reload docker
docker pull registry.internal:5000/myapp:1.0
```"""

    tradeoff = """\
- 목록에서 제거하는 즉시 해당 레지스트리의 pull/push가 실패한다 (`http: server gave HTTP response to \
HTTPS client` 또는 `x509: certificate signed by unknown authority`). **TLS를 먼저 준비하고 제거하라.**
- 사설 CA 인증서는 그 레지스트리를 쓰는 **모든 Docker 호스트와 CI 러너**에 배포해야 한다. 하나라도 \
빠지면 그 호스트의 배포가 멈춘다.
- 당장 제거가 어렵다면 최소한 이미지를 태그 대신 다이제스트(`image@sha256:...`)로 받아 변조를 감지하라.
- `localhost`/`127.0.0.1` 레지스트리는 Docker가 원래 insecure로 허용하므로 이 점검에서 제외된다."""

    learn_more = "https://docs.docker.com/engine/security/certificates/"

    def evaluate(self, daemon: DaemonConfig) -> list[Finding]:
        target = daemon.target_label
        registries = daemon.get("insecure-registries", [])
        mirrors = daemon.get("registry-mirrors", [])
        if not isinstance(registries, list) or not isinstance(mirrors, list):
            return [self.make(Status.WARN, target=target, current="insecure-registries/registry-mirrors가 배열이 아님")]

        insecure = [str(r) for r in registries if not is_loopback_registry(str(r))]
        http_mirrors = [str(m) for m in mirrors if str(m).lower().startswith("http://")]

        if insecure or http_mirrors:
            parts = []
            if insecure:
                parts.append(f"insecure-registries {to_json(insecure)}")
            if http_mirrors:
                parts.append(f"HTTP 미러 {to_json(http_mirrors)}")
            return [self.make(Status.FAIL, target=target, current=", ".join(parts))]

        if registries:
            return [self.make(Status.PASS, target=target, current=f"루프백 레지스트리만 등록 {to_json(registries)}")]
        return [self.make(Status.PASS, target=target, current="없음")]
