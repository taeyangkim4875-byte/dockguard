"""컨테이너 A가 컨테이너 B에 연결되지 않을 때의 원인 추적 (diagnose connectivity).

이 진단 트리는 dockguard 제작 배경이 된 실제 장애를, 그때 손으로 밟았던 순서 그대로 옮긴 것이다.
정전으로 서버가 재부팅된 뒤 백엔드가 RabbitMQ에서 메시지를 소비하지 못했고, 원인을 찾기까지
며칠이 걸렸다. 그때 확인한 순서가 곧 아래 단계다.

    1. 두 컨테이너가 살아 있는가          (docker ps — 재부팅 후 안 올라온 컨테이너가 있었다)
    2. 상대가 그 포트를 여는가            (포트·방화벽을 의심했다)
    3. 둘이 같은 네트워크에 있는가        ← 진짜 원인이 여기 있었다
    4. 그 네트워크에서 통신이 허용되는가  (daemon.json의 icc: false)
    5. 상대를 어떤 주소로 찾고 있는가     (호스트 외부 IP를 쓰고 있었다)

'연결이 안 된다'는 증상에서 사람이 가장 늦게 의심하는 것이 3번(네트워크 격리)인데,
컨테이너 환경에서는 가장 흔한 원인이다. 그래서 이 진단은 그 확인을 자동으로, 앞쪽에서 해 준다.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
from typing import Iterator

from dockguard.core.context import DEFAULT_BRIDGE, ContainerInfo, DockerRuntime, ScanContext
from dockguard.core.models import Status
from dockguard.diagnostics.base import DockerDiagnosis
from dockguard.diagnostics.models import DiagnosisStep

# 접속 대상 주소가 들어 있을 만한 환경변수 키 (대문자 부분 일치)
HOST_KEY_HINTS = ("HOST", "URL", "URI", "ADDR", "ENDPOINT", "SERVER", "BROKER", "DSN", "CONNECTION", "NODE")
# 값을 화면에 띄우면 안 되는 키 (URL류는 자격증명만 가린 뒤 보여준다)
SECRET_KEY_HINTS = ("PASS", "SECRET", "TOKEN", "CREDENTIAL", "PRIVATE")
# 컨테이너 안에서 이 주소들은 '자기 자신'을 가리킨다
SELF_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

_URL_RE = re.compile(r"^(?P<scheme>[a-zA-Z][\w+.-]*)://(?P<rest>.*)$")


# --------------------------------------------------------------------------- 주소 해석 헬퍼


def mask_credentials(value: str) -> str:
    """값에 섞인 비밀번호를 가린다 (예: amqp://user:pa55w0rd@rabbitmq:5672 → amqp://user:***@rabbitmq:5672)."""
    return re.sub(r"(//[^/:@\s]+):([^@/\s]+)@", r"\1:***@", value)


def extract_host(value: str) -> str | None:
    """설정값에서 호스트 부분만 뽑는다 (URL, host:port, host 모두 지원)."""
    value = value.strip()
    if not value:
        return None
    match = _URL_RE.match(value)
    if match:
        rest = match.group("rest").split("/")[0].split("?")[0]
        value = rest.rsplit("@", 1)[-1]  # user:pass@ 제거
    if value.startswith("["):  # [::1]:6379 같은 IPv6 표기
        return value[1 : value.find("]")] if "]" in value else value[1:]
    # host:port — 포트가 숫자일 때만 잘라낸다 (IPv6 원문을 망가뜨리지 않도록)
    head, sep, tail = value.rpartition(":")
    if sep and head and tail.isdigit():
        value = head
    return value or None


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def address_candidates(container: ContainerInfo, target: ContainerInfo, target_ref: str) -> list[tuple[str, str]]:
    """상대 접속 주소로 보이는 환경변수만 고른다 (비밀번호 계열 키는 아예 읽지 않는다).

    키 이름이 주소처럼 보이거나(HOST/URL/...), 값이 상대 컨테이너·서비스 이름을 담고 있으면 후보로 본다.
    """
    names = {n.lower() for n in (target.name, target.compose_service or "", target_ref) if n}
    found: list[tuple[str, str]] = []
    for key, value in container.env.items():
        upper = key.upper()
        if any(hint in upper for hint in SECRET_KEY_HINTS) and not _URL_RE.match(value.strip()):
            continue
        looks_like_address = any(hint in upper for hint in HOST_KEY_HINTS)
        mentions_target = any(name in value.lower() for name in names)
        if looks_like_address or mentions_target:
            found.append((key, value))
    return found


def resolve(runtime: DockerRuntime, ref: str) -> list[ContainerInfo]:
    """컨테이너 이름 · ID · compose 서비스 이름으로 컨테이너를 찾는다 (스케일된 서비스는 여러 개)."""
    exact = runtime.find_container(ref)
    if exact is not None:
        return [exact]
    return [c for c in runtime.containers if c.compose_service == ref]


def similar_names(runtime: DockerRuntime, ref: str) -> list[str]:
    """오타·이름 변경을 잡아 주기 위한 비슷한 컨테이너 이름."""
    names = [c.name for c in runtime.containers]
    return difflib.get_close_matches(ref, names, n=3, cutoff=0.5) or names[:5]


def listening_ports(container: ContainerInfo) -> set[int]:
    """이미지가 선언한 EXPOSE + 호스트에 공개된 포트."""
    declared = {int(p.split("/")[0]) for p in container.exposed_ports if p.split("/")[0].isdigit()}
    return declared | {p.container_port for p in container.ports}


# --------------------------------------------------------------------------- 진단


class ConnectivityDiagnosis(DockerDiagnosis):
    """'A가 B에 연결되지 않는다'의 원인을 네트워크 관점에서 추적한다."""

    id = "connectivity"
    title = "컨테이너 연결 실패"

    def __init__(self, source_ref: str, target_ref: str, port: int | None = None) -> None:
        self.source_ref = source_ref
        self.target_ref = target_ref
        self.port = port

    # ------------------------------------------------------------------ 메타

    def symptom(self, context: ScanContext) -> str:
        where = f" {self.port}번 포트" if self.port else ""
        return f"`{self.source_ref}`에서 `{self.target_ref}`{where}로 연결되지 않는다"

    def target_label(self, context: ScanContext) -> str:
        return f"{self.source_ref} → {self.target_ref}" + (f":{self.port}" if self.port else "")

    def next_checks(self, context: ScanContext) -> list[str]:
        tgt, src = self.target_ref, self.source_ref
        port = self.port or "<포트>"
        return [
            f'애플리케이션이 정말 그 포트를 듣고 있는지: docker exec {tgt} sh -c "netstat -tlnp 2>/dev/null || ss -tlnp"',
            f'컨테이너 안에서 실제로 닿는지: docker exec {src} sh -c "getent hosts {tgt}; nc -zv {tgt} {port}"',
            f"인증 실패(비밀번호 · 계정 · vhost)는 이 진단이 잡지 못한다: docker logs --tail 50 {tgt}",
            "대상 서비스가 컨테이너 안에서 127.0.0.1에만 바인딩됐는지 (설정의 bind 주소를 0.0.0.0으로)",
            "호스트 방화벽 · iptables DOCKER-USER 체인에 차단 규칙이 있는지: sudo iptables -L DOCKER-USER -n",
            "예방 점검도 함께: dockguard scan --category network --explain",
        ]

    # ------------------------------------------------------------------ 진단 트리

    def steps(self, context: ScanContext) -> Iterator[DiagnosisStep]:
        runtime = self.runtime(context)

        step, src, tgt = self._step_containers(runtime)
        yield step
        if src is None or tgt is None:
            return  # 컨테이너가 없으면 뒤 단계는 검사할 수 없다

        yield self._step_port(tgt)
        shared, step_network = self._step_shared_network(runtime, src, tgt)
        yield step_network
        yield self._step_icc(runtime, context, src, tgt, shared)
        yield self._step_address(src, tgt)

    # -------------------------------------------------- 1. 컨테이너 존재 · 실행 여부

    def _step_containers(
        self, runtime: DockerRuntime
    ) -> tuple[DiagnosisStep, ContainerInfo | None, ContainerInfo | None]:
        name = "1. 두 컨테이너가 존재하고 실행 중인가?"
        picked: dict[str, ContainerInfo] = {}
        missing: list[str] = []
        evidence: list[str] = []

        for ref in (self.source_ref, self.target_ref):
            matches = resolve(runtime, ref)
            if not matches:
                missing.append(ref)
                continue
            chosen = next((c for c in matches if c.running), matches[0])  # 스케일된 서비스는 실행 중인 것 우선
            picked[ref] = chosen
            extra = f" (같은 서비스 컨테이너 {len(matches)}개 중 {chosen.name} 기준)" if len(matches) > 1 else ""
            evidence.append(
                f"{ref} → {chosen.name}: {chosen.state} "
                f"(image: {chosen.image or '?'}, restart: {chosen.restart_policy}){extra}"
            )

        if missing:
            evidence += [f"{ref}: 이 호스트에 해당 컨테이너가 없음" for ref in missing]
            evidence.append(f"호스트에 있는 비슷한 이름: {', '.join(similar_names(runtime, missing[0]))}")
            return (
                self.step(
                    name,
                    Status.FAIL,
                    f"컨테이너를 찾을 수 없음: {', '.join(missing)}",
                    evidence=evidence,
                    cause=f"`{', '.join(missing)}` 컨테이너가 이 호스트에 없다",
                    fix=MISSING_CONTAINER_FIX,
                    tradeoff=(
                        "`docker compose up -d`는 설정이 바뀐 컨테이너를 재생성한다. 이름 있는 볼륨은 유지되지만, "
                        "익명 볼륨에만 있던 데이터(예: 손으로 만든 메시지큐 계정)는 사라질 수 있으니 먼저 "
                        "`docker volume ls`로 볼륨부터 확인하라."
                    ),
                ),
                picked.get(self.source_ref),
                picked.get(self.target_ref),
            )

        src, tgt = picked[self.source_ref], picked[self.target_ref]
        stopped = [c for c in (src, tgt) if not c.running]
        if stopped:
            c = stopped[0]
            no_policy = c.restart_policy in ("", "no")
            cause = f"`{c.name}` 컨테이너가 멈춰 있다 ({c.state})"
            if no_policy:
                cause += " — 재시작 정책이 없어 재부팅 후 자동으로 올라오지 않았다"
            return (
                self.step(
                    name,
                    Status.FAIL,
                    f"{c.name}가 실행 중이 아님 ({c.state}, restart: {c.restart_policy})",
                    evidence=evidence,
                    cause=cause,
                    fix=(
                        "```bash\n"
                        f"docker logs --tail 50 {c.name}      # 왜 멈췄는지 먼저 확인\n"
                        f"docker start {c.name}\n"
                        f"docker update --restart unless-stopped {c.name}   # 재부팅 후 자동 기동\n"
                        "```\n\n"
                        "compose로 관리한다면 서비스에 `restart: unless-stopped`를 넣고 "
                        "`docker compose up -d`로 영구 반영하라."
                    ),
                    tradeoff=(
                        "`restart: always`는 애플리케이션이 죽는 원인을 가린 채 무한 재시작을 반복할 수 있다. "
                        "`unless-stopped`를 쓰고, 재시작이 반복되면 로그부터 확인하라."
                    ),
                ),
                src,
                tgt,
            )

        return self.step(name, Status.PASS, f"{src.name}, {tgt.name} 모두 실행 중", evidence=evidence), src, tgt

    # -------------------------------------------------- 2. 대상 포트

    def _step_port(self, tgt: ContainerInfo) -> DiagnosisStep:
        name = f"2. {tgt.name}가 {self.port or '대상'} 포트를 여는가?"
        if self.port is None:
            return self.step(name, Status.SKIP, "포트를 지정하지 않아 건너뜀 (--port 로 지정하면 확인합니다)")
        if not tgt.running:
            return self.step(name, Status.SKIP, f"{tgt.name}가 실행 중이 아니라 확인할 수 없음")

        declared = listening_ports(tgt)
        evidence = [
            f"{tgt.name} EXPOSE: {', '.join(tgt.exposed_ports) or '선언 없음'}",
            f"{tgt.name} 호스트 공개 포트: {', '.join(p.label for p in tgt.ports) or '없음'}",
        ]
        check_cmd = f'docker exec {tgt.name} sh -c "netstat -tlnp 2>/dev/null || ss -tlnp"'
        if not declared:
            return self.step(
                name,
                Status.WARN,
                "이미지에 포트 선언이 없어 확인 불가 — 실제 리슨 여부는 직접 확인 필요",
                evidence=evidence + [f"확인: {check_cmd}"],
            )
        if self.port in declared:
            return self.step(name, Status.PASS, f"{self.port} 포트를 여는 것으로 선언됨", evidence=evidence)

        opened = ", ".join(str(p) for p in sorted(declared))
        return self.step(
            name,
            Status.FAIL,
            f"{tgt.name}가 {self.port} 포트를 열지 않음 (여는 포트: {opened})",
            evidence=evidence,
            cause=f"`{tgt.name}`는 {self.port}번 포트를 열지 않는다 (여는 포트: {opened})",
            fix=(
                "포트 번호를 잘못 알고 있는 것일 수 있다. 실제로 무엇을 듣고 있는지 확인하라.\n\n"
                "```bash\n"
                f"{check_cmd}\n"
                f"docker logs --tail 50 {tgt.name}\n"
                "```\n\n"
                "포트가 맞다면 애플리케이션의 리슨 포트 설정을, 아니라면 접속하는 쪽의 포트 설정을 고친다.\n\n"
                "*참고: EXPOSE 선언이 없어도 애플리케이션은 포트를 들을 수 있다. 위 명령으로 실제 상태를 확인하라.*"
            ),
            tradeoff=(
                "대상이 컨테이너 안에서 `127.0.0.1`에만 바인딩돼 있으면 포트를 열어도 다른 컨테이너에서는 닿지 않는다. "
                "바인드 주소를 `0.0.0.0`으로 바꾸면 해결되지만, 그 순간 같은 네트워크의 모든 컨테이너에 노출된다는 점을 "
                "함께 고려하라."
            ),
        )

    # -------------------------------------------------- 3. 공유 네트워크 (핵심)

    def _step_shared_network(
        self, runtime: DockerRuntime, src: ContainerInfo, tgt: ContainerInfo
    ) -> tuple[list[str], DiagnosisStep]:
        name = "3. 두 컨테이너가 공유하는 네트워크가 있는가?"

        for c in (src, tgt):
            if c.network_mode == "none":
                return [], self.step(
                    name,
                    Status.FAIL,
                    f"{c.name}가 network_mode: none — 네트워크가 아예 없음",
                    evidence=[f"{c.name} network_mode: none"],
                    cause=f"`{c.name}`가 네트워크 없이(`network_mode: none`) 실행 중이다",
                    fix=(
                        "compose에서 해당 서비스의 `network_mode: none`을 지우고 공통 네트워크에 연결한 뒤 재생성하라.\n\n"
                        f"```bash\ndocker compose up -d --force-recreate {c.compose_service or c.name}\n```"
                    ),
                    tradeoff=(
                        "`network_mode: none`은 가장 강한 격리다. 이 서비스가 의도적으로 외부와 차단된 것이라면, "
                        "격리를 푸는 대신 통신 방식을 바꾸는 편(볼륨·파일 경유)이 나을 수 있다."
                    ),
                )

        if src.network_mode == "host":
            published = [p for p in tgt.ports if self.port is None or p.container_port == self.port]
            if published:
                return [], self.step(
                    name,
                    Status.WARN,
                    f"{src.name}가 host 네트워크 — {tgt.name}의 공개 포트({published[0].label})로만 통신 가능",
                    evidence=[f"{src.name} network_mode: host", f"{tgt.name} 공개 포트: {published[0].label}"],
                )
            port = self.port or 0
            return [], self.step(
                name,
                Status.FAIL,
                f"{src.name}가 host 네트워크인데 {tgt.name}는 포트를 호스트에 공개하지 않음",
                evidence=[f"{src.name} network_mode: host", f"{tgt.name} 공개 포트: 없음"],
                cause=(
                    f"`{src.name}`는 host 네트워크라 Docker 내부 DNS·내부 IP를 쓸 수 없는데, "
                    f"`{tgt.name}`는 호스트에 포트를 공개하지 않았다"
                ),
                fix=(
                    f"둘 중 하나를 택한다.\n\n"
                    f"1. `{src.name}`를 host 네트워크에서 빼고, 두 컨테이너를 같은 커스텀 네트워크에 둔다 (권장).\n"
                    f"2. `{tgt.name}`의 포트를 호스트에 공개한다.\n\n"
                    "```yaml\n"
                    "services:\n"
                    f"  {tgt.compose_service or tgt.name}:\n"
                    "    ports:\n"
                    f'      - "127.0.0.1:{port}:{port}"   # 루프백에만 공개\n'
                    "```"
                ),
                tradeoff=(
                    "포트를 `0.0.0.0`으로 공개하면 외부에서도 접근할 수 있게 된다 (NET-004). "
                    "꼭 공개해야 한다면 `127.0.0.1:`을 붙여 루프백으로 제한하라."
                ),
            )
        if tgt.network_mode == "host":
            return [], self.step(
                name,
                Status.WARN,
                f"{tgt.name}가 host 네트워크 — 컨테이너 이름이 아니라 호스트 IP로 접근해야 함",
                evidence=[f"{tgt.name} network_mode: host"],
            )

        src_nets = runtime.effective_networks(src)
        tgt_nets = runtime.effective_networks(tgt)
        shared = [n for n in src_nets if n in tgt_nets]
        evidence = [
            f"{src.name} 네트워크: {', '.join(src_nets) or '없음'}",
            f"{tgt.name} 네트워크: {', '.join(tgt_nets) or '없음'}",
            f"공통: {', '.join(shared) or '없음'}",
        ]

        if shared:
            custom = [n for n in shared if n != DEFAULT_BRIDGE]
            if not custom:
                return shared, self.step(
                    name,
                    Status.WARN,
                    "기본 bridge로만 연결됨 — 컨테이너 이름 DNS가 없고 재기동마다 IP가 바뀜",
                    evidence=evidence,
                )
            return shared, self.step(name, Status.PASS, f"공유 네트워크: {', '.join(custom)}", evidence=evidence)

        return [], self._network_isolated(src, tgt, src_nets, tgt_nets, evidence)

    def _network_isolated(
        self,
        src: ContainerInfo,
        tgt: ContainerInfo,
        src_nets: list[str],
        tgt_nets: list[str],
        evidence: list[str],
    ) -> DiagnosisStep:
        """공유 네트워크가 없을 때 — 이 진단이 만들어진 이유인 바로 그 상황."""
        suggested = next((n for n in tgt_nets if n != DEFAULT_BRIDGE), None)
        if suggested:
            connect = f"docker network connect {suggested} {src.name}"
        else:
            connect = (
                "docker network create app-net\n"
                f"docker network connect app-net {tgt.name}\n"
                f"docker network connect app-net {src.name}"
            )
        network = suggested or "app-net"
        # compose에 쓸 이름은 프로젝트 접두사를 뗀 것 (messaging_mq-net → mq-net)
        yaml_name = network.split("_", 1)[-1] if suggested else "app-net"
        again = f"dockguard diagnose connectivity {self.source_ref} {self.target_ref}" + (
            f" --port {self.port}" if self.port else ""
        )
        members = "docker network inspect " + network + " --format '{{range .Containers}}{{.Name}} {{end}}'"

        return self.step(
            "3. 두 컨테이너가 공유하는 네트워크가 있는가?",
            Status.FAIL,
            f"공유 네트워크 없음 — {src.name}: [{', '.join(src_nets) or '없음'}] / "
            f"{tgt.name}: [{', '.join(tgt_nets) or '없음'}]",
            evidence=evidence,
            cause="네트워크 격리 — 두 컨테이너가 공유하는 Docker 네트워크가 없어 서로에게 도달할 수 없다",
            fix=(
                "**지금 바로 복구하려면** (임시)\n\n"
                f"```bash\n{connect}\n```\n\n"
                "**재기동 후에도 유지되게 하려면** — compose에 영구 반영한다. "
                "`docker network connect`로 붙인 연결은 컨테이너를 재생성하면 사라진다.\n\n"
                "```yaml\n"
                "services:\n"
                f"  {src.compose_service or src.name}:\n"
                f"    networks: [{yaml_name}]\n"
                f"  {tgt.compose_service or tgt.name}:\n"
                f"    networks: [{yaml_name}]\n"
                "networks:\n"
                f"  {yaml_name}:\n"
                "```\n\n"
                "두 서비스가 서로 다른 compose 프로젝트에 있다면, 한쪽이 만든 네트워크를 다른 쪽에서 참조한다.\n\n"
                "```yaml\n"
                "networks:\n"
                f"  {yaml_name}:\n"
                "    external: true\n"
                f"    name: {network}\n"
                "```\n\n"
                "**확인**\n\n"
                f"```bash\n{members}\n{again}\n```"
            ),
            tradeoff=(
                "- **임시 연결은 재기동 시 풀린다.** `docker network connect`로 급한 불을 껐다면 반드시 compose에 "
                "반영하라. 그러지 않으면 다음 정전 때 같은 장애가 그대로 반복된다.\n"
                "- **같은 네트워크의 컨테이너끼리는 모든 포트로 통신할 수 있다.** 편하다고 모든 서비스를 한 네트워크에 "
                "몰아넣으면 한 컨테이너가 침해됐을 때 옆으로 퍼지기 쉬워진다(측면 이동). 통신이 필요한 서비스끼리만 "
                "묶은 목적별 네트워크(`mq-net`, `db-net`)를 만들어라. — `dockguard learn network-isolation`\n"
                "- 기본 bridge에서 커스텀 네트워크로 옮기면 컨테이너 IP가 바뀐다. IP로 접속하던 설정은 컨테이너 "
                "이름으로 바꿔라 (5단계 참고)."
            ),
        )

    # -------------------------------------------------- 4. icc (컨테이너 간 통신 차단)

    def _step_icc(
        self,
        runtime: DockerRuntime,
        context: ScanContext,
        src: ContainerInfo,
        tgt: ContainerInfo,
        shared: list[str],
    ) -> DiagnosisStep:
        name = "4. 그 네트워크에서 컨테이너 간 통신이 허용되는가?"
        daemon = context.daemon
        daemon_icc_off = daemon is not None and daemon.usable and daemon.get("icc") is False
        bridge = runtime.network(DEFAULT_BRIDGE)
        bridge_icc_off = (bridge is not None and bridge.icc_disabled) or daemon_icc_off
        daemon_note = (
            f"daemon.json({daemon.path}) icc: false" if daemon_icc_off else "daemon.json icc: 미설정 또는 true"
        )

        if not shared:
            # 공유 네트워크가 없으면 판정할 수 없지만, 여기서 알려 주지 않으면
            # "그럼 둘 다 기본 bridge에 붙이면 되겠네"라는 잘못된 복구로 이어진다.
            hint = (
                "참고: 기본 bridge는 컨테이너 간 통신이 꺼져 있다(icc: false). 두 컨테이너를 기본 bridge에 "
                "함께 붙여도 통신은 되지 않으니 반드시 커스텀 네트워크를 쓰라."
                if bridge_icc_off
                else "참고: 기본 bridge는 통신은 되지만 컨테이너 이름 DNS가 없다. 커스텀 네트워크를 쓰라."
            )
            return self.step(name, Status.SKIP, f"공유 네트워크가 없어 판정 불가 — {hint}", evidence=[daemon_note])

        blocked: list[str] = []
        usable: list[str] = []
        for net_name in shared:
            network = runtime.network(net_name)
            if net_name == DEFAULT_BRIDGE and bridge_icc_off:
                blocked.append(f"{net_name} (icc: false)")
            elif network is not None and network.icc_disabled:
                blocked.append(f"{net_name} (enable_icc=false)")
            else:
                usable.append(net_name)

        evidence = [
            daemon_note,
            f"차단된 네트워크: {', '.join(blocked) or '없음'}",
            f"통신 가능: {', '.join(usable) or '없음'}",
        ]
        if usable:
            return self.step(name, Status.PASS, f"{', '.join(usable)}에서 통신 허용", evidence=evidence)

        return self.step(
            name,
            Status.FAIL,
            f"공유 네트워크 {', '.join(blocked)}에서 컨테이너 간 통신이 차단됨",
            evidence=evidence,
            cause=f"`icc: false`로 {', '.join(blocked)} 위의 컨테이너 간 통신이 차단되어 있다",
            fix=(
                "`icc: false`는 좋은 보안 설정이다. 되돌리지 말고 **두 컨테이너를 커스텀 네트워크로 옮겨라.** "
                "커스텀 네트워크는 daemon.json의 `icc` 설정과 무관하게 내부 통신이 허용된다.\n\n"
                "```bash\n"
                "docker network create app-net\n"
                f"docker network connect app-net {tgt.name}\n"
                f"docker network connect app-net {src.name}\n"
                "```\n\n"
                "그리고 compose의 두 서비스에 같은 `networks:`를 지정해 영구 반영한다.\n\n"
                "정말 기본 bridge에서 통신해야 한다면 `/etc/docker/daemon.json`에서 `\"icc\": true`로 되돌리고 "
                "데몬을 재시작해야 하지만, 권장하지 않는다. — `dockguard learn icc`"
            ),
            tradeoff=(
                "`icc: true`로 되돌리면 **기본 bridge의 모든 컨테이너가 서로 통신할 수 있게 된다.** 한 컨테이너가 "
                "침해되면 나머지로 옮겨 다니기 쉬워진다. 데몬 재시작이 실행 중인 컨테이너에 영향을 준다는 문제도 있다. "
                "커스텀 네트워크로 옮기는 쪽이 보안과 가용성을 모두 지키는 해법이다."
            ),
        )

    # -------------------------------------------------- 5. 접속 주소 설정

    def _step_address(self, src: ContainerInfo, tgt: ContainerInfo) -> DiagnosisStep:
        name = f"5. {src.name}는 {tgt.name}를 어떤 주소로 찾는가?"
        candidates = address_candidates(src, tgt, self.target_ref)
        if not candidates:
            return self.step(
                name,
                Status.SKIP,
                "접속 주소로 보이는 환경변수를 찾지 못함 — 설정 파일에 들어 있을 수 있다",
                evidence=[f"확인: docker exec {src.name} env"],
            )

        evidence = [f"{key}={mask_credentials(value)}" for key, value in candidates]
        names = {n.lower() for n in (tgt.name, tgt.compose_service or "", self.target_ref) if n}
        published = [p for p in tgt.ports if self.port is None or p.container_port == self.port]

        for key, value in candidates:
            host = extract_host(value)
            if host is None or host.lower() in names:
                continue  # 컨테이너 이름으로 잘 찾고 있다
            lowered = host.lower()
            if lowered in SELF_HOSTS:
                return self.step(
                    name,
                    Status.FAIL,
                    f"{key}가 {host} — 컨테이너 안에서 이 주소는 자기 자신을 가리킨다",
                    evidence=evidence,
                    cause=f"`{key}={host}`는 컨테이너 안에서 **자기 자신**을 가리킨다 (호스트도, 상대 컨테이너도 아니다)",
                    fix=self._address_fix(key, host, src, tgt),
                    tradeoff=ADDRESS_TRADEOFF,
                )
            if is_ip_literal(host):
                reachable = bool(published)
                note = (
                    f"{tgt.name}가 호스트에 {published[0].label}로 공개돼 있어 우회 접속은 될 수 있다"
                    if reachable
                    else f"{tgt.name}는 호스트에 포트를 공개하지 않아 이 주소로는 닿지 않는다"
                )
                ports_note = f"{tgt.name} 호스트 공개 포트: {', '.join(p.label for p in tgt.ports) or '없음'}"
                if reachable:
                    return self.step(
                        name,
                        Status.WARN,
                        f"{key}가 IP({host})로 고정됨 — {note} (컨테이너 이름 사용 권장)",
                        evidence=evidence + [ports_note],
                    )
                return self.step(
                    name,
                    Status.FAIL,
                    f"{key}가 IP({host})로 고정됨 — {note}",
                    evidence=evidence + [ports_note],
                    cause=f"`{key}={host}` — 컨테이너 간 통신에 호스트·외부 IP를 쓰고 있다. {note}",
                    fix=self._address_fix(key, host, src, tgt),
                    tradeoff=ADDRESS_TRADEOFF,
                )
            return self.step(
                name,
                Status.WARN,
                f"{key}가 `{host}` — {tgt.name}의 이름과 다름 (네트워크 별칭이라면 정상)",
                evidence=evidence + [f"확인: docker exec {src.name} getent hosts {host}"],
            )

        return self.step(name, Status.PASS, "컨테이너 이름으로 접속하도록 설정됨", evidence=evidence)

    def _address_fix(self, key: str, host: str, src: ContainerInfo, tgt: ContainerInfo) -> str:
        service = src.compose_service or src.name
        return (
            "컨테이너끼리는 **컨테이너 이름(= compose 서비스 이름)** 으로 통신한다. 같은 커스텀 네트워크에 있으면 "
            "Docker 내장 DNS가 이름을 IP로 바꿔 주고, 컨테이너가 재생성돼 IP가 바뀌어도 그대로 동작한다.\n\n"
            "```yaml\n"
            "services:\n"
            f"  {service}:\n"
            "    environment:\n"
            f"      {key}: {tgt.compose_service or tgt.name}    # {host} → 컨테이너 이름\n"
            "```\n\n"
            "```bash\n"
            f"docker compose up -d --force-recreate {service}\n"
            f"docker exec {src.name} getent hosts {tgt.name}   # 이름이 풀리는지 확인\n"
            "```"
        )


MISSING_CONTAINER_FIX = (
    "이름이 바뀌었거나(compose 프로젝트 이름 변경 등), 재부팅·재배포 후 다시 생성되지 않은 것이다.\n\n"
    "```bash\n"
    "docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.Image}}'\n"
    "docker compose up -d      # compose로 관리한다면 다시 올린다\n"
    "```\n\n"
    "compose 서비스 이름으로 찾아도 된다 (예: `dockguard diagnose connectivity backend rabbitmq`)."
)

ADDRESS_TRADEOFF = (
    "컨테이너 이름으로 접속하려면 두 컨테이너가 **같은 커스텀 네트워크**에 있어야 한다 (기본 bridge에는 이름 DNS가 없다). "
    "주소만 바꾸고 네트워크를 맞추지 않으면 여전히 연결되지 않는다 — 3단계를 함께 확인하라."
)
