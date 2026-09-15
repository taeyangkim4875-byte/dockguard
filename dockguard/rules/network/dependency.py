"""NET-001: 서비스 의존성 통신 검증 — dockguard의 핵심 기능.

"정전 후 재기동했더니 백엔드가 RabbitMQ에 접속하지 못한다"를 즉시 찾아내기 위한 룰.
dependencies.yaml(또는 compose depends_on)에 선언된 A → B마다 다음을 확인한다.

1. 두 컨테이너가 실제로 존재하는가
2. B가 실행 중인가 (재시작 정책이 없으면 재부팅 후 올라오지 않는다)
3. 둘이 공유하는 Docker 네트워크가 있는가
4. 그 네트워크에서 통신이 막혀 있지 않은가 (기본 bridge + icc:false, 네트워크별 enable_icc=false)
5. (가능하면) B가 그 포트를 노출하는가
"""

from __future__ import annotations

from dataclasses import dataclass

from dockguard.core.context import (
    DEFAULT_BRIDGE,
    ContainerInfo,
    Dependency,
    DockerRuntime,
    ScanContext,
)
from dockguard.core.models import Finding, Severity, Status
from dockguard.core.rule import register
from dockguard.knowledge.references import best_practice
from dockguard.rules.network._base import NetworkRule

_STATUS_WORST_FIRST = [Status.FAIL, Status.WARN, Status.PASS]


@dataclass
class PairResult:
    status: Status
    detail: str
    suggested_network: str | None = None  # 연결을 제안할 공통 네트워크


def _best(results: list[PairResult]) -> PairResult:
    """여러 대상 컨테이너(스케일된 서비스) 중 하나라도 닿으면 된다."""
    return max(results, key=lambda r: _STATUS_WORST_FIRST.index(r.status))


def _worst(results: list[PairResult]) -> PairResult:
    """출발 컨테이너가 여러 개면 전부 닿아야 한다."""
    return min(results, key=lambda r: _STATUS_WORST_FIRST.index(r.status))


def bridge_icc_disabled(runtime: DockerRuntime, context: ScanContext) -> bool:
    """기본 bridge에서 컨테이너 간 통신이 막혀 있는지.

    실행 중인 Docker가 기본 bridge 옵션(enable_icc)에 실제 상태를 기록하므로 그것을 우선 보고,
    daemon.json의 icc도 함께 본다 (dockerd 실행 옵션으로 켠 경우도 잡힌다).
    """
    bridge = runtime.network(DEFAULT_BRIDGE)
    if bridge is not None and bridge.icc_disabled:
        return True
    daemon = context.daemon
    return daemon is not None and daemon.usable and daemon.get("icc") is False


@register
class DependencyConnectivityRule(NetworkRule):
    id = "NET-001"
    title = "서비스 의존성 통신 검증"
    severity = Severity.CRITICAL
    reference = best_practice("서비스 간 통신 경로를 선언하고 실제 네트워크 상태와 대조 (dockguard 고유 점검)")
    recommended = "두 컨테이너가 같은 커스텀 네트워크에 연결"

    why = """\
서비스는 혼자 동작하지 않는다. 백엔드는 메시지큐와 DB에, 워커는 큐에 붙어야 한다. 그런데 Docker에서 두 \
컨테이너가 통신하려면 **같은 Docker 네트워크에 연결되어 있어야** 하고, 그 네트워크에서 통신이 막혀 있지 \
않아야 한다.

이 조건은 평소에는 잘 드러나지 않다가 **정전·재부팅·재배포 직후**에 깨진다.

- compose 밖에서 `docker run`으로 다시 띄운 컨테이너는 기본 bridge에만 붙는다.
- `docker network connect`로 임시 연결했던 것은 컨테이너 재생성 시 풀린다.
- `daemon.json`에 `icc: false`를 적용한 뒤 데몬이 재시작되면 기본 bridge 위의 통신이 모두 끊긴다.
- 재시작 정책(`restart:`)이 없는 컨테이너는 재부팅 후 아예 올라오지 않는다.

에러는 보통 `Connection refused`나 타임아웃뿐이라, 원인이 **네트워크 구성**이라는 걸 찾는 데 오래 걸린다. \
dockguard의 제작 배경이 된 사고에서도 이 문제를 찾는 데 가장 오래 걸렸다. 이 룰은 선언된 의존성마다 실제 \
네트워크 상태를 대조해 **통신이 불가능한 조합을 즉시** 알려준다."""

    how_to_fix = """\
1. 두 컨테이너를 같은 네트워크에 연결한다. 당장 복구가 급하다면:

```bash
docker network connect <공통 네트워크> <컨테이너>
```

2. **compose 파일에 영구 반영한다** (임시 연결은 재생성 시 풀린다).

```yaml
services:
  backend:
    networks: [mq-net]
    environment:
      RABBITMQ_HOST: rabbitmq        # 호스트 IP가 아니라 서비스 이름으로
  rabbitmq:
    networks: [mq-net]
networks:
  mq-net:
```

서로 다른 compose 프로젝트에 있는 서비스라면 한쪽에서 만든 네트워크를 다른 쪽에서 `external: true`로 참조한다.

3. 다시 점검한다.

```bash
dockguard scan --category network
```"""

    tradeoff = """\
- **네트워크 연결은 신중히.** 같은 네트워크에 있는 컨테이너끼리는 모든 포트로 통신할 수 있다. 통신이 필요한 \
서비스끼리만 묶은 **목적별 네트워크**(예: `mq-net`, `db-net`)를 만들고, 편하다고 모든 서비스를 하나의 \
네트워크에 넣지 마라 (측면 이동 위험, DAEMON-001 참고).
- `docker network connect`로 임시 연결한 것은 **재기동 시 풀린다.** 급한 복구 후에는 반드시 compose 파일에 \
반영하라. 그렇지 않으면 다음 정전 때 같은 장애가 반복된다.
- 기본 bridge 대신 커스텀 네트워크로 옮기면 컨테이너 IP가 바뀐다. IP로 접속하던 설정은 서비스 이름으로 바꿔라.
- 이 룰은 **네트워크 경로**만 확인한다. 비밀번호 불일치, 방화벽(DOCKER-USER 체인), 애플리케이션 설정 오류는 \
잡지 못하므로, 통과 후에도 연결이 안 되면 로그의 인증 오류를 확인하라."""

    learn_more = "https://docs.docker.com/engine/network/"

    def evaluate(self, runtime: DockerRuntime, context: ScanContext) -> list[Finding]:
        if not context.dependencies:
            return [
                self.make(
                    Status.SKIP,
                    target="서비스 의존성",
                    current=(
                        "검증할 의존성이 없습니다 — dependencies.yaml을 만들거나(--deps, "
                        "config/dependencies.example.yaml 참고) compose depends_on을 사용하세요"
                    ),
                )
            ]
        return [self._check(dep, runtime, context) for dep in context.dependencies]

    # ------------------------------------------------------------------ 이름 → 컨테이너

    @staticmethod
    def resolve(ref: str, dep: Dependency, runtime: DockerRuntime) -> list[ContainerInfo]:
        """컨테이너 이름, 또는 compose 서비스 이름으로 컨테이너를 찾는다 (스케일된 서비스는 여러 개)."""
        if dep.project:
            scoped = [c for c in runtime.containers if c.compose_project == dep.project and c.compose_service == ref]
            if scoped:
                return scoped
        exact = runtime.find_container(ref)
        if exact is not None:
            return [exact]
        return [c for c in runtime.containers if c.compose_service == ref]

    # ------------------------------------------------------------------ 판정

    def _check(self, dep: Dependency, runtime: DockerRuntime, context: ScanContext) -> Finding:
        target = f"{dep.label} ({dep.origin})" if dep.origin else dep.label
        sources = self.resolve(dep.source, dep, runtime)
        targets = self.resolve(dep.target, dep, runtime)

        missing = [name for name, found in ((dep.source, sources), (dep.target, targets)) if not found]
        if missing:
            situation = (
                f"`{', '.join(missing)}` 컨테이너가 이 호스트에 없다. 이름이 바뀌었거나(compose 프로젝트 이름 변경 등) "
                "정전·재배포 후 다시 생성되지 않은 것일 수 있다."
            )
            return self._fail(dep, target, f"컨테이너를 찾을 수 없음: {', '.join(missing)}", situation, fix_now="")

        running_targets = [t for t in targets if t.running]
        if not running_targets:
            t = targets[0]
            no_policy = t.restart_policy == "no"
            note = " — 재시작 정책이 없어 재부팅 후 자동으로 올라오지 않음" if no_policy else ""
            situation = (
                f"`{t.name}` 컨테이너가 멈춰 있다({t.state}). "
                + ("재시작 정책이 없으면 정전·재부팅 후 컨테이너가 자동으로 올라오지 않는다." if no_policy else "")
            )
            fix_now = (
                f"**지금 바로 복구하려면**\n\n```bash\ndocker start {t.name}\n"
                f"docker update --restart unless-stopped {t.name}   # 재부팅 후에도 자동 기동\n```\n\n"
                "compose로 관리한다면 서비스에 `restart: unless-stopped`를 추가하라.\n\n"
            )
            return self._fail(
                dep, target, f"{t.name} 컨테이너가 실행 중이 아님 ({t.state}, restart: {t.restart_policy}){note}",
                situation, fix_now,
            )  # fmt: skip

        per_source: list[tuple[ContainerInfo, PairResult]] = []
        for src in sources:
            best = _best([self._pair(src, tgt, dep, runtime, context) for tgt in running_targets])
            per_source.append((src, best))

        worst = _worst([r for _, r in per_source])
        stopped = [s.name for s in sources if not s.running]
        detail = worst.detail
        if len(sources) > 1:
            detail = "; ".join(f"{s.name}: {r.detail}" for s, r in per_source if r.status == worst.status)
        if stopped:
            detail += f" (참고: {', '.join(stopped)} 중지 상태)"

        if worst.status == Status.FAIL:
            network = worst.suggested_network or "<공통 네트워크>"
            situation = (
                f"현재 상태로는 `{dep.source}`에서 `{dep.target}`로 통신할 수 없다. "
                "정전·재기동 후 네트워크가 분리되면 이런 상황이 생긴다."
            )
            fix_now = f"**지금 바로 복구하려면**\n\n```bash\ndocker network connect {network} {sources[0].name}\n```\n\n"
            return self._fail(dep, target, detail, situation, fix_now)
        return self.make(worst.status, target=target, current=detail)

    def _pair(
        self, src: ContainerInfo, tgt: ContainerInfo, dep: Dependency, runtime: DockerRuntime, context: ScanContext
    ) -> PairResult:
        for container in (src, tgt):
            if container.network_mode == "none":
                return PairResult(Status.FAIL, f"{container.name}가 network_mode: none (네트워크 없음)")

        if src.network_mode == "host":
            published = [p for p in tgt.ports if dep.port is None or p.container_port == dep.port]
            if published:
                return PairResult(Status.WARN, f"{src.name}가 host 네트워크 — {tgt.name}의 공개 포트({published[0].label})로 통신")
            return PairResult(Status.FAIL, f"{src.name}가 host 네트워크인데 {tgt.name}가 포트를 공개하지 않음")
        if tgt.network_mode == "host":
            return PairResult(Status.WARN, f"{tgt.name}가 host 네트워크 — 호스트 IP로만 접근 가능 (격리 없음)")

        src_nets = runtime.effective_networks(src)
        tgt_nets = runtime.effective_networks(tgt)
        shared = [n for n in src_nets if n in tgt_nets]
        suggestion = next((n for n in tgt_nets if n != DEFAULT_BRIDGE), None)
        if not shared:
            return PairResult(
                Status.FAIL,
                f"공유 네트워크 없음 — {src.name}: {', '.join(src_nets) or '없음'} / {tgt.name}: {', '.join(tgt_nets) or '없음'}",
                suggestion,
            )

        blocked: list[str] = []
        usable: list[str] = []
        for name in shared:
            network = runtime.network(name)
            if name == DEFAULT_BRIDGE and bridge_icc_disabled(runtime, context):
                blocked.append(f"{name}(icc: false)")
            elif network is not None and network.icc_disabled:
                blocked.append(f"{name}(enable_icc=false)")
            else:
                usable.append(name)
        if not usable:
            return PairResult(Status.FAIL, f"공유 네트워크 {', '.join(blocked)}에서 컨테이너 간 통신이 차단됨", suggestion)

        if usable == [DEFAULT_BRIDGE]:
            return PairResult(
                Status.WARN,
                "기본 bridge로만 연결 — 컨테이너 이름으로 DNS 조회가 안 되고 재기동마다 IP가 바뀜",
                suggestion,
            )

        if dep.port and tgt.exposed_ports and not tgt.exposes(dep.port):
            exposed = ", ".join(tgt.exposed_ports)
            return PairResult(
                Status.WARN,
                f"공유 네트워크 {', '.join(usable)} — 단, {tgt.name}는 {dep.port} 포트를 노출하지 않음 (EXPOSE: {exposed})",
            )
        return PairResult(Status.PASS, f"공유 네트워크: {', '.join(usable)}")

    def _fail(self, dep: Dependency, target: str, detail: str, situation: str, fix_now: str) -> Finding:
        """의존성 이유와 현재 상황을 why 맨 앞에, 즉시 복구 명령을 how_to_fix 맨 앞에 붙인다."""
        reason = dep.reason or "선언된 서비스 의존성"
        return self.make(
            Status.FAIL,
            target=target,
            current=detail,
            why=f"**{reason}** — 하지만 {situation}\n\n{self.why}",
            how_to_fix=f"{fix_now}{self.how_to_fix}",
        )
