"""실행 중인 Docker의 컨테이너 · 네트워크 상태 수집.

수집 경로 (앞에서 실패하면 다음으로):
1. Docker SDK for Python (`docker` 패키지)
2. `docker` CLI (`docker inspect` JSON)
3. (사용자 지정) 스냅샷 파일 — Python을 설치할 수 없는 서버에서 떠 온 JSON을 다른 곳에서 분석

세 경로 모두 `docker inspect`와 같은 JSON을 내놓으므로 파서는 하나다.
Docker에 연결하지 못해도 예외를 던지지 않고, 사유를 담은 DockerRuntime(available=False)을 돌려준다.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Protocol

from dockguard.core.context import ContainerInfo, DockerRuntime, NetworkInfo, PublishedPort

SDK_TIMEOUT = 10  # 초
CLI_TIMEOUT = 30  # 초

MSG_PERMISSION = (
    "Docker 소켓에 접근할 권한이 없습니다. sudo로 실행하세요. "
    "(사용자를 docker 그룹에 넣는 방법도 있지만, docker 그룹은 사실상 root 권한이라는 점에 주의하세요)"
)
MSG_NOT_RUNNING = "Docker 데몬에 연결할 수 없습니다. " + (
    "실행 중인지 확인하세요: sudo systemctl status docker"
    if sys.platform.startswith("linux")
    else "Docker Desktop이 실행 중인지 확인하세요."
)
MSG_NOT_INSTALLED = "Docker SDK와 docker 명령을 모두 찾을 수 없습니다. Docker가 설치된 호스트에서 실행하세요."
OFFLINE_HINT = " (서버에서 떠 온 스냅샷은 --docker-snapshot 으로 분석할 수 있습니다)"

# 여러 경로가 모두 실패했을 때 어떤 사유를 보여줄지 (구체적인 것 우선)
_ERROR_PRIORITY = [MSG_PERMISSION, MSG_NOT_RUNNING]


class DockerUnavailable(Exception):
    """이 수집 경로로는 Docker 상태를 가져올 수 없음. 메시지는 사용자에게 그대로 보여준다."""


def classify_docker_error(message: str) -> str:
    """Docker 클라이언트 오류 메시지를 사용자가 할 일이 드러나는 안내문으로 바꾼다."""
    lowered = message.lower()
    if "permission denied" in lowered or "access is denied" in lowered:
        return MSG_PERMISSION
    not_running_signals = (
        "cannot connect",
        "connection refused",
        "no such file",
        "filenotfounderror",
        "is the docker daemon running",
        "error while fetching server api version",
        "cannot find the file specified",
        "connection aborted",
    )
    if any(signal in lowered for signal in not_running_signals):
        return MSG_NOT_RUNNING
    first_line = message.strip().splitlines()[0] if message.strip() else "알 수 없는 오류"
    return f"Docker 데몬과 통신하지 못했습니다: {first_line}"


# --------------------------------------------------------------------------- 파서 (docker inspect JSON → 모델)


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def parse_container(data: dict[str, Any]) -> ContainerInfo:
    config = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    settings = data.get("NetworkSettings") or {}

    ports: list[PublishedPort] = []
    for key, bindings in (settings.get("Ports") or {}).items():
        port_text, _, protocol = str(key).partition("/")
        container_port = _to_int(port_text)
        if container_port is None:
            continue
        for binding in bindings or []:
            ports.append(
                PublishedPort(
                    container_port=container_port,
                    protocol=protocol or "tcp",
                    host_ip=str(binding.get("HostIp", "")),
                    host_port=_to_int(binding.get("HostPort")),
                )
            )

    return ContainerInfo(
        id=str(data.get("Id", "")),
        name=str(data.get("Name", "")).lstrip("/"),
        image=str(config.get("Image", "")),
        state=str((data.get("State") or {}).get("Status", "unknown")),
        restart_policy=str((host.get("RestartPolicy") or {}).get("Name") or "no"),
        network_mode=str(host.get("NetworkMode") or "default"),
        networks=list((settings.get("Networks") or {}).keys()),
        ports=ports,
        exposed_ports=list((config.get("ExposedPorts") or {}).keys()),
        labels={str(k): str(v) for k, v in (config.get("Labels") or {}).items()},
    )


def parse_network(data: dict[str, Any]) -> NetworkInfo:
    return NetworkInfo(
        id=str(data.get("Id", "")),
        name=str(data.get("Name", "")),
        driver=str(data.get("Driver", "")),
        internal=bool(data.get("Internal", False)),
        options={str(k): str(v) for k, v in (data.get("Options") or {}).items()},
    )


# --------------------------------------------------------------------------- 수집 경로


class Backend(Protocol):
    name: str

    def containers(self) -> list[dict[str, Any]]: ...

    def networks(self) -> list[dict[str, Any]]: ...

    def info(self) -> dict[str, Any]: ...


class SdkBackend:
    """Docker SDK for Python."""

    name = "Docker SDK"

    def __init__(self) -> None:
        try:
            import docker  # 선택 의존성: 없으면 CLI로 폴백
        except ImportError as exc:
            raise DockerUnavailable(MSG_NOT_INSTALLED) from exc
        try:
            self.client = docker.from_env(timeout=SDK_TIMEOUT)
            self.client.ping()
        except Exception as exc:  # noqa: BLE001 — SDK는 requests/소켓 예외를 그대로 올리기도 한다
            raise DockerUnavailable(classify_docker_error(str(exc))) from exc

    def containers(self) -> list[dict[str, Any]]:
        return [c.attrs for c in self.client.containers.list(all=True, ignore_removed=True)]

    def networks(self) -> list[dict[str, Any]]:
        return list(self.client.api.networks())

    def info(self) -> dict[str, Any]:
        return dict(self.client.info())


Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class CliBackend:
    """`docker` 명령 폴백. SDK가 없거나 SDK 연결이 실패한 환경용."""

    name = "docker CLI"

    def __init__(self, runner: Runner = subprocess.run) -> None:
        docker = shutil.which("docker")
        if docker is None:
            raise DockerUnavailable(MSG_NOT_INSTALLED)
        self.docker = docker
        self.runner = runner
        self._run("version", "--format", "{{.Server.Version}}")  # 데몬 연결 확인

    def _run(self, *args: str) -> str:
        try:
            proc = self.runner([self.docker, *args], capture_output=True, text=True, timeout=CLI_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DockerUnavailable(classify_docker_error(str(exc))) from exc
        if proc.returncode != 0:
            raise DockerUnavailable(classify_docker_error(proc.stderr or proc.stdout))
        return proc.stdout

    def _inspect(self, list_args: list[str], inspect_args: list[str]) -> list[dict[str, Any]]:
        ids = self._run(*list_args).split()
        if not ids:
            return []
        return json.loads(self._run(*inspect_args, *ids))

    def containers(self) -> list[dict[str, Any]]:
        return self._inspect(["ps", "-aq", "--no-trunc"], ["inspect"])

    def networks(self) -> list[dict[str, Any]]:
        return self._inspect(["network", "ls", "-q", "--no-trunc"], ["network", "inspect"])

    def info(self) -> dict[str, Any]:
        return json.loads(self._run("info", "--format", "{{json .}}"))


class SnapshotBackend:
    """오프라인 분석용 스냅샷 파일 ({"containers": [...], "networks": [...], "info": {...}})."""

    name = "스냅샷 파일"

    def __init__(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except OSError as exc:
            raise DockerUnavailable(f"스냅샷 파일을 읽을 수 없습니다: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise DockerUnavailable(f"스냅샷 JSON 파싱 실패 ({exc.lineno}행 {exc.colno}열: {exc.msg})") from exc
        if not isinstance(data, dict) or not isinstance(data.get("containers", []), list):
            raise DockerUnavailable('스냅샷 형식이 올바르지 않습니다. {"containers": [...], "networks": [...]} 형태여야 합니다.')
        self.name = f"스냅샷 파일 ({path.name})"
        self.data = data

    def containers(self) -> list[dict[str, Any]]:
        return list(self.data.get("containers") or [])

    def networks(self) -> list[dict[str, Any]]:
        return list(self.data.get("networks") or [])

    def info(self) -> dict[str, Any]:
        return dict(self.data.get("info") or {})


def build_runtime(backend: Backend) -> DockerRuntime:
    """수집 경로에서 데이터를 가져와 모델로 변환한다."""
    try:
        containers = [parse_container(d) for d in backend.containers()]
        networks = [parse_network(d) for d in backend.networks()]
    except DockerUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DockerUnavailable(classify_docker_error(str(exc))) from exc
    try:
        info = backend.info()
    except Exception:  # noqa: BLE001 — info는 보조 정보라 실패해도 진행
        info = {}
    return DockerRuntime(
        available=True,
        source=backend.name,
        containers=containers,
        networks=networks,
        security_options=[str(o) for o in info.get("SecurityOptions") or []],
        server_version=info.get("ServerVersion"),
        host_name=info.get("Name"),
    )


BackendFactory = Callable[[], Backend]
DEFAULT_BACKENDS: tuple[BackendFactory, ...] = (SdkBackend, CliBackend)


def collect_runtime(
    snapshot: Path | None = None,
    backends: tuple[BackendFactory, ...] | None = None,
) -> DockerRuntime:
    """Docker 상태를 수집한다. 모든 경로가 실패하면 가장 구체적인 사유와 함께 available=False."""
    if snapshot is not None:
        try:
            return build_runtime(SnapshotBackend(snapshot))
        except DockerUnavailable as exc:
            return DockerRuntime(available=False, error=str(exc))

    errors: list[str] = []
    for factory in backends or DEFAULT_BACKENDS:
        try:
            return build_runtime(factory())
        except DockerUnavailable as exc:
            errors.append(str(exc))

    for preferred in _ERROR_PRIORITY:
        if preferred in errors:
            return DockerRuntime(available=False, error=preferred + OFFLINE_HINT)
    specific = [e for e in errors if e != MSG_NOT_INSTALLED]
    return DockerRuntime(available=False, error=(specific[0] if specific else MSG_NOT_INSTALLED) + OFFLINE_HINT)
