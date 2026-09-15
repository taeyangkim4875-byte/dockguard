"""daemon.json 안전 수정기.

절대 원칙 (CLAUDE.md §10):
1. 수정 전 반드시 백업 (`daemon.json.bak.<타임스탬프>`)
2. 기본은 dry-run — 이 모듈의 `build_plan()`은 파일을 건드리지 않는다
3. 적용 전 재확인 프롬프트 — CLI 책임
4. 부작용이 큰 항목(RISKY)은 사용자가 룰 ID를 명시해야만 포함
5. 적용 후 검증 — 실패하면 원본으로 자동 롤백

적용 순서:
  임시 파일에 새 내용 쓰기 → JSON 검증 → (가능하면) `dockerd --validate` →
  원본 백업 → 원자적 교체(os.replace) → 다시 읽어 검증 → 실패 시 백업으로 복원
"""

from __future__ import annotations

import copy
import difflib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from dockguard.core.collector import load_daemon_config
from dockguard.core.context import DaemonConfig, ScanContext
from dockguard.core.models import ApplyMethod, Category, ConfigPatch, Finding, FixRisk
from dockguard.core.rule import Rule

BACKUP_TIMESTAMP_FORMAT = "%Y%m%d-%H%M%S"
NEW_FILE_MODE = 0o644
DOCKERD_VALIDATE_TIMEOUT = 15  # 초

# (성공 여부 | None=검증 불가, 메시지)
Validator = Callable[[Path], "tuple[bool | None, str]"]


class RemediationError(Exception):
    """수정을 진행할 수 없거나 실패한 경우. 메시지는 사용자에게 그대로 보여준다."""


@dataclass
class PlannedFix:
    """자동 수정할 문제 항목과 그 수정 계획."""

    finding: Finding
    patch: ConfigPatch


@dataclass
class SkippedFix:
    """자동 수정 대상에서 빠진 문제 항목과 그 이유."""

    finding: Finding
    reason: str


@dataclass
class RemediationPlan:
    """daemon.json 수정 계획 (아직 파일은 건드리지 않은 상태)."""

    daemon: DaemonConfig
    fixes: list[PlannedFix] = field(default_factory=list)
    skipped: list[SkippedFix] = field(default_factory=list)
    after: dict[str, Any] = field(default_factory=dict)

    @property
    def patches(self) -> list[ConfigPatch]:
        return [f.patch for f in self.fixes]

    @property
    def requires_recreate(self) -> bool:
        return any(p.requires_recreate for p in self.patches)

    @property
    def has_changes(self) -> bool:
        return bool(self.patches) and self.after != self.daemon.data

    @property
    def risky_patches(self) -> list[ConfigPatch]:
        return [p for p in self.patches if p.risk == FixRisk.RISKY]

    @property
    def apply_with(self) -> ApplyMethod | None:
        """변경을 반영하는 데 필요한 조치 (하나라도 재시작이 필요하면 재시작)."""
        if not self.patches:
            return None
        if any(p.apply_with == ApplyMethod.RESTART for p in self.patches):
            return ApplyMethod.RESTART
        return ApplyMethod.RELOAD

    @property
    def live_restore_before(self) -> bool:
        return self.daemon.data.get("live-restore") is True

    @property
    def live_restore_after(self) -> bool:
        """수정 후 live-restore가 켜져 있는지 (재시작 시 컨테이너 유지 여부)."""
        return self.after.get("live-restore") is True

    def new_text(self) -> str:
        """수정 후 daemon.json 내용. 원본의 들여쓰기 스타일을 유지한다."""
        return dump_json(self.after, _detect_indent(self.daemon.raw_text)) + "\n"

    def diff(self) -> str:
        """원본 대비 unified diff (전체 경로는 화면 상단에 따로 표시)."""
        before = self.daemon.raw_text if self.daemon.exists else ""
        name = self.daemon.path.name
        return "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                self.new_text().splitlines(keepends=True),
                fromfile=f"{name} (현재)" if self.daemon.exists else "/dev/null",
                tofile=f"{name} (수정 후)",
            )
        )


@dataclass
class ApplyResult:
    path: Path
    backup_path: Path | None  # 새 파일을 만든 경우 None
    validation: str  # 검증 결과 요약


INLINE_ARRAY_MAX_WIDTH = 80


def dump_json(value: Any, indent: int | str = 2, _level: int = 0) -> str:
    """사람이 손으로 쓴 daemon.json과 비슷한 모양으로 직렬화한다.

    `json.dumps(indent=...)`는 `["a", "b"]` 같은 짧은 배열도 여러 줄로 펼쳐서, 수정하지 않은 줄까지
    diff에 나타난다. 스칼라만 담긴 짧은 배열은 한 줄로 유지해 diff를 실제 변경분으로 좁힌다.
    """
    unit = "\t" if indent == "\t" else " " * int(indent)
    pad, close = unit * (_level + 1), unit * _level
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = [f"{pad}{json.dumps(k, ensure_ascii=False)}: {dump_json(v, indent, _level + 1)}" for k, v in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + close + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        if not any(isinstance(v, (dict, list)) for v in value):
            inline = "[" + ", ".join(json.dumps(v, ensure_ascii=False) for v in value) + "]"
            if len(inline) <= INLINE_ARRAY_MAX_WIDTH:
                return inline
        items = [pad + dump_json(v, indent, _level + 1) for v in value]
        return "[\n" + ",\n".join(items) + "\n" + close + "]"
    return json.dumps(value, ensure_ascii=False)


def _detect_indent(text: str) -> int | str:
    for line in text.splitlines():
        stripped = line.lstrip(" \t")
        if stripped and len(stripped) != len(line):
            prefix = line[: len(line) - len(stripped)]
            return "\t" if prefix.startswith("\t") else len(prefix)
    return 2


def _apply_patches(data: dict[str, Any], patches: Iterable[ConfigPatch]) -> dict[str, Any]:
    result = copy.deepcopy(data)
    for patch in patches:
        for key, value in patch.set_values.items():
            result[key] = copy.deepcopy(value)
        for key in patch.remove_keys:
            result.pop(key, None)
    return result


# --------------------------------------------------------------------------- 계획 수립 (dry-run)


def build_plan(
    context: ScanContext,
    findings: Iterable[Finding],
    rules: Iterable[Rule],
    selected_ids: Iterable[str] | None = None,
) -> RemediationPlan:
    """문제 항목(FAIL/WARN)에서 자동 수정 계획을 만든다. 파일은 건드리지 않는다.

    Args:
        selected_ids: 수정할 룰 ID. None이면 SAFE 항목 전체.
            RISKY 항목은 여기에 ID가 명시된 경우에만 포함된다.
    """
    daemon = context.daemon
    if daemon is None:
        raise RemediationError("daemon.json 정보가 수집되지 않았습니다.")
    if not daemon.usable:
        raise RemediationError(f"daemon.json을 안전하게 수정할 수 없습니다: {daemon.error}")

    selected = {s.upper() for s in selected_ids} if selected_ids else None
    rules_by_id = {r.id: r for r in rules}
    plan = RemediationPlan(daemon=daemon)

    for finding in sorted(findings, key=Finding.sort_key):
        if finding.category != Category.DAEMON.value or not finding.is_problem:
            continue
        if selected is not None and finding.rule_id not in selected:
            continue
        rule = rules_by_id.get(finding.rule_id)
        patch = rule.plan_fix(finding, context) if rule else None
        if patch is None:
            reason = rule.no_autofix_reason if rule else "룰 정보를 찾을 수 없습니다."
            plan.skipped.append(SkippedFix(finding, reason))
            continue
        if patch.risk == FixRisk.RISKY and (selected is None or finding.rule_id not in selected):
            plan.skipped.append(
                SkippedFix(
                    finding,
                    f"부작용이 커서 기본 수정 대상에서 제외했습니다. 영향을 확인했다면 "
                    f"`--rule {finding.rule_id}`로 명시해 포함할 수 있습니다.",
                )
            )
            continue
        plan.fixes.append(PlannedFix(finding, patch))

    plan.after = _apply_patches(daemon.data, plan.patches)
    return plan


# --------------------------------------------------------------------------- 검증


def validate_with_dockerd(path: Path) -> tuple[bool | None, str]:
    """`dockerd --validate`로 설정 파일을 검증한다 (Docker 23.0+).

    Returns:
        (True, 메시지): 검증 통과 / (False, 메시지): 설정 오류 / (None, 메시지): 검증 불가
    """
    dockerd = shutil.which("dockerd")
    if dockerd is None:
        return None, "dockerd를 찾을 수 없어 JSON 문법 검증만 수행했습니다."
    try:
        proc = subprocess.run(
            [dockerd, "--validate", "--config-file", str(path)],
            capture_output=True,
            text=True,
            timeout=DOCKERD_VALIDATE_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"dockerd 검증을 실행하지 못했습니다: {exc}"

    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode == 0:
        return True, "dockerd --validate 통과"
    if "unknown flag" in output:
        return None, "이 Docker 버전은 --validate를 지원하지 않아 JSON 문법 검증만 수행했습니다."
    return False, output or f"dockerd --validate 실패 (종료 코드 {proc.returncode})"


# --------------------------------------------------------------------------- 적용


def _backup_path(path: Path, now: datetime) -> Path:
    base = path.with_name(f"{path.name}.bak.{now.strftime(BACKUP_TIMESTAMP_FORMAT)}")
    candidate, n = base, 1
    while candidate.exists():  # 같은 초에 두 번 실행해도 백업을 덮어쓰지 않는다
        candidate = base.with_name(f"{base.name}.{n}")
        n += 1
    return candidate


def _copy_ownership(src: Path, dst: Path) -> None:
    """원본의 권한/소유자를 새 파일에 복사한다 (DAEMON-007 권한이 수정으로 망가지지 않게)."""
    shutil.copymode(src, dst)
    if os.name == "posix":
        st = src.stat()
        try:
            os.chown(dst, st.st_uid, st.st_gid)
        except PermissionError:  # pragma: no cover — root가 아니면 소유자 변경 불가
            pass


def apply_plan(
    plan: RemediationPlan,
    *,
    validator: Validator = validate_with_dockerd,
    now: datetime | None = None,
) -> ApplyResult:
    """수정 계획을 실제 파일에 적용한다. 실패하면 원본을 보존/복원하고 RemediationError를 던진다."""
    if not plan.has_changes:
        raise RemediationError("적용할 변경 사항이 없습니다.")

    path = plan.daemon.path
    text = plan.new_text()
    if json.loads(text) != plan.after:  # pragma: no cover — 직렬화 자체 검증
        raise RemediationError("내부 오류: 수정 결과 직렬화가 일치하지 않습니다.")

    tmp = path.with_name(f".{path.name}.dockguard.tmp")
    backup: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        # 1) 임시 파일에 쓰고 검증 — 이 단계에서 실패하면 원본은 전혀 건드리지 않은 상태
        tmp.write_text(text, encoding="utf-8")
        if path.exists():
            _copy_ownership(path, tmp)
        else:
            os.chmod(tmp, NEW_FILE_MODE)
        ok, validation = validator(tmp)
        if ok is False:
            raise RemediationError(f"dockerd 설정 검증 실패 — 원본은 변경되지 않았습니다.\n{validation}")

        # 2) 백업 후 원자적 교체
        if path.exists():
            backup = _backup_path(path, now or datetime.now())
            shutil.copy2(path, backup)
        os.replace(tmp, path)
    except PermissionError as exc:
        raise RemediationError(f"파일을 쓸 권한이 없습니다 ({exc.filename}). sudo로 다시 실행하세요.") from exc
    finally:
        if tmp.exists():
            tmp.unlink()

    # 3) 다시 읽어 검증 — 실패하면 롤백
    reloaded = load_daemon_config(path)
    if not reloaded.usable or reloaded.data != plan.after:
        _rollback(path, backup)
        reason = reloaded.error or "다시 읽은 내용이 수정 계획과 다릅니다."
        raise RemediationError(f"적용 후 검증에 실패해 원본으로 복원했습니다: {reason}")

    return ApplyResult(path=path, backup_path=backup, validation=validation)


@dataclass
class NextStep:
    description: str
    command: str = ""
    warning: bool = False


def next_steps(plan: RemediationPlan, result: ApplyResult, platform: str | None = None) -> list[NextStep]:
    """적용 후 사용자가 해야 할 일. dockguard는 Docker를 직접 재시작하지 않는다 (안전 원칙)."""
    platform = platform or sys.platform
    steps: list[NextStep] = []
    linux = platform.startswith("linux")

    if not linux:
        steps.append(NextStep("Docker Desktop을 재시작해 설정을 반영하세요 (트레이 아이콘 → Restart)."))
    elif plan.apply_with == ApplyMethod.RELOAD:
        steps.append(NextStep("설정 리로드 — 컨테이너에는 영향이 없습니다", "sudo systemctl reload docker"))
    elif plan.live_restore_after and not plan.live_restore_before:
        steps.append(NextStep("1) live-restore를 먼저 활성화 (리로드, 컨테이너 영향 없음)", "sudo systemctl reload docker"))
        steps.append(
            NextStep("2) 데몬 재시작 — live-restore 덕분에 실행 중인 컨테이너는 유지됩니다", "sudo systemctl restart docker")
        )
    elif plan.live_restore_after:
        steps.append(NextStep("데몬 재시작 — live-restore가 켜져 있어 컨테이너는 유지됩니다", "sudo systemctl restart docker"))
    else:
        steps.append(
            NextStep(
                "데몬 재시작 — 모든 컨테이너가 재기동됩니다. 서비스 영향이 적은 시간에 수행하세요",
                "sudo systemctl restart docker",
                warning=True,
            )
        )

    if plan.requires_recreate:
        steps.append(
            NextStep(
                "기존 컨테이너에 새 기본값 반영 (named volume이 아닌 데이터는 사라질 수 있으니 `down`은 쓰지 마세요)",
                "docker compose up -d --force-recreate",
            )
        )
    steps.append(NextStep("결과 확인", "dockguard scan --category daemon"))

    if result.backup_path is not None:
        restore = (
            f"sudo cp {result.backup_path} {result.path}" if linux else f'copy "{result.backup_path}" "{result.path}"'
        )
    else:
        restore = f"sudo rm {result.path}" if linux else f'del "{result.path}"'
    steps.append(NextStep("문제가 생기면 원래대로 되돌리기 (이후 Docker 재시작)", restore))
    return steps


def _rollback(path: Path, backup: Path | None) -> None:
    if backup is not None:
        shutil.copy2(backup, path)
    elif path.exists():  # 새로 만든 파일이었다면 삭제
        path.unlink()
