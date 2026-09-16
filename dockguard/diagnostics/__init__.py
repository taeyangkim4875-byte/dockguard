"""진단(diagnose) 엔진 — 이미 발생한 증상에서 근본 원인을 추론한다.

스캔(scan)이 "무엇이 위험한가"를 미리 찾는 예방이라면, 진단은 "왜 안 되는가"를 사후에 추적한다.
새 진단을 추가하려면 Diagnosis 하위 클래스를 만들고 아래 레지스트리에 등록하면 된다.
"""

from __future__ import annotations

from dockguard.diagnostics.base import Diagnosis, DockerDiagnosis
from dockguard.diagnostics.connectivity import ConnectivityDiagnosis
from dockguard.diagnostics.models import DiagnosisResult, DiagnosisStep

# 진단 id → 클래스
DIAGNOSES: dict[str, type[Diagnosis]] = {
    ConnectivityDiagnosis.id: ConnectivityDiagnosis,
}

__all__ = [
    "DIAGNOSES",
    "Diagnosis",
    "DockerDiagnosis",
    "ConnectivityDiagnosis",
    "DiagnosisResult",
    "DiagnosisStep",
]
