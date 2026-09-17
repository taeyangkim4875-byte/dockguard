#!/usr/bin/env bash
# 데모 정리 — demo/setup_demo.sh 가 만든 것만 지운다 (demo- 접두사).
#
#   bash demo/cleanup_demo.sh
set -euo pipefail

command -v docker >/dev/null || { echo "docker 명령을 찾을 수 없습니다." >&2; exit 1; }

echo "▶ 데모 컨테이너 제거"
docker rm -f demo-backend demo-rabbitmq >/dev/null 2>&1 || true

echo "▶ 데모 네트워크 제거"
docker network rm demo-net-app demo-net-mq >/dev/null 2>&1 || true

echo "정리 완료 (demo- 로 시작하는 리소스만 제거했습니다)"
