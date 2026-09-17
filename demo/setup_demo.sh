#!/usr/bin/env bash
# 데모 시나리오 2 — "정전 후 백엔드가 RabbitMQ에 연결되지 않는다"를 재현한다.
#
#   bash demo/setup_demo.sh
#   dockguard diagnose connectivity demo-backend demo-rabbitmq --port 5672
#   bash demo/cleanup_demo.sh
#
# 만드는 것 (모두 demo- 접두사 — 기존 컨테이너·네트워크는 절대 건드리지 않는다):
#   demo-net-mq      RabbitMQ가 있는 네트워크
#   demo-net-app     백엔드가 있는 네트워크          ← 서로 다르다. 이게 사고의 핵심
#   demo-rabbitmq    5672/15672를 0.0.0.0에 공개한 채 실행 (NET-004도 함께 잡힌다)
#   demo-backend     RABBITMQ_HOST를 잘못 잡은 채 실행 (진단 5단계에서 잡힌다)
#
# 실제 RabbitMQ 대신 가벼운 alpine(sleep)을 쓴다. dockguard가 보는 것은 컨테이너의
# 네트워크 연결·공개 포트·환경변수이고, 그 구성은 사고 당시와 같다.
#
# examples/rabbitmq-incident/reproduce.sh 와의 차이:
#   그쪽은 사고 전체(컨테이너 5개, 멈춘 Redis, compose 라벨)를 재현해 CI E2E에서 쓴다.
#   이 스크립트는 **시연용 최소 구성**이다 — 30초 안에 만들어지고, 화면에 담기고, 바로 지워진다.
set -euo pipefail

IMAGE="${DEMO_IMAGE:-alpine:3.20}"

command -v docker >/dev/null || { echo "docker 명령을 찾을 수 없습니다." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker 데몬에 연결할 수 없습니다. (sudo가 필요할 수 있습니다)" >&2; exit 1; }

echo "▶ 기존 데모 리소스 정리"
bash "$(dirname "$0")/cleanup_demo.sh" >/dev/null 2>&1 || true

echo "▶ 네트워크 두 개 생성 — demo-net-mq / demo-net-app (서로 분리)"
docker network create demo-net-mq >/dev/null
docker network create demo-net-app >/dev/null

echo "▶ demo-rabbitmq — demo-net-mq 에서 기동, 5672·15672를 0.0.0.0에 공개"
docker run -d --name demo-rabbitmq --network demo-net-mq --restart unless-stopped \
  -p 5672:5672 -p 15672:15672 \
  "$IMAGE" sleep 3600 >/dev/null

echo "▶ demo-backend — demo-net-app 에서 기동 (다른 네트워크!), 접속 주소는 127.0.0.1"
docker run -d --name demo-backend --network demo-net-app --restart always \
  -e RABBITMQ_HOST=127.0.0.1 -e RABBITMQ_PORT=5672 -e RABBITMQ_USER=app \
  "$IMAGE" sleep 3600 >/dev/null

cat <<'EOF'

재현 완료 — 두 컨테이너는 실행 중이지만 서로 통신할 수 없는 상태입니다.

  증상: [backend] AMQPConnectionError: Connection refused (5672)

원인을 찾아보세요:

  dockguard diagnose connectivity demo-backend demo-rabbitmq --port 5672

끝나면 정리:

  bash demo/cleanup_demo.sh
EOF
