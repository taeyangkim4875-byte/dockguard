#!/usr/bin/env bash
# 정전 후 재부팅된 서버의 "네트워크 상태"를 실제 Docker로 재현한다.
#
# 실제 RabbitMQ·Redis 대신 가벼운 alpine 컨테이너(sleep)를 쓰지만, 컨테이너 이름·compose 라벨·네트워크·
# 포트 공개·재시작 정책은 사고 당시와 같다. dockguard가 보는 것은 바로 이 구성이다.
#
#   bash examples/rabbitmq-incident/reproduce.sh
#   dockguard scan -c network --deps examples/rabbitmq-incident/dependencies.yaml
#   bash examples/rabbitmq-incident/cleanup.sh
set -euo pipefail

IMAGE="alpine:3.20"
NETWORK="messaging_mq-net"
compose_labels() { # compose가 붙이는 라벨을 흉내 낸다 (프로젝트 messaging)
  echo "--label com.docker.compose.project=messaging --label com.docker.compose.service=$1"
}

echo "▶ 네트워크 ${NETWORK} 생성 (compose 프로젝트 messaging의 mq-net)"
docker network create "${NETWORK}" >/dev/null

echo "▶ rabbitmq — 5672/15672를 0.0.0.0에 공개한 채로 기동 (NET-004)"
# shellcheck disable=SC2046
docker run -d --name rabbitmq --network "${NETWORK}" --restart unless-stopped \
  -p 5672:5672 -p 15672:15672 $(compose_labels rabbitmq) "${IMAGE}" sleep 3600 >/dev/null

echo "▶ service-manager, report-worker — 같은 네트워크에서 정상 기동"
# shellcheck disable=SC2046
docker run -d --name service-manager --network "${NETWORK}" --restart unless-stopped \
  $(compose_labels service-manager) "${IMAGE}" sleep 3600 >/dev/null
# shellcheck disable=SC2046
docker run -d --name messaging-report-worker-1 --network "${NETWORK}" --restart unless-stopped \
  $(compose_labels report-worker) "${IMAGE}" sleep 3600 >/dev/null

echo "▶ redis — 재시작 정책이 없어 재부팅 후 올라오지 않은 상태 (생성만 됨)"
# shellcheck disable=SC2046
docker create --name messaging-redis-1 --network "${NETWORK}" \
  $(compose_labels redis) "${IMAGE}" sleep 3600 >/dev/null

echo "▶ backend-container — 장애 복구 중 compose 밖에서 docker run으로 다시 띄움 (기본 bridge에만 연결)"
docker run -d --name backend-container --restart always -p 127.0.0.1:8080:8080 \n  -e RABBITMQ_HOST=203.0.113.50 -e RABBITMQ_PORT=5672 -e RABBITMQ_USER=app \n  "${IMAGE}" sleep 3600 >/dev/null

echo
echo "재현 완료. 이제 진단해 보세요:"
echo "  dockguard scan -c network --deps examples/rabbitmq-incident/dependencies.yaml --explain"
echo "  dockguard diagnose connectivity backend-container rabbitmq --port 5672"
