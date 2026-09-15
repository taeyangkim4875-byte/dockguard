#!/usr/bin/env bash
# reproduce.sh가 만든 컨테이너와 네트워크를 지운다 (다른 컨테이너는 건드리지 않는다).
set -uo pipefail

docker rm -f rabbitmq service-manager messaging-report-worker-1 messaging-redis-1 backend-container >/dev/null 2>&1
docker network rm messaging_mq-net >/dev/null 2>&1
echo "정리 완료"
