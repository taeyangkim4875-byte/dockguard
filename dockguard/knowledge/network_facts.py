"""네트워크 룰이 쓰는 보안 지식 상수."""

from __future__ import annotations

# 외부(0.0.0.0)에 열려 있으면 안 되는 포트 — 컨테이너 포트 기준 (NET-004)
# 대부분 "내부망에서만 쓴다"는 가정으로 인증이 약하거나 기본 계정이 남아 있기 쉬운 서비스다.
SENSITIVE_PORTS: dict[int, str] = {
    5672: "RabbitMQ AMQP",
    15672: "RabbitMQ 관리 UI",
    25672: "RabbitMQ 클러스터 통신",
    4369: "Erlang epmd (RabbitMQ)",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    1433: "SQL Server",
    1521: "Oracle DB",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
    9200: "Elasticsearch HTTP",
    9300: "Elasticsearch 노드 통신",
    5601: "Kibana",
    9092: "Kafka",
    2181: "ZooKeeper",
    2379: "etcd",
    8500: "Consul",
    5984: "CouchDB",
    8086: "InfluxDB",
    2375: "Docker API (평문, 인증 없음)",
    2376: "Docker API (TLS)",
}

# compose 라벨 — 실행 중인 컨테이너를 compose 서비스와 연결할 때 사용
COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
COMPOSE_SERVICE_LABEL = "com.docker.compose.service"
