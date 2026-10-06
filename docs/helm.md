# Helm Chart

## Chart Structure
    helm/
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
        ├── mcp-honeypot/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   └── configmap.yaml
        ├── otel-collector/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   └── configmap.yaml
        ├── prometheus/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   ├── configmap.yaml
        │   └── pvc.yaml
        ├── jaeger/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   └── pvc.yaml
        └── grafana/
            ├── deployment.yaml
            ├── service.yaml
            ├── configmap.yaml
            └── pvc.yaml

## values.yaml

Condensed from the chart's `helm/values.yaml` (read that file for the exact
keys; every image tag is pinned — the chart never uses `latest`):

    global:
      namespace: mcp-honeypot
      imagePullPolicy: IfNotPresent

    honeypot:
      image: { repository: ghcr.io/todie/mcp-honeypot, tag: "0.1.0" }
      replicas: 1
      port: 8000

    otelCollector:
      image: { repository: otel/opentelemetry-collector-contrib, tag: "0.96.0" }
      grpcPort: 4317
      httpPort: 4318
      prometheusExportPort: 8889

    prometheus:
      image: { repository: prom/prometheus, tag: "v2.51.0" }
      port: 9090
      retentionTime: "30d"
      retentionSize: "10GB"
      storage: 10Gi

    jaeger:
      image: { repository: jaegertracing/all-in-one, tag: "1.55" }
      uiPort: 16686
      otlpGrpcPort: 4317
      storage: 20Gi
      # No span TTL key in the chart; the 168 h trace TTL lives in the
      # Compose stack (BADGER_SPAN_STORE_TTL).

    grafana:
      image: { repository: grafana/grafana, tag: "10.4.0" }
      port: 3000
      storage: 5Gi
      # The chart ships a default admin login; override it for production.
      adminUser: admin
      adminPassword: honeypot

## Docker Compose (Local Dev)
    version: "3.9"
    services:
      mcp-honeypot:
        build: ./server
        ports: ["8000:8000", "8001:8001"]
        environment:
          OTEL_EXPORTER_OTLP_ENDPOINT: http://otel-collector:4317
          OTEL_SERVICE_NAME: mcp-honeypot

      otel-collector:
        image: otel/opentelemetry-collector-contrib:latest
        volumes:
          - ./collector/config.yaml:/etc/otel/config.yaml
        command: ["--config=/etc/otel/config.yaml"]
        ports: ["4317:4317", "4318:4318", "8889:8889"]

      prometheus:
        image: prom/prometheus:latest
        volumes:
          - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
          - prometheus-data:/prometheus
        ports: ["9090:9090"]

      jaeger:
        image: jaegertracing/all-in-one:latest
        environment:
          COLLECTOR_OTLP_ENABLED: "true"
          SPAN_STORAGE_TYPE: badger
          BADGER_EPHEMERAL: "false"
          BADGER_DIRECTORY_VALUE: /badger/data
          BADGER_DIRECTORY_KEY: /badger/key
        volumes:
          - jaeger-data:/badger
        ports: ["16686:16686", "14250:14250"]

      grafana:
        image: grafana/grafana:latest
        volumes:
          - ./dashboards/provisioning:/etc/grafana/provisioning
          - ./dashboards/json:/var/lib/grafana/dashboards
          - grafana-data:/var/lib/grafana
        ports: ["3000:3000"]
        environment:
          GF_SECURITY_ADMIN_USER: admin
          GF_SECURITY_ADMIN_PASSWORD: honeypot

    volumes:
      prometheus-data:
      jaeger-data:
      grafana-data:

## Deploy Commands
    # Local
    docker-compose up --build

    # Helm install
    helm install mcp-honeypot ./helm \
      --namespace mcp-honeypot \
      --create-namespace \
      --set grafana.adminPassword=your-password

    # Upgrade
    helm upgrade mcp-honeypot ./helm --namespace mcp-honeypot
