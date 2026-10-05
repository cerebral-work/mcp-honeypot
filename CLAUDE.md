# MCP Honeypot — CLAUDE.md

## Project Overview
Research-grade honeypot for observing agentic attacks against MCP servers.
Starts as self-hosted research, evolves into standalone product.

## Module Index
| Module | Doc | Purpose |
|--------|-----|---------|
| MCP Server | [docs/mcp-server.md](docs/mcp-server.md) | 13 fake MCP tools with dual instrumentation |
| OpenTelemetry | [docs/otel.md](docs/otel.md) | Protocol + tool-level tracing |
| Storage | [docs/storage.md](docs/storage.md) | Prometheus + Jaeger (Badger) |
| Grafana | [docs/grafana.md](docs/grafana.md) | 4 dashboards (35 panels) + alerting |
| Helm | [docs/helm.md](docs/helm.md) | K8s deployment + Docker Compose |
| Threat Model | [docs/threat-model.md](docs/threat-model.md) | Attack taxonomy + 7 detection flags |

## Server Modules
| File | Purpose |
|------|---------|
| `server/main.py` | MCP server (SSE), Starlette app, tool dispatch |
| `server/config.py` | Settings from env vars (frozen dataclass) |
| `server/transport_wrapper.py` | Per-message OTel spans, session ID, agent fingerprinting |
| `server/tagging.py` | 7 anomaly flags, session state, eviction |
| `server/instrumentation.py` | OTel tracer + meter setup, 3 custom metrics |
| `server/logging_config.py` | structlog JSON logging, session_id contextvar |
| `server/middleware.py` | Rate limiting (slowapi), security headers, CORS |
| `server/tools/registry.py` | 13 tools with JSON Schema definitions |
| `server/tools/fake_responses.py` | Plausible fake responses (never raises) |
| `server/tools/handlers/` | 4 category handlers + dispatch |

## Core Principles
1. Observe everything — protocol transport layer AND individual tool handlers
2. Mimic success — respond as if tools executed; never tip off the attacker
3. Tag aggressively — agent fingerprint, tool name, param patterns, anomaly flags on every span
4. Real-time visibility — Prometheus scrape ≤15s, Grafana auto-refresh 10s
5. Portable by default — containerised, Helm for K8s, Docker Compose for local dev

## Tech Stack
- Python 3.12, MCP SDK 1.6.0 (official Anthropic)
- OpenTelemetry SDK + Collector Contrib 0.96.0
- Prometheus 2.51.0 (metrics), Jaeger 1.55 (traces), Grafana 10.4.0 (dashboards)
- Helm + Kubernetes / Docker Compose

## Env Vars (config.py reads these)
`OTLP_ENDPOINT`, `OTLP_INSECURE`, `SERVICE_NAME`, `MCP_HOST`, `MCP_PORT`,
`HONEYPOT_PHASE`, `LOG_LEVEL`, `HONEYPOT_WEBHOOK_SECRET` (public phase only),
`MAX_REQUEST_BODY_BYTES` (default 1 MiB), `MESSAGES_RATE_LIMIT` (default `600/minute` per client IP)

## Scripts & Make
- `make help` — show all 20 targets
- `make setup` / `make up` / `make down` / `make test` / `make ci`
- `./scripts/*.sh` — individual convenience scripts

## Quickstart
    make setup
    make up
    # Or: docker compose up --build
    Grafana:    http://localhost:3000  (admin/honeypot)
    Jaeger:     http://localhost:16686
    Prometheus: http://localhost:9090
    MCP server: http://localhost:8000

## Demo
    python tools/adversarial_agent.py --persona all --delay 0.2
