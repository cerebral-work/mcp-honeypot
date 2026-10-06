# MCP Honeypot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/todie/mcp-honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/todie/mcp-honeypot/actions/workflows/ci.yml)

A research-grade honeypot for observing agentic attacks against MCP (Model Context Protocol) servers.
It exposes 13 plausible fake tools — filesystem access, secrets retrieval, web fetching, command
execution — while silently recording every call with full OpenTelemetry instrumentation.  The goal is
to fingerprint adversarial agents, catalogue their tool-use patterns, and surface anomalies in real time.

## Architecture

```
                        ┌──────────────────────────────────┐
  Attacking Agent ──────▶ MCP Honeypot  :8000 (SSE)        │
                        │  • 13 fake tools (4 categories)   │
                        │  • transport wrapper (spans)       │
                        │  • session state + 7 anomaly flags │
                        │  • rate limiting + security hdrs   │
                        └────────────┬─────────────────────┘
                                     │ OTLP gRPC :4317
                        ┌────────────▼─────────────────────┐
                        │  OTel Collector                    │
                        │  receivers:  OTLP 4317/4318       │
                        │  processors: memory_limiter, batch │
                        └──────┬───────────┬───────────────┘
                               │ OTLP      │ Prometheus
                ┌──────────────▼──┐   ┌───▼──────────────────┐
                │  Jaeger  :16686  │   │  Prometheus :9090     │
                │  (traces)        │   │  (metrics + 7 rules)  │
                └──────────────────┘   └───────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
                                   │  Grafana  :3000           │
                                   │  4 dashboards, 35 panels  │
                                   │  10s auto-refresh          │
                                   └───────────────────────────┘
```

## Quickstart

```bash
git clone https://github.com/todie/mcp-honeypot.git
cd mcp-honeypot
cp .env.example .env
docker compose up --build
```

| Service    | URL                        | Credentials     |
|------------|----------------------------|-----------------|
| MCP server | http://localhost:8000      | —               |
| Grafana    | http://localhost:3000      | admin / honeypot|
| Jaeger     | http://localhost:16686     | —               |
| Prometheus | http://localhost:9090      | —               |

## Run the Adversarial Agent

Light up all 4 dashboards with realistic attack traffic:

```bash
# Run all 5 attack personas (recon, exfiltrator, bruteforce, lateral, chaos)
docker run --rm --network mcp-honeypot_default \
  -v ./tools:/app/tools:ro \
  mcp-honeypot-mcp-honeypot \
  python tools/adversarial_agent.py --persona all --delay 0.2

# Or run a specific persona
python tools/adversarial_agent.py --persona recon
python tools/adversarial_agent.py --persona chaos --sessions 3
```

## Detection Logic

Every tool call is tagged with up to 7 anomaly flags:

| Flag | Trigger |
|------|---------|
| `credential_probe` | Any secrets-category tool call |
| `path_traversal` | `../` in any parameter value |
| `param_obfuscation` | Parameter value >20 chars that is valid base64 |
| `rapid_enumeration` | >10 calls within 5s in a single session |
| `replay_attempt` | Same tool+params hash seen within 60s |
| `exfiltration_chain` | Read-family call → network-family call within 300s |
| `privilege_escalation` | Tool category not seen before in this session |

## Environment Variables

All variables are documented in [`.env.example`](.env.example).  Key ones:

| Variable | Default | Description |
|----------|---------|-------------|
| `OTLP_ENDPOINT` | `otel-collector:4317` | OTLP gRPC endpoint |
| `OTLP_INSECURE` | `true` | Skip TLS for OTLP (only `false` disables) |
| `SERVICE_NAME` | `mcp-honeypot` | Service name in traces/metrics |
| `MCP_HOST` | `0.0.0.0` | MCP server bind address |
| `MCP_PORT` | `8000` | MCP server port |
| `HONEYPOT_PHASE` | `research` | Phase: `research` or `public` |
| `LOG_LEVEL` | `INFO` | Structured log level |
| `GRAFANA_ADMIN_PASSWORD` | `honeypot` | Grafana admin password |

## Scripts

| Script | Purpose |
|--------|---------|
| `./scripts/setup.sh` | Create `.env`, Python venv, install deps, pre-commit hooks |
| `./scripts/lint.sh` | Ruff lint + format check + pyright |
| `./scripts/test.sh` | Run pytest unit tests (no Docker) |
| `./scripts/build.sh` | Build server Docker image |
| `./scripts/up.sh` | Start full stack via Docker Compose |
| `./scripts/down.sh` | Stop stack (`--clean` to remove volumes) |
| `./scripts/smoke.sh` | Run smoke tests against running stack |
| `./scripts/protect-main.sh` | Apply GitHub branch protection rules |
| `make help` | Show all 20 Makefile targets |

## Testing

```bash
# Unit tests (389 as of 2026-10-05, no Docker required; 3 integration tests self-skip without the stack)
make test

# Full CI locally (lint + typecheck + test + secrets scan + Docker build)
make ci

# Smoke test against running stack
make smoke

# Run adversarial agent for e2e validation
python tools/adversarial_agent.py --persona all
```

## Contributing

**Branch naming:** `<type>/<short-description>` — e.g. `feat/transport-wrapper`, `fix/otel-exporter`.

**PR expectations:**
- Keep PRs focused on one subtask (see [`PLAN.md`](PLAN.md) for the task list).
- All CI jobs must pass: ruff (lint + format), pyright (types), pytest (unit tests), gitleaks (secrets), Docker build.
- Pre-commit hooks run automatically: `ruff`, `pyright`, `gitleaks`, `hadolint`, `yamllint`.
- Add or update tests for any new detection logic.

## Further Reading

| Document | Purpose |
|----------|---------|
| [docs/mcp-server.md](docs/mcp-server.md) | Fake MCP endpoints, dual instrumentation |
| [docs/otel.md](docs/otel.md) | OTel protocol + tool-level tracing |
| [docs/storage.md](docs/storage.md) | Prometheus + Jaeger setup |
| [docs/grafana.md](docs/grafana.md) | Dashboard design + alerting |
| [docs/helm.md](docs/helm.md) | Kubernetes deployment (Phase 2) |
| [docs/threat-model.md](docs/threat-model.md) | Attack taxonomy + detection logic |
| [PLAN.md](PLAN.md) | Full implementation plan with task breakdown |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |

## License

[MIT](LICENSE) — Copyright (c) 2026 Christian M. Todie
