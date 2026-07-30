# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-07-30)


### Features

* apply terrarium federation standards ([b75804d](https://github.com/cerebral-work/mcp-honeypot/commit/b75804d1779036d68b4b9349d81ca7eef23ea95e))


### Bug Fixes

* **deps:** align opentelemetry-instrumentation-asgi with the 0.53b0 line (unbreaks all PR CI) ([#33](https://github.com/cerebral-work/mcp-honeypot/issues/33)) ([5b2e420](https://github.com/cerebral-work/mcp-honeypot/commit/5b2e42009143d3175f22aa64dd3aff3e96fc71eb))

## [Unreleased]

### Added
- Regression tests for adversarial agent, export tool, and test harness (+96 tests)
- Sessions active gauge metric (mcp_sessions_active)
- Grafana alert notification routing (webhook contact points)
- Data export tool (tools/export.py) — JSON traces, CSV metrics, summaries
- 6 runnable examples (basic client, multi-session, flag triggers, telemetry check, custom agent, pytest integration)
- Tests for transport_wrapper, middleware, handlers, main.py (+51 tests)

### Changed
- Adversarial agent SSE lifecycle fixed — keeps connection alive, reads responses
- Docker Compose hardened: 127.0.0.1 bindings, resource limits, non-root Dockerfile
- Grafana anonymous auth disabled
- CI now lints tools/ and examples/

### Fixed
- docs/threat-model.md: updated to match SHA-256 + TTL implementation
- docs/storage.md: Badger env vars, root user, CLI retention flags
- docs/mcp-server.md: Starlette not FastAPI, correct env var names

## [0.1.0] - 2026-03-31

### Added
- MCP honeypot server with SSE transport and 13 fake tools
- 7 anomaly detection flags: credential_probe, path_traversal, param_obfuscation, rapid_enumeration, replay_attempt, exfiltration_chain, privilege_escalation
- OpenTelemetry instrumentation (traces + metrics via OTLP gRPC)
- Structured JSON logging with session correlation (structlog)
- Rate limiting (60/min global, 10/min SSE) + security headers middleware
- Transport wrapper with agent fingerprinting (User-Agent, MCP clientInfo)
- Docker Compose stack: honeypot, OTel Collector, Prometheus, Jaeger, Grafana
- 4 Grafana dashboards (35 panels): Attack Summary, Agent Drilldown, Anomaly Monitor, Tool Intelligence
- 7 Prometheus recording rules for tool co-occurrence analysis
- Helm chart (Phase 2 scaffolding) for Kubernetes deployment
- Adversarial agent with 5 attack personas (recon, exfiltrator, bruteforce, lateral, chaos)
- Interactive agent simulator with live telemetry display
- Test harness: async MCP client, telemetry validator, attack scenarios
- 135 unit/integration tests
- CI pipeline: ruff lint/format, pyright typecheck, pytest, gitleaks secrets scan, Docker build
- Pre-commit hooks: ruff, pyright, gitleaks, hadolint, yamllint
- Makefile with 20 targets
- 8 convenience scripts (setup, lint, test, build, up, down, smoke, protect-main)
- MIT license, SECURITY.md, .dockerignore, .editorconfig, Dependabot

[Unreleased]: https://github.com/todie/mcp-honeypot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/todie/mcp-honeypot/releases/tag/v0.1.0
