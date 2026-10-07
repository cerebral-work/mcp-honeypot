# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-10-07)


### Features

* apply terrarium federation standards ([b75804d](https://github.com/cerebral-work/mcp-honeypot/commit/b75804d1779036d68b4b9349d81ca7eef23ea95e))
* **server:** cap request bodies at 1 MiB (TOD-1056) ([93b90cd](https://github.com/cerebral-work/mcp-honeypot/commit/93b90cd3cc964e07a645e2e06adfa523b3bc6b11))
* **server:** per-client-IP rate limit on POST /messages (TOD-1056) ([f2a2ded](https://github.com/cerebral-work/mcp-honeypot/commit/f2a2dedf6c87ffa43f61fa758a6be574e74d0dc3))
* **server:** protocol_tagging module for MCP-native detections D1-D6 ([3bcaa5d](https://github.com/cerebral-work/mcp-honeypot/commit/3bcaa5d62ef45b3e0dd2b84f5214a5c6ab5b0886))
* **server:** put protocol findings on message spans and the anomaly counter ([002de99](https://github.com/cerebral-work/mcp-honeypot/commit/002de997351a4658cb0d37d5bd611df1ec8765ee))


### Bug Fixes

* **deps:** align OpenTelemetry packages on 1.45.0 / 0.66b0 ([8fff849](https://github.com/cerebral-work/mcp-honeypot/commit/8fff84958a506272bfb91ad97c875619e5115bab))
* **deps:** align opentelemetry-instrumentation-asgi with the 0.53b0 line (unbreaks all PR CI) ([#33](https://github.com/cerebral-work/mcp-honeypot/issues/33)) ([5b2e420](https://github.com/cerebral-work/mcp-honeypot/commit/5b2e42009143d3175f22aa64dd3aff3e96fc71eb))
* **server:** give tool handlers the caller's session id ([d6dec5f](https://github.com/cerebral-work/mcp-honeypot/commit/d6dec5f0609fee14c43741ddaa29a146552b9299))
* **server:** harden protocol_tagging against evasion and oversized input ([21326af](https://github.com/cerebral-work/mcp-honeypot/commit/21326af6d121cda147c9920e9a336a4388292f6b))
* **server:** stop every GET /sse returning 500 ([fc7f96a](https://github.com/cerebral-work/mcp-honeypot/commit/fc7f96a2cf2bb6b27f299c53dd2d395c75a5efdd))
* **server:** stop every POST /messages raising after the SDK replies ([015362f](https://github.com/cerebral-work/mcp-honeypot/commit/015362f43d83ac038a4cc7a7106e35d13faa6680))


### Documentation

* add the survey, gap analysis and citation check behind the spec ([c5d5e52](https://github.com/cerebral-work/mcp-honeypot/commit/c5d5e527fc5a3d16ded1e94cab3be5c5b73f6f84))
* document the protocol-level detections ([67baeaf](https://github.com/cerebral-work/mcp-honeypot/commit/67baeafd3c7cb1fb256cd7b745e0b3bbce2c7a31))
* name D2 by its flag, lifecycle_violation ([fb6377a](https://github.com/cerebral-work/mcp-honeypot/commit/fb6377a1ed86afaf6ddf3edef8a270f937da97d8))
* reconcile the five conflicts found by the R&D site review ([c083980](https://github.com/cerebral-work/mcp-honeypot/commit/c08398016bdb26fd7e172cd196eea8f34af4b362))
* record operator rulings on spec decisions 1, 2, 4 and 6 ([4bbc486](https://github.com/cerebral-work/mcp-honeypot/commit/4bbc4865c3e834a23052ec4f9749bb7c8e9d32c0))
* record operator rulings on spec decisions 3, 5, 7, 8 and 9 ([1d07bbb](https://github.com/cerebral-work/mcp-honeypot/commit/1d07bbb30d5468bfd5c03287b68aa3b9e9fc1531))
* spec for MCP-native detections ([7da0512](https://github.com/cerebral-work/mcp-honeypot/commit/7da0512c7465135e1f8d357d8aff6a93ed15c54e))

## [Unreleased]

### Added
- Request body size cap (`MAX_REQUEST_BODY_BYTES`, default 1 MiB): larger bodies get 413 before the SDK parses them (TOD-1056)
- Per-client-IP rate limit on `POST /messages` (`MESSAGES_RATE_LIMIT`, default 600/minute): excess messages get 429 and a `messages_rate_limited` log event (TOD-1056)
- MCP-native protocol detections (spec P1): `unknown_method`, `lifecycle_violation`, `feature_enumeration`, `protocol_version_anomaly`, `hidden_unicode` and `ansi_escape` on every inbound message span, counted in `mcp_anomalies_total`
- Message spans record `mcp.message_kind`, `mcp.jsonrpc.id`, the client's `protocolVersion` and capability keys
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
- `POST /messages` no longer raises "Exception in ASGI application" after the SDK has replied
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
