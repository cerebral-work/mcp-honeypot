# Roadmap

## Release Path

| Version | Codename | Focus | Status |
|---------|----------|-------|--------|
| v0.1.0 | **Core** | Static tools + telemetry pipeline | Released |
| v0.1.1 | **Hardened** | Agent fix, 282 tests, Docker hardening, release tooling | Released |
| v0.2.0 | **Dynamic** | OpenAPI mode + ToolLoader protocol | [Spec](spec-openapi-mode.md) |
| v0.3.0 | **Plugins** | Provider system + YAML tools + hot-reload | [Spec](spec-plugin-system.md) |
| v0.4.0 | **Deception** | Stateful FS + session recording + replay + classifier | Planned |
| v0.5.0 | **Intelligence** | Canary tokens + STIX export + cross-session correlation | Planned |
| v0.6.0 | **Platform** | Admin API + CLI + multi-tenancy + TLS/JA3 | Planned |
| v1.0.0 | **Standard** | Benchmark suite + fuzzer + public threat feed | Planned |

See [vision.md](vision.md) for the full product vision.

## v0.2.0 — Dynamic Tools

**Goal:** Mimic any API by consuming an OpenAPI 3.x spec.

See [spec-openapi-mode.md](spec-openapi-mode.md) for the full specification.

**Key deliverables:**
- `ToolLoader` protocol (internal interface, seed of the plugin system)
- OpenAPI 3.x spec parser → `ToolMeta` generation
- JSON Schema → plausible fake value generation
- Automatic category mapping (heuristic + override)
- `HONEYPOT_MODE=static|openapi|combined` configuration
- Zero behavior change for existing users (default mode = static)

**Estimated effort:** 3-5 sessions

## v0.3.0 — Plugin System

**Goal:** Public `ToolProvider` protocol. YAML tool definitions. Hot-reload.

See [spec-plugin-system.md](spec-plugin-system.md) for the full specification.

**Key deliverables:**
- `ToolProvider` protocol with `owns_tool()`, `health_check()`, `reload()`
- `ProviderRegistry` for discovery, loading, merging, conflict resolution
- YAML provider with 13 template functions
- Hot-reload via filesystem watch
- Community provider packaging via entry_points
- Backward compatibility shim for v0.2.0 config

**Estimated effort:** 5-8 sessions

## v0.4.0 — Deep Deception

**Goal:** Deception convincing enough to hold agents for extended sessions.

**Key deliverables:**
- Stateful fake filesystem (write→read consistency within a session)
- Session recording (raw JSON-RPC stream capture to disk)
- Session replay (`honeypot replay SESSION_ID --against RULES`)
- Context-aware responses (vary based on what agent has already seen)
- Agent behavior labels (recon, exfiltrator, bruteforce, lateral, scanner, targeted)
- Rule-based classifier with configurable patterns

**Estimated effort:** 5-8 sessions

## v0.5.0 — Intelligence

**Goal:** Close the loop — detect when stolen data is used externally.

**Key deliverables:**
- Canary token integration (AWS, GitHub, Slack webhook tokens)
- Token lifecycle: issue → track → alert on use
- Cross-session agent correlation (persistent fingerprint DB)
- STIX 2.1 export for threat sharing
- Agent classification ML pipeline (offline, batch, optional)
- Canary Alerts dashboard

**Estimated effort:** 5-8 sessions

## v0.6.0 — Platform

**Goal:** Production deployment for Phase 3 (public exposure).

**Key deliverables:**
- Admin REST API (`:8080`) for session management, rule CRUD, provider CRUD
- `honeypot` CLI tool (init, up, status, export, replay, benchmark)
- Multi-tenancy (namespaced endpoints, per-tenant dashboards)
- TLS termination + JA3 fingerprinting
- Behavioral rate limiting (session-based, not IP-based)
- Session Timeline + Agent Classification + Provider Health dashboards

**Estimated effort:** 8-10 sessions

## v1.0.0 — The Standard

**Goal:** The definitive MCP security tool.

**Key deliverables:**
- MCP protocol fuzzer (send malformed responses, test client safety)
- Benchmark suite for MCP client safety scoring
- Public threat intelligence feed
- Hosted offering (honeypot-as-a-service) documentation
- Research playbooks and case studies
- GraphQL and gRPC providers

**Estimated effort:** 5-8 sessions

## Feature Complete Definition

The honeypot is "feature complete" at **v0.4.0** — that's where a researcher
can publish a paper. It has dynamic tools, a plugin system, convincing
deception, and session recording/replay. Everything after v0.4.0 is about
scale, intelligence, and community.

The honeypot is "product complete" at **v1.0.0** — that's where it's a
platform that organizations deploy, a tool that MCP client developers test
against, and a community that shares threat intelligence.
