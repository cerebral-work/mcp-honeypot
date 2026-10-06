> Provenance: Written 2026-10-04 against `590ede9`, read-only. Line numbers refer to that commit. References to `gaps-kimi.md` mean `2026-10-04-code-gap-analysis.md`, and `survey-fugu.md` means `2026-10-04-mcp-attack-survey.md`. Bug B1 (session id `unknown`) and the `GET /sse` 500 were fixed after this was written, by #47 and #46.

# Code gap analysis — MCP-native detections

Scope: `server/main.py`, `server/transport_wrapper.py`, `server/tagging.py`,
`server/tools/registry.py`, `server/instrumentation.py`, `server/tools/handlers/*`,
tests. Repo: `mcp-honeypot-mcp-native-detections` @ 590ede9 (`feat/mcp-native-detections`).
SDK facts verified against the **deployed pin `mcp==1.6.0`** (`server/requirements.txt:2`,
wheel inspected) and the locally installed `mcp 1.28.1` where behavior differs.

## 1. Protocol-level signals captured today

| Signal | Captured at | Lands on |
|---|---|---|
| JSON-RPC method name | `transport_wrapper.py:164` (`msg_dict.get("method")`) | Span **name** `mcp.<method>` + attr `mcp.method` (`transport_wrapper.py:179-186`); debug log `mcp_message_received` (`transport_wrapper.py:191-196`). No metric, no flag. |
| `initialize` → `clientInfo.name/version` | `transport_wrapper.py:57-69`, refine at `:168-172` | Span attr `agent.id` (`:182`). Refine happens before the span is started, so the initialize span itself carries the refined id. No metric/log of the raw value. |
| `initialize` → `protocolVersion` | — | **Nowhere.** `_extract_agent_from_initialize` (`transport_wrapper.py:57-69`) reads only `clientInfo`. |
| `initialize` → `capabilities` | — | **Nowhere** (same). |
| `clientInfo` extra fields | — | **Nowhere.** |
| `User-Agent` header | `transport_wrapper.py:47-55` | `agent.id` span attr (`:182`) + `sse_connection_opened` log (`main.py:125-130`). |
| Remote IP | `main.py:117-119` | Session-id derivation input (`transport_wrapper.py:36-38`) + two log lines (`main.py:125-130`, `:150-153`). **Not** a span attribute. |
| `Host`, `Origin`, `Referer`, `Accept` headers | — | **Nowhere.** Headers are read once (`main.py:120`) and only UA is extracted. |
| `X-Forwarded-For` | `middleware.py:37-44` | Rate-limit key only; never recorded. |
| honeypot session id (sha256(ip:connect_ts)[:16]) | `transport_wrapper.py:36-38` | Span attr `mcp.session_id` (`:183`); logs via `session_id_var` (`:175`) — **broken on the tool-call path**, see bug B1. |
| SDK session uuid (`/messages?session_id=`) | SDK `sse.py` (1.6.0: `:149` area) | **Nowhere** in honeypot code — never correlated with the honeypot session id. |
| Message size (JSON chars) | `transport_wrapper.py:166` | Span attr `mcp.message_size` (`:186`). |
| JSON-RPC `id` | — | **Nowhere.** No request/response correlation, no id-reuse detection possible. |
| Request vs notification distinction | — | **Nowhere.** Both become identical `mcp.<method>` spans. |
| Known notifications (`notifications/initialized`, `cancelled`, `progress`) | wrapper sees them pre-dispatch | Span + debug log only; SDK then drops them (no handlers registered, 1.6.0 `server.py:159`). |
| Unknown method string | wrapper sees it (passed transport validation) | Span `mcp.<attacker-string>` + debug log; then **session teardown** (see §2). No metric, no flag. |
| Malformed frame (bad JSON / bad envelope) | SDK `sse.py:165-167` (1.6.0) | HTTP 400 + `logger.exception("Failed to parse message")` → JSON log via root logger. **Never reaches the wrapper** → no span, no metric, no session context. Fuzzing is invisible in traces. |
| POST to unknown/expired session uuid | SDK `sse.py:155-156` (1.6.0) | HTTP 404 + SDK warning log. Nowhere in honeypot. |
| Tool call: name + params | `main.py:71-110` → `tools/handlers/secrets.py:29-35` (same pattern in all 4 handlers) | Span `tool.<name>`; attrs `mcp.tool`, `mcp.tool.params_json`, `mcp.tool.param_count`, `anomaly.flags`; metrics `mcp_tool_calls_total` (`secrets.py:38`), `mcp_anomalies_total` (`:42`); `honeypot.response_*` attrs (`:50-51`). |
| Rate-limit hit | `middleware.py:77-95` | Warning log + `honeypot.rate_limited` on the *current* span — but `/messages` has no active span, so only `/sse` hits are tagged. |
| `POST /messages` HTTP exchange itself | `main.py:154-158` | **Nowhere** — no span, no log, no rate-limit decorator (slowapi `SlowAPIMiddleware` is never added in `middleware.py:163-185`, so the "60/minute" default limit is inert; only `/sse`'s decorator is live). |

## 2. Methods the server answers, and unknown-method behavior

Answered (mcp==1.6.0 pin):

- `ping` — auto-registered by the SDK (1.6.0 `server.py:141`), empty result.
- `initialize` — SDK handshake (`ServerSession`, `mcp/server/session.py`); server options built at `main.py:139-143`.
- `tools/list` — `main.py:56-68` (13 tools from `TOOL_REGISTRY`, `tools/registry.py:31`).
- `tools/call` — `main.py:71-110`. **Any** tool name is "answered": unknown names fall back to the filesystem handler (`tools/handlers/__init__.py:36-39`) and get a plausible fake response.

Validates but unanswered → JSON-RPC **-32601 Method not found** (1.6.0 `server.py:567`):
`resources/list`, `resources/read`, `resources/templates/list`, `resources/subscribe`,
`resources/unsubscribe`, `prompts/list`, `prompts/get`, `logging/setLevel`,
`completion/complete` — all in the SDK `ClientRequest` union (1.6.0 `types.py`,
`class ClientRequest`) but no handler registered.

**Unknown method string (not in the union): session kill.** The 1.6.0 `_receive_loop`
request branch has **no** validation-error handler (`session.py:306-327`):
`ClientRequest.model_validate` raises `ValidationError`, which escapes the receive
loop and tears the session down — the SSE connection drops with **no JSON-RPC error
response**. The only artifact is a stdlib exception log (JSON-formatted via
`logging_config.py`). Fixed upstream: installed 1.28.1 responds -32602 "Invalid
request parameters" and keeps the session (`session.py:383-393`). Consequence for
detection: on the deployed pin, an attacker's very first off-schema probe kills the
session, so method enumeration looks like connect → one probe → disconnect.

Unknown **notification** method: validation fails → warning log only, session survives
(1.6.0 `session.py:344-349`). Known notifications are no-ops (empty
`notification_handlers`, 1.6.0 `server.py:159`).

## 3. Where new detections hook in

(a) **Per-message protocol checks** — `InstrumentedTransport._instrument_message`,
`transport_wrapper.py:140-197`. It already sees every transport-validated message
pre-dispatch with method, full `msg_dict`, and size; add extraction of
`protocolVersion`, `capabilities`, JSON-RPC `id`, request-vs-notification kind, and
unknown-method counting here. Caveat: fix bug B2 first or this hook is dead on any
SDK ≥ ~1.9. For **malformed frames** (never reach the wrapper) the hook is
`handle_messages` (`main.py:154-158`) — wrap `sse_transport.handle_post_message` and
count 400/404 responses, or subclass `SseServerTransport`.

(b) **Per-session sequence checks** — today the only sequence state lives in
`tagging.detect_anomalies` (`tagging.py:118-191`), keyed by `session_id`, fed only
from tool-call handlers (e.g. `secrets.py:29`). A protocol-level sequence detector
(initialize-before-tools, missing `notifications/initialized`, notification floods,
method mix per session) belongs in `_instrument_message` with per-connection state on
`InstrumentedTransport` (it already has `self.session_id`, `_connect_ts`), delegating
flag logic to a new tagging function that takes method names rather than tool names.
**Fix bug B1 first** — with all sessions keyed `"unknown"`, any sequence state is
cross-contaminated garbage.

## 4. Bugs found

**B1 — `session_id_var` never reaches the tool-call path (severe).**
`transport_wrapper.py:175` sets the contextvar inside the `_pump` task
(`transport_wrapper.py:120-127`). ContextVar sets do not cross anyio task boundaries
(verified empirically this session: pump task sets, consumer task reads `None`).
`call_tool` therefore always reads `"unknown"` (`main.py:88`). Consequences:
- every `tool.*` span carries `mcp.session_id="unknown"` (`main.py:93`);
- **all sessions share one tagging bucket** — `detect_anomalies(..., "unknown")`
  (`tagging.py:124-128`), so `rapid_enumeration`, `replay_attempt`,
  `exfiltration_chain`, `privilege_escalation` cross-contaminate between unrelated
  agents (agent A's `read_file` primes agent B's `exfiltration_chain`);
- metric label `agent_id` on `mcp_tool_calls_total` is always `"unknown"`
  (`secrets.py:38` and siblings);
- handler-context log lines lack `session_id` (`logging_config.py:29-37`).
No test covers it: `tests/test_main.py` never references `session_id_var`, and the
tagging unit tests call `detect_anomalies` directly with explicit ids.

**B2 — wrapper silently dies on SDK ≥ ~1.9 (latent).** `transport_wrapper.py:150`
assumes messages have `.root` (true for pinned 1.6.0: `sse.py:88` yields
`JSONRPCMessage`). Newer SDKs yield `SessionMessage` (installed 1.28.1 `sse.py:140`)
which has `.message`, not `.root` → `msg_dict={}` → every span becomes `mcp.unknown`,
and method/size/agent-refinement all silently stop. The requirements pin masks it in
Docker; any SDK bump kills per-method tracing without an error. (Even on 1.6.0,
`Exception` items on the stream become `mcp.unknown` spans.)

**B3 — eviction is access-triggered only; unbounded growth across session ids.**
`_maybe_evict` (`tagging.py:105-113`) checks only the session currently being
accessed. An attacker spraying fresh session ids (trivial — new TCP connection per
call, since the honeypot id is `sha256(ip:connect_ts)`) grows
`session_state` forever; no global sweep exists.

**B4 — `state["calls"]` is append-only.** `tagging.py:185` appends every call;
entries are never trimmed. `rapid_enumeration`'s listcomp (`tagging.py:152`) scans
the full history per call → O(n) per call inside a long-lived session (up to 1h,
`tagging.py:52`) — CPU amplification for an attacker who keeps one session warm.

**B5 — path-traversal regex gaps (documented but worth restating).**
`tagging.py:142` matches only literal `../` against `str(params)`: misses backslash
`..\..\` (test-tagging gap, `tests/test_tagging.py:105-109`) and URL-encoded
`..%2f`; conversely any `../` anywhere in any nested value flags, including inside
base64 blobs.

**B6 — attacker-controlled cardinality in metrics and span names (detection-relevant
side observation, outside the two named files).** Unknown tool names reach
`mcp_tool_calls_total.add(1, {"tool": tool_name, ...})` (`secrets.py:38`) and span
name `tool.<name>` (`main.py:90-92`) via the filesystem fallback
(`tools/handlers/__init__.py:36-39`); arbitrary methods become span names
`mcp.<method>` (`transport_wrapper.py:180`); UA/`clientInfo` become `agent.id`
(`transport_wrapper.py:182`). All unbounded attacker input into Prometheus label
values / Jaeger operation names → cardinality bomb against our own observability
backend.

Not bugs (verified intentional): replay TTL anchored to first sighting
(`tagging.py:162-163`, pinned by `tests/test_tagging.py:254-274`);
rapid_enumeration firing on the 12th call (threshold semantics pinned by
`tests/test_tagging.py:188-204`).

---
*Throwaway verification script (B1): two anyio tasks + memory-object stream;
set in producer task, consumer reads `None`. Repo untouched (read-only per brief).*
