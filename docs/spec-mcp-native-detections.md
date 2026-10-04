# Spec: MCP-Native Detections

Status: draft for operator review. Branch `feat/mcp-native-detections`, based on
`a511ad4`. No code changes accompany this document.

Citations: `file:line` refers to the tree at `a511ad4`. "survey §N" refers to the
attack-class survey (`docs/research/2026-10-04-mcp-attack-survey.md`, 15 classes; its
14 URLs were fetched and checked in `docs/research/2026-10-04-mcp-attack-survey-citation-check.md`).
"gaps §N" refers to the code gap analysis (`docs/research/2026-10-04-code-gap-analysis.md`,
written against `590ede9`, before #46 and #47). Statements about SDK `mcp==1.6.0` internals come from those
two surfaces and were not re-verified against the wheel while writing this spec; each is
marked "(per gaps)" and must be confirmed by the test named next to it.

## 0. Already done, not proposed

Merged on main and treated as baseline:

- #45: OpenTelemetry version pins.
- #46: `GET /sse` returned 500 because `mcp_sessions_active` was imported by name before
  `setup_telemetry()` assigned it. Fixed by module-attribute access at
  `server/main.py:135`.
- #47: tool handlers read session id `unknown`. Fixed by binding `session_id_var` in the
  connection's own context at `server/main.py:133`. The older `session_id_var.set` inside
  the pump task at `server/transport_wrapper.py:175` is now redundant for tool calls but
  still runs per message. Per-session tagging state is therefore keyed correctly for tool
  calls; `tests/test_sse_session.py` covers the SSE round trip.

Parked tickets, referenced by ID only:

| ID | Topic | Dependency of this spec |
|---|---|---|
| TOD-1050 | jury runner | none |
| TOD-1051 | SDK `SessionMessage` unwrap (wrapper reads `.root`, `transport_wrapper.py:150`) | All wrapper-level detections below stop working on an SDK bump until fixed. Safe on the `mcp==1.6.0` pin. |
| TOD-1052 | unbounded tagging state (`tagging.py:69`, `:105-110`, `:185`) | New per-source state in section 3.2 must not copy this pattern; see D9, D10 and section 3.2. |
| TOD-1053 | attacker-controlled metric labels and span names | Section 3 rules apply to every new capture. The unknown-method detection (D1) needs the bounded span name from that ticket. |
| TOD-1054 | `path_traversal` gaps (`tagging.py:142`) | none |

## 1. Problem and scope

The seven existing flags (`docs/threat-model.md`, `server/tagging.py:137-182`) are
generic: they look at tool names and arguments inside `tools/call`. Nothing inspects the
MCP protocol itself. Today the wrapper records only the method name, message size,
User-Agent and `initialize.clientInfo` (`transport_wrapper.py:164-186`). Protocol
version, capabilities, JSON-RPC id, request kind, `Origin`, `Host`, the SDK session UUID
and malformed or unknown-session POSTs are all discarded (gaps §1).

Goal: flags for MCP-specific behaviour that a server can observe first-order on the wire.

### In scope (server-observable first-order)

| Survey class | Why in scope |
|---|---|
| survey §5 hidden Unicode | Tag characters arrive inside inbound JSON strings; directly scannable. |
| survey §6 ANSI deception | Only when ESC bytes arrive inbound; scannable the same way. |
| survey §8 DNS rebinding / browser access | `Origin`, `Host`, `Sec-Fetch-*` are request headers. |
| survey §9 session-id guessing / hijack | Session id is in the `/messages` query string; 404s are visible at the HTTP layer. |
| survey §15 capability / version probing | `initialize` fields, method order and timing are inbound. |
| survey §11 token passthrough | Partial only: metadata about an `Authorization` header (D7), no passthrough claim. |

### Out of scope

| Survey class | Reason |
|---|---|
| survey §1 tool-description poisoning | Malicious text never reaches this server; second-order arguments only. |
| survey §2 rug-pull | Defining event is outbound; this server's definitions are static (`main.py:56-68`). |
| survey §3 cross-server shadowing | Cause is invisible server-side; not attributable. |
| survey §4 result/resource injection | Same; `exfiltration_chain` (`tagging.py:166-172`) already covers the sequence. |
| survey §7 sampling abuse | Flows server to client. Only the capability precondition is observed (captured by D4, no flag). |
| survey §10 OAuth confused deputy | No OAuth endpoints (`main.py:181-188`). |
| survey §12 OAuth-discovery SSRF | Outbound attack; no metadata routes. |
| survey §13 malicious authorization URL | Outbound attack. |
| survey §14 local startup / stdio proxy | Wholly client-host side. |

Second-order indicators for survey §1, §3, §4 (secret-looking material in arguments) are
not specced here; see Open Decision 5.

## 2. Proposed detections

Conventions for all flags:

- Flag names are snake_case, drawn from a fixed vocabulary in one module-level
  `PROTOCOL_FLAGS` frozenset. Flags are the only values used as the `flag` label of
  `mcp_anomalies_total` (`instrumentation.py:82-83`), so the vocabulary bounds that
  label's cardinality.
- Message-level flags are written to the per-message span as `anomaly.flags` (same
  attribute name as tool spans, `secrets.py:36`) and counted via
  `instrumentation.mcp_anomalies_total.add(1, {"flag": f})`. Access the counter through
  the module attribute at call time, not an import-time name (the #46 lesson).
- New logic lives in a new module `server/protocol_tagging.py` that takes plain dicts and
  returns flag lists. `tagging.py` stays tool-level. This keeps the new code testable
  without a running server.
- Connection-level state lives on `InstrumentedTransport` (`transport_wrapper.py:75`) and
  dies with the connection. No new process-global dicts except the bounded structure in
  section 3.2.

### D1. `unknown_method`

- Signal: JSON-RPC `method` string is not in `KNOWN_METHODS`, the union of client
  requests and notifications for the pinned SDK (`initialize`, `ping`, `tools/list`,
  `tools/call`, `resources/*`, `prompts/*`, `logging/setLevel`, `completion/complete`,
  `notifications/initialized`, `notifications/cancelled`, `notifications/progress`,
  `notifications/roots/list_changed`). Exact list to be generated from the SDK type
  union at import time rather than hand-copied (test asserts parity).
- Why it matters (survey §15): on `mcp==1.6.0` an off-union request method raises an
  unhandled `ValidationError` in the SDK receive loop and drops the SSE connection with
  no JSON-RPC error (per gaps §2, survey §15). The wrapper is the only place that sees
  the method before that happens. The pump calls `_instrument_message` before
  `send_channel.send` (`transport_wrapper.py:124-125`), so the flag is emitted before
  teardown.
- Hook: `InstrumentedTransport._instrument_message`, `transport_wrapper.py:164`, after
  `method` is read.
- New capture: raw method string as attribute `mcp.method.raw` (truncated, section 3.1).
  Span name becomes `mcp.<method>` only for known methods, otherwise `mcp.unknown_method`
  (replaces `transport_wrapper.py:180` behaviour; coordinate with TOD-1053).
- False positives: legitimate clients on a newer spec revision send methods outside the
  1.6.0 union (for example `elicitation/create` replies, `tasks/*`). Mitigation: flag
  carries the raw method so analysis can separate "newer client" from "fuzzer"; the flag
  is informational, not a verdict.
- Tests (`tests/test_protocol_tagging.py`): `tools/list` returns no flag; `foo/bar`
  returns `["unknown_method"]`; every method in the SDK union is a member of
  `KNOWN_METHODS` (parity test that fails if the SDK pin moves); a transport-level test
  feeds a message with an unknown method through `wrap_read_stream` and asserts the span
  has `anomaly.flags` containing `unknown_method` and `mcp.method.raw` set.
  Negative: a notification `notifications/initialized` is not flagged.

### D2. `lifecycle_violation`

- Signal: ordering. Any JSON-RPC request other than `initialize` and `ping` arrives on a
  connection before an `initialize` request was seen. Sub-signal
  `missing_initialized_notification`: a `tools/call` arrives after `initialize` but
  before `notifications/initialized` (spec lifecycle, survey §15). Both use the single
  flag name `lifecycle_violation`, with attribute `mcp.lifecycle.reason` set to
  `no_initialize` or `no_initialized_notification`.
- Hook: `_instrument_message`; state is two booleans on `InstrumentedTransport` set in
  `__init__` (`transport_wrapper.py:88-100`).
- New capture: JSON-RPC `id` and message kind (section 3.1) are needed to tell requests
  from notifications; kind is derived from the presence of `id` in `msg_dict`.
- False positives: some real clients skip `notifications/initialized` or send
  `tools/call` optimistically; the 1.6.0 server does not enforce it, so the traffic is
  served normally. Treat `no_initialized_notification` as a fingerprint feature, and only
  `no_initialize` as suspicious.
- Tests: sequence initialize, initialized, tools/call yields no flag. tools/call first
  yields `lifecycle_violation` with reason `no_initialize`. initialize then tools/call
  yields reason `no_initialized_notification`. Negative: `ping` first is not flagged.

### D3. `feature_enumeration`

- Signal: within one connection, requests to two or more distinct feature-list methods
  from `{resources/list, resources/templates/list, prompts/list, completion/complete,
  logging/setLevel}` in addition to `tools/list`, or any one of them within a configured
  window (default 10 s) of `initialize`. These nine methods validate but are unhandled
  and return -32601 (per gaps §2), which is a clean probe signal (survey §15).
- Distinct from `rapid_enumeration` (`tagging.py:151-154`), which counts tool calls
  only.
- Hook: `_instrument_message`; a `set[str]` of feature methods seen, on the transport.
- New capture: none beyond the method name.
- False positives: generic MCP clients (for example inspector UIs) call all list
  endpoints on connect. Mitigation: flag requires the two-method threshold and records
  the `clientInfo` fingerprint, so known inspectors can be allow-listed analytically
  rather than in code.
- Tests: `tools/list` plus `prompts/list` flags once, not on every later call; one
  method alone is not flagged. Negative: repeated `tools/list` does not flag
  (`tools/list` is not in the feature set).

### D4. `protocol_version_anomaly`

- Signal: `initialize.params.protocolVersion` is missing, not a string, longer than 32
  characters, not matching `YYYY-MM-DD`, or a date not in `KNOWN_PROTOCOL_VERSIONS`
  (configurable; initial set `2024-11-05`, `2025-03-26`, `2025-06-18`, where the first
  and last are cited in survey §15 and the middle one is an addition to confirm).
- The pinned server answers every initialize with `LATEST_PROTOCOL_VERSION`
  (`2024-11-05`) regardless of the request (per survey §15), so the server response
  carries no information; the client's request value is the datum.
- Hook: `_instrument_message`, inside the existing `method == "initialize"` branch
  (`transport_wrapper.py:168-172`).
- New capture: `protocolVersion` as span attribute `mcp.client.protocol_version`
  (truncated). Capability keys as `mcp.client.capabilities` (sorted top-level keys
  joined with `,`, plus truncated JSON in `mcp.client.capabilities_json`). The presence
  of `sampling` and `roots` is the survey §7 precondition and is recorded here without a
  flag. Also `clientInfo` extra keys count.
- False positives: a client from a spec revision released after this list was written.
  The flag is informational and the raw value is preserved.
- Tests: `2025-06-18` no flag; `2099-01-01` flagged; `{"x": 1}` (non-string) flagged;
  100-character string flagged and attribute truncated to the cap. Negative: missing
  `capabilities` alone does not flag.

### D5. `hidden_unicode`

- Signal (survey §5): any string in the inbound message, recursively through
  `params` (keys and values), contains a code point in U+E0000..U+E007F (Unicode Tags).
  Whether zero-width characters and bidi controls are included is Open Decision 3.
- Hook: `_instrument_message` over the Python `msg_dict` strings. Scan the Python
  strings, not `json.dumps` output: `json.dumps` escapes non-ASCII by default, so the
  size computation at `transport_wrapper.py:165` would hide the code points from a byte
  scan.
- New capture: attributes `mcp.unicode.field_path` (first matching JSON path, for
  example `params.arguments.query`), `mcp.unicode.tag_count`, and the decoded ASCII text
  (code point minus 0xE0000) truncated and set as `mcp.unicode.decoded`.
- Interaction with the estate: this repo's operator SOP says estate-authored docs
  legitimately carry an invisible metadata channel. Honeypot inbound traffic is foreign
  content by definition, so every hit is hostile-presumed. The decoded text is data,
  never instructions to be followed.
- False positives: emoji tag sequences (flag subdivisions, for example the England
  flag) use U+E0062..U+E007F tags legitimately. Mitigation: only flag when the decoded
  tag run is not a well-formed emoji tag sequence (starts with U+1F3F4 and ends with
  U+E007F); test pins this.
- Tests: string with `chr(0xE0041)` flagged with decoded `A`; flag-emoji tag sequence
  not flagged (negative); nested in `params.arguments.a.b[0]` flagged with correct path;
  clean ASCII not flagged.

### D6. `ansi_escape`

- Signal (survey §6): any inbound string contains ESC (`0x1b`) or C1 control `0x9b`.
  Only meaningful when an attacker or compromised agent relays it inbound.
- Hook: same scan pass as D5 (one walk over the message, two predicates).
- New capture: `mcp.ansi.field_path`, `mcp.ansi.sequence_kinds` (CSI, OSC, other; bounded
  vocabulary), not the raw bytes as a metric label.
- False positives: terminal-pasted logs in tool arguments legitimately contain colour
  codes. The flag is informational; OSC 8 hyperlinks (`ESC ] 8`) are the stronger
  sub-signal and get `sequence_kinds=osc`.
- Tests: `"\x1b[31mred"` flagged `csi`; `"\x1b]8;;http://x\x1b\\t"` flagged `osc`;
  plain text with a literal backslash-x-1-b (four characters, not ESC) not flagged
  (negative).

### D7. `credential_header_presented` (partial, survey §11)

- Signal: request carries an `Authorization` header. The server has no authorization
  middleware, so passthrough cannot be established (survey §11); the flag records only
  that a credential was offered to an unauthenticated endpoint.
- Hook: `handle_sse` (`main.py:119` already reads raw headers) and the POST wrapper in
  D9.
- New capture: scheme (first token, lowercased, restricted to a vocabulary of `bearer`,
  `basic`, `other`) and length bucket. Nothing derived from the credential itself: no
  value and no hash, in any attribute, log or metric (operator ruling 2026-10-04,
  decision 4).
- False positives: clients configured with a token by habit. Informational only.
- Tests: `Authorization: Bearer abc` yields scheme `bearer` and a length bucket, and a
  test greps all span attributes and captured log output for the literal token and
  asserts it is absent. Negative: no header, no flag.

### D8. `browser_origin_request`, `host_header_mismatch` (survey §8)

- Signal: on `GET /sse` or `POST /messages`:
  - `Origin` header present (non-browser MCP clients normally send none) ->
    `browser_origin_request`; stronger when `Sec-Fetch-Site` is `cross-site`.
  - `Host` header not in `settings.expected_hosts` (new config, default: empty meaning
    "do not flag") -> `host_header_mismatch`. Neither header alone proves rebinding
    (survey §8), so the flags are separate and no combined verdict is emitted.
- Hook: `handle_sse` at `main.py:119` (headers already available) and the POST wrapper
  in D9. `SseServerTransport("/messages")` is constructed without transport-security
  settings and `CORSMiddleware` defaults to `*` (`middleware.py:172-185`); this spec
  observes and does not change that behaviour (Non-goals).
- New capture: `http.origin`, `http.host`, `http.referer`, `http.sec_fetch_site`,
  `http.sec_fetch_mode` on a short `mcp.connection` span created in `handle_sse`
  (there is no span for the GET today, gaps §1) and on the POST span (D9). All
  truncated; none are metric labels. New setting `expected_hosts` in
  `server/config.py` (`Settings`, `config.py:33-77`).
- False positives: legitimate browser-based MCP inspectors send `Origin`. Reverse
  proxies rewrite `Host`. Mitigation: `expected_hosts` empty by default, and the raw
  headers are preserved for analysis.
- Tests: ASGI-level unit test builds a scope with `origin: http://evil.example` and
  asserts the flag on the connection span; scope without origin yields none (negative);
  `Host: 127.0.0.1:8000` with `expected_hosts=("honeypot.example",)` flags mismatch,
  and with the matching host does not.

### D9. `session_id_probe`, `session_id_cross_source` (survey §9)

- Signal:
  - `session_id_probe`: `POST /messages` returns 404 (unknown or expired SDK session
    UUID) or 400/422 (missing or malformed `session_id`, or bad body) (per gaps §1;
    survey §9). These are rejected inside the SDK before the instrumentation wrapper
    sees them. A single occurrence is recorded; three or more from one source IP inside
    60 s raises the flag (thresholds are constants in `protocol_tagging.py`).
  - `session_id_cross_source`: a POST that the SDK accepted (202) arrives from a source
    IP different from the IP that opened the matching `/sse` stream.
- Hook: `main.py:158-164`, `handle_messages`. Wrap the ASGI `send` callable passed to
  `sse_transport.handle_post_message` to capture the response status code, and read the
  `session_id` query parameter from `request.query_params`.
- New capture: SDK session UUID. It is not recorded anywhere today and is not
  correlated with the honeypot session id (gaps §1). To map UUID to honeypot session,
  parse the first `endpoint` SSE event from the response body in `handle_sse`'s wrapped
  `send`. This mapping is an implementation spike (unverified): if the 1.6.0 event
  format cannot be parsed reliably, `session_id_cross_source` is dropped and
  `session_id_probe` ships alone.
- Cardinality: the UUID is a span attribute (`mcp.sdk_session_id`) only. For probes, the
  attacker-supplied value is truncated to 64 chars and recorded as
  `mcp.probe.session_id.raw`; never a label.
- Bounded state: per-source counters use the bounded structure in section 3.2.
- False positives: a client reconnecting after a server restart POSTs to a stale UUID
  (404) once; legitimate clients behind NAT or a proxy may change egress IP mid-session.
  Mitigation: the 3-in-60-s threshold, and `session_id_cross_source` is advisory.
- Tests: ASGI test POSTs to `/messages?session_id=00000000000000000000000000000000`
  and asserts a 404 is observed and counted; three probes flag, two do not (boundary,
  negative); a valid session round trip (reuse the pattern in
  `tests/test_sse_session.py`) yields no probe flag.

### D10. `single_probe_reconnect` (survey §15)

- Signal: from one source IP, N or more SSE connections (default 5) inside a window
  (default 60 s), each lasting under 5 s and carrying at most one non-initialize
  request. This is the expected signature of systematic enumeration against the pinned
  SDK, where each off-union probe kills the session (per gaps §2, survey §15).
- Hook: `handle_sse` `finally` block (`main.py:148-149`), which knows connection
  duration; per-connection request count from the transport.
- New capture: connection duration and request count as attributes on a
  `mcp.connection_closed` span or on the existing close log line (`main.py:151-155`).
- Bounded state: shares the per-source structure in section 3.2.
- False positives: health-checking scanners and flaky clients reconnect rapidly. The
  `sse_limit` decorator (`main.py:113`) rate-limits GET /sse; the flag measures what
  gets through. Informational.
- Tests: five synthetic short connections from one IP inside the window flag; four do
  not (negative); five from five distinct IPs do not.

## 3. Data-capture changes and cardinality (TOD-1053)

### 3.1 What is captured, and where it may go

| Datum | Span attribute | Metric label | Log field |
|---|---|---|---|
| JSON-RPC method (raw, attacker controlled) | `mcp.method.raw`, truncated | never | yes |
| Span name | fixed vocabulary only (`mcp.<known method>` or `mcp.unknown_method`) | n/a | n/a |
| `protocolVersion`, capability keys | yes, truncated | never | yes |
| JSON-RPC `id` and kind (`request`, `notification`, `response`, `error`) | yes (`mcp.jsonrpc.id` as string, truncated; `mcp.message_kind`) | kind only (fixed vocabulary) | yes |
| `Origin`, `Host`, `Referer`, `Sec-Fetch-*` | yes, truncated | never | yes |
| SDK session UUID, probe session id | yes, truncated | never | yes |
| Authorization metadata (D7) | scheme bucket and length bucket | scheme bucket only | no raw value anywhere |
| Unicode / ANSI findings | field path, counts, kinds | never | yes |

Rules, which also bound this spec's interaction with TOD-1053:

1. Raw attacker strings go on spans and logs only, never on metric labels or span
   names. A single constant `MAX_ATTR_LEN` (initial 256) truncates every captured string
   and a `...[truncated N]` suffix records the original length.
2. The only new metric label values are the fixed flag vocabulary (`PROTOCOL_FLAGS`),
   the fixed message-kind vocabulary and the fixed scheme buckets. A unit test asserts
   that every label dict produced by the new code has values drawn from these sets.
3. Existing leaks remain TOD-1053's to fix and are not re-specced: `tool` label from the
   unknown-tool fallback (`secrets.py:38`, `tools/handlers/__init__.py:36-39`) and
   `agent.id` from User-Agent (`transport_wrapper.py:182`). Note `secrets.py:38` also
   passes `session_id` as the `agent_id` label, which is per-connection cardinality; the
   new code does not add to it. Rename of the span `mcp.<method>` at
   `transport_wrapper.py:180` is introduced by D1 and should land in the same change as
   TOD-1053's fix to avoid two edits to one line.

### 3.2 Bounded per-source state

D9 and D10 need state keyed by source IP across connections. The existing pattern is
unbounded (`tagging.py:69`, `:105-110`, `:185`, TOD-1052). New state must be:

- a single dict capped at `MAX_SOURCES` entries (default 10,000) with
  least-recently-used eviction on insert, so growth is bounded regardless of attacker
  behaviour;
- values are fixed-size (a `collections.deque(maxlen=N)` of timestamps), never appended
  without bound;
- injectable clock for tests.

If TOD-1052 lands first and provides a shared bounded store, reuse it instead.

### 3.3 Message-kind derivation

`InstrumentedTransport._instrument_message` already produces `msg_dict`
(`transport_wrapper.py:146-162`). Kind is derived: has `method` and `id` -> request; has
`method`, no `id` -> notification; has `result` -> response; has `error` -> error. No
extra SDK dependency, but it relies on the `.root` unwrap, hence the TOD-1051 dependency.

## 4. Phased plan (fits docs/roadmap.md)

The roadmap's v0.2.0 (OpenAPI) and v0.3.0 (plugins) concern tool loading and are
independent of this work. The v0.4.0 "agent behavior labels" and v0.5.0 "cross-session
correlation" items consume these flags as inputs. Placement of the first two phases
relative to v0.2.0 is Open Decision 1.

| Phase | Content | Depends on | Done when |
|---|---|---|---|
| P0 prerequisites | TOD-1051, TOD-1052, TOD-1053 merged | those tickets | Each ticket's own acceptance met; this spec adds no work here. |
| P1 capture and message-level flags | `protocol_tagging.py`; D1, D2, D3, D4, D5, D6; capture table rows for method, version, capabilities, id, kind; bounded attrs; `PROTOCOL_FLAGS` | P0 (at least TOD-1053 for the span-name rule) | New unit tests green including every negative case; `tests/test_sse_session.py` extended so a real SDK client session produces `mcp.client.protocol_version` and no spurious flags; an adversarial probe (unknown method) produces `unknown_method` on a span in the in-memory exporter; `docs/threat-model.md` lists the new flags; CHANGELOG entry. |
| P2 HTTP layer | D7, D8, D9 (`session_id_probe` first, `cross_source` only if the spike works), `mcp.connection` span, POST wrapper, `expected_hosts` setting | P1 | Same test bar; a real `curl` against a locally run server with a forged `Origin` and a bogus `session_id` produces the corresponding flags on spans read back from the exporter, not just exit code 0; `docs/otel.md` documents the new attributes. |
| P3 cross-connection | D10, shared bounded source store (section 3.2) | P2 and TOD-1052 | `single_probe_reconnect` fires in a scripted five-connection test and stays quiet at four; memory bound test: 100k distinct source ids keep state under `MAX_SOURCES`. |
| P4 observability | Grafana panel for `mcp_anomalies_total` by new flags; alert rule review (`dashboards/provisioning/alerting`); `docs/grafana.md` update | P1 | Panel renders from a seeded series (rendered and inspected before review, per repo quality gate); no alert fires on baseline traffic from the existing adversarial agent (`tools/adversarial_agent.py`). |
| P5 downstream | Feed flags into v0.4.0 classifier labels and v0.5.0 fingerprint DB | roadmap v0.4/v0.5 | Tracked in those versions' specs, not here. |

Every phase is a separately mergeable PR. P1 changes no server responses.

## 5. Non-goals

- Changing server responses or SDK behaviour. No hardening of CORS, Origin validation
  or DNS-rebinding protection; the honeypot observes and replies as it does today.
- Active probing of clients: planting canary instructions in tool results (survey §4) or
  issuing `sampling/createMessage` (survey §7). Survey caution 9 flags both as
  manipulation of connecting agents; excluded pending an operator decision.
- Implementing OAuth endpoints so that survey §10-§13 become observable.
- Upgrading `mcp` beyond 1.6.0. Detections target the pin; the parity test in D1 and the
  TOD-1051 dependency make an upgrade a visible, deliberate step.
- Verdict-level combination of flags (for example "this is DNS rebinding"). Flags are
  features; classification belongs to roadmap v0.4.0.
- Prevalence or base-rate claims. No dataset exists (survey, Gaps and cautions 1).
- Fuzz and malformed-JSON coverage as a goal in itself. D9 incidentally counts 400s from
  the same hook; a dedicated fuzz detector is not specced (survey, Gaps and cautions 5).
- Fixing the path_traversal gaps (TOD-1054) or the jury runner (TOD-1050).

## 6. Open decisions (for the lead to put to the operator)

Rulings recorded 2026-10-04 (Christian, by interview in lane w18:p1):

| # | Decision | Ruling |
|---|---|---|
| 1 | Release placement | A: patch line before v0.2.0 |
| 2 | Phase ordering | A: message-level first, then HTTP layer, then cross-connection |
| 4 | D7 credential handling | B: scheme bucket and length only, no hash |
| 6 | Active probing | A: passive only |

Decisions 3, 5, 7, 8 and 9 are still open. Each one's recommendation is the working
default until it is ruled on. None of them blocks phase P1 except 3, whose
recommendation (Tags block for the flag, other invisible characters as a count) only
records data.

1. **Release placement.** Where do P1 and P2 ship relative to the roadmap?
   - A: patch line before v0.2.0 (for example v0.1.2 "Protocol"); no responses change,
     so it is low risk and the data starts accumulating sooner.
   - B: fold into v0.4.0 "Deep Deception" with the classifier.
   - C: new minor between v0.1.1 and v0.2.0.
   - Recommendation: A.
2. **Phase ordering.** Which detections come first?
   - A: message-level flags (D1-D6) then HTTP layer (D7-D9) then cross-connection (D10),
     as in section 4.
   - B: HTTP layer first, because the honeypot is internet-exposed in the public phase
     and survey §8 and §9 are the classes attackers can reach without speaking MCP.
   - C: ship D1, D4, D8 only as a minimal first PR.
   - Recommendation: A, since B depends on the SDK-UUID spike and C leaves most of the
     value on the table.
3. **Hidden-character breadth for D5.** What counts as hidden Unicode?
   - A: Tags block U+E0000..U+E007F only, as in survey §5.
   - B: Tags plus zero-width (U+200B..U+200D, U+2060, U+FEFF) and bidi controls.
   - C: B plus variation-selector runs (the estate's own invisible metadata channel).
   - Recommendation: A for the flag, with B recorded as an attribute count
     (`mcp.unicode.other_invisible_count`) so the question can be answered from data
     before widening the flag.
4. **Credential header handling (D7).** How much of an `Authorization` header is stored?
   - A: scheme bucket plus truncated hash prefix (the first draft).
   - B: scheme bucket and length only, no hash.
   - C: drop D7 entirely (survey §11 is partial and unprovable here).
   - Recommendation: B. The hash adds reuse correlation but is still derived from
     attacker-supplied credential material, which the operator may prefer not to retain.
5. **Second-order indicators for survey §1, §3, §4.** Add a flag for secret-shaped
   material in tool arguments (PEM header, `ssh-rsa`, cloud key prefixes)?
   - A: no, keep this spec first-order only.
   - B: yes, one flag `secret_material_in_args`, labelled second-order in docs.
   - C: separate spec later.
   - Recommendation: C. The signal is not attributable to a specific attack class and
     overlaps `credential_probe` and TOD-1054 style regex work.
6. **Active probing.** Should canary instructions in fake tool results (survey §4) or a
   `sampling/createMessage` request (survey §7) ever be built?
   - A: no, passive only.
   - B: only in `HONEYPOT_PHASE=research`, behind an explicit flag.
   - C: separate spec with its own ethics review.
   - Recommendation: A for this spec; C if the operator wants it explored.
7. **SDK UUID spike scope (D9).** If parsing the `endpoint` event proves unreliable, is
   dropping `session_id_cross_source` acceptable?
   - A: yes, ship `session_id_probe` alone.
   - B: no, subclass `SseServerTransport` to expose the UUID.
   - C: wait for the SDK upgrade path.
   - Recommendation: A, with B revisited after TOD-1051.
8. **Flag naming and vocabulary freeze.** Freeze the names in section 2 now?
   - A: freeze, since dashboards and the classifier will key on them.
   - B: leave provisional until P1 is implemented.
   - Recommendation: B for D9 and D10 (names depend on the spike), A for the rest.
9. **`expected_hosts` default (D8).** Empty (never flag) or require it to be set in the
   public phase?
   - A: empty by default.
   - B: required when `HONEYPOT_PHASE=public`, mirroring how `config.py:70` already
     special-cases the public phase.
   - Recommendation: B.
