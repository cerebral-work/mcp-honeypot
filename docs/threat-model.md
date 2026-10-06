# Threat Model: Agentic Attack Patterns

## Attack Taxonomy

### 1. Reconnaissance / Enumeration
Sequential tools/list calls followed by parameter probing.
Detection: >10 enumeration calls in <5s → rapid_enumeration flag

### 2. Credential Harvesting
Agent targets secrets, env vars, or config files. First high-intent signal.
Detection: any call to get_env_var, read_secret, list_secrets → credential_probe flag
Log exact requested key names — reveals what the agent is looking for.

### 3. Privilege Escalation
Tool category shift mid-session — e.g. file-reading agent suddenly calls exec tools.
Detection: category shift → privilege_escalation flag

### 4. Path Traversal
../ patterns in filesystem tool parameters.
Detection: regex match on ../ in any filesystem param → path_traversal flag

### 5. Exfiltration Chains
Read-then-network call pattern — list_directory → read_file → fetch_url.
Detection: read-then-network within same session → exfiltration_chain flag

### 6. Replay / Brute Force
Identical or near-identical requests repeated systematically.
Detection: identical request hash within 60s → replay_attempt flag

### 7. Obfuscation
Base64, URL encoding, Unicode escapes in parameters.
Detection: encoded content in params → param_obfuscation flag

## Detection Implementation (tagging.py)

### Session State

Each session is tracked via a plain dict created by `_new_session()`:

    {
        "calls": [],            # list of {"tool": str, "time": float}
        "hashes": {},           # call_hash → last_seen_time (TTL-based expiry)
        "last_read_time": None, # monotonic time of last READ_TOOLS call
        "categories_seen": set(),
        "last_active": time.monotonic(),
    }

Sessions are evicted after 1 hour of inactivity (`SESSION_EVICT_SECONDS = 3600`).

### Core Detection Logic

    def detect_anomalies(tool_name, params, session_id):
        flags = []
        now = time.monotonic()
        _maybe_evict(session_id, now)
        state = session_state.setdefault(session_id, _new_session())
        state["last_active"] = now

        # credential_probe — any call to secrets tools
        if tool_name in {"get_env_var", "read_secret", "list_secrets", "get_api_key"}:
            flags.append("credential_probe")

        # path_traversal — ../ in any param
        if re.search(r"\.\./", str(params)):
            flags.append("path_traversal")

        # param_obfuscation — base64-decodable string >20 chars
        for v in params.values():
            if isinstance(v, str) and len(v) > 20:
                try:
                    base64.b64decode(v, validate=True)
                    flags.append("param_obfuscation")
                    break
                except Exception:
                    pass

        # rapid_enumeration — >10 calls in <5s window
        recent = [c for c in state["calls"] if now - c["time"] < 5]
        if len(recent) > 10:
            flags.append("rapid_enumeration")

        # replay_attempt — identical call hash within 60s TTL window
        h = hashlib.sha256(
            f"{tool_name}:{json.dumps(params, sort_keys=True, default=str)}".encode()
        ).hexdigest()
        prev_time = state["hashes"].get(h)
        if prev_time is not None and (now - prev_time) <= 60:
            flags.append("replay_attempt")
            # Original timestamp anchors the TTL — replays age out naturally
        else:
            state["hashes"][h] = now

        # exfiltration_chain — read tool followed by network tool within 300s
        if tool_name in NETWORK_TOOLS and state["last_read_time"] is not None:
            if (now - state["last_read_time"]) <= 300:  # EXFIL_TTL_SECONDS
                flags.append("exfiltration_chain")
        if tool_name in READ_TOOLS:
            state["last_read_time"] = now

        # privilege_escalation — tool category shift mid-session
        category = CATEGORY_MAP.get(tool_name)
        if category is not None:
            if state["categories_seen"] and category not in state["categories_seen"]:
                flags.append("privilege_escalation")
            state["categories_seen"].add(category)

        state["calls"].append({"tool": tool_name, "time": now})
        return flags

### Tunables

| Constant | Value | Purpose |
|----------|-------|---------|
| RAPID_WINDOW_SECONDS | 5.0 | Window for rapid_enumeration detection |
| RAPID_THRESHOLD | 10 | Call count that triggers rapid_enumeration |
| REPLAY_TTL_SECONDS | 60.0 | TTL window for replay hash expiry |
| EXFIL_TTL_SECONDS | 300.0 | Read-to-network chain window |
| SESSION_EVICT_SECONDS | 3600.0 | Idle session eviction threshold |

## Protocol-Level Detections (protocol_tagging.py)

The seven flags above are tool-level and generic to any API. These six are
specific to the Model Context Protocol and run on every inbound JSON-RPC
message in `InstrumentedTransport`, before the SDK sees it. They never change
a response. Full design, sources and rulings: [spec-mcp-native-detections.md](spec-mcp-native-detections.md).

| Flag | Fires when | Main span attributes |
|------|------------|----------------------|
| `unknown_method` | The method is outside the pinned SDK's client request and notification union. On `mcp==1.6.0` such a request also ends the SSE connection. | `mcp.method.raw` |
| `lifecycle_violation` | A request other than `initialize` or `ping` arrives before `initialize` (`no_initialize`), or `tools/call` arrives before `notifications/initialized` (`no_initialized_notification`). | `mcp.lifecycle.reason` |
| `feature_enumeration` | A connection requests a second distinct feature-list method (`resources/list`, `resources/templates/list`, `prompts/list`, `completion/complete`, `logging/setLevel`). Fires once per connection. | `mcp.feature_methods` |
| `protocol_version_anomaly` | `initialize.params.protocolVersion` is missing, not a string, longer than 32 characters, not `YYYY-MM-DD`, or not a known revision. | `mcp.client.protocol_version`, `mcp.client.capabilities` |
| `hidden_unicode` | Any string in the message carries Unicode Tags (U+E0000..U+E007F) outside a well-formed emoji tag sequence. Zero-width and bidi characters are counted, not flagged. | `mcp.unicode.field_path`, `mcp.unicode.decoded`, `mcp.unicode.other_invisible_count` |
| `ansi_escape` | Any string in the message contains ESC or C1 CSI. | `mcp.ansi.field_path`, `mcp.ansi.sequence_kinds` |

Every message span also carries `mcp.message_kind` and, for requests, `mcp.jsonrpc.id`.
Span names come from a fixed vocabulary: `mcp.<known method>`, `mcp.unknown_method`,
`mcp.response`, `mcp.error` or `mcp.unknown`. Attacker-supplied strings are truncated
to 256 characters with a `...[truncated N]` suffix and appear only on span attributes
and logs, never as metric labels. `mcp_anomalies_total` counts these flags under the
same `flag` label as the tool-level flags.
Messages larger than the scan bound are not fully scanned; `mcp.scan.truncated=1` marks them, and such messages are themselves anomalous for MCP traffic.

## Research Questions
- Do agents have consistent fingerprints across sessions?
- What tool enumeration order is characteristic of different frameworks (LangChain, CrewAI, AutoGen)?
- How do agents behave differently on error vs success responses?
- Do agents adapt when they detect they may be in a honeypot?
- What is the distribution of tool call chain depth?
