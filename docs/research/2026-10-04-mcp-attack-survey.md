> Provenance: Written 2026-10-04 by Sakana fugu-ultra (opencode, lane w18:p4) for the MCP-native detections spec. Kept as written so that "survey §N" citations in `docs/spec-mcp-native-detections.md` resolve. References to `gaps-kimi.md` mean `2026-10-04-code-gap-analysis.md`, and `survey-fugu.md` means `2026-10-04-mcp-attack-survey.md`. Bug B1 (session id `unknown`) and the `GET /sse` 500 were fixed after this was written, by #47 and #46.

# Survey: published MCP-specific attack classes as of 2026

## Scope and observability baseline

This survey is limited to published attacks that depend on MCP semantics, transports, or client/server trust boundaries. Generic API abuse and generic malformed-JSON fuzzing are excluded. The target honeypot is an MCP server using legacy HTTP+SSE and `mcp==1.6.0` (`server/requirements.txt:2`). Today it records the JSON-RPC method and message size (`server/transport_wrapper.py:164-186`), `User-Agent` and `initialize.clientInfo` (`server/transport_wrapper.py:47-69,168-172`), and tool names and arguments (`server/main.py:71-105`; `gaps-kimi.md:31`). It does not record `initialize.protocolVersion`, capabilities, JSON-RPC ids, request kind, `Origin`, `Host`, `Referer`, `Accept`, or the SDK SSE session UUID (`gaps-kimi.md:15-30`). Per-tool session state is also unreliable because `session_id_var` is set in a different anyio task, causing tool calls to share the key `unknown` (`gaps-kimi.md:87-101`). Observability below distinguishes wire-visible signals from signals actually retained today.

## 1. Tool-description poisoning (line jumping)

A malicious MCP server embeds model-directed instructions in a tool description or schema description. The client obtains this content through `tools/list` and places it in model context before the tool is called, allowing the instructions to influence the model before invocation approval. Published demonstrations instructed agents to read local configuration and SSH-key files and pass them in an innocuous-looking argument. Trail of Bits calls the same pre-invocation primitive "line jumping."

- **Victim side:** client.
- **Server-side honeypot observability:** **Not observable server-side as a first-order attack.** A server sends descriptions; it does not receive the malicious description that poisoned the client. If a compromised agent later calls this honeypot, the honeypot can see resulting `tools/call` names, arguments, order, and timing. Examples include file contents, credentials, PEM text, or encoded blobs placed in unrelated parameters. Those are second-order indicators and cannot by themselves attribute the behavior to description poisoning. Tool arguments are retained today, but reliable cross-call correlation requires fixing the shared-`unknown` session bug (`gaps-kimi.md:87-101`).
- **Sources:**
  - https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
  - https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/

## 2. Rug-pull tool redefinition

A malicious or compromised server initially advertises benign tools, gains user trust or approval, and later changes a tool description or schema to include malicious instructions. The changed definition can be delivered on a later `tools/list`, including after a `notifications/tools/list_changed` signal. This defeats approval based only on the definition seen at installation time; published mitigations include pinning or hashing definitions and alerting when definitions change.

- **Victim side:** client.
- **Server-side honeypot observability:** **Not observable server-side.** The defining event is a server changing its own outbound definition. An inbound `tools/list` request only reveals that the client refreshed the list, not whether another server performed a rug pull or whether the client accepted one. The honeypot records the method today but does not retain definition versions because its definitions are static (`server/main.py:56-68`).
- **Sources:**
  - https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
  - https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/

## 3. Cross-server tool shadowing

When one client connects several MCP servers to the same model context, a malicious server can put instructions in its own tool description that alter how the model uses a different trusted server. Invariant demonstrated a malicious tool description that redirected calls to a trusted email tool even when the malicious tool itself was never invoked. This uses the model as a relay across server trust boundaries rather than requiring direct server-to-server communication.

- **Victim side:** both. The client is manipulated, and the trusted server receives semantically altered calls.
- **Server-side honeypot observability:** **Not observable server-side as a first-order attack; partially observable second-order.** If the honeypot is the trusted server being shadowed, it can see the resulting `tools/call` name and arguments, such as a destination repeatedly replaced with one attacker-controlled value. It cannot see the malicious description, the user's intended value, or the other connected server, so the cause is not attributable from server traffic alone. Tool arguments are captured today; trustworthy per-session pattern analysis is blocked by `gaps-kimi.md` bug B1.
- **Sources:**
  - https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
  - https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/

## 4. Indirect prompt injection through tool results and resources

A trusted MCP server can return attacker-authored content from an external system, such as an issue, web page, file, database row, tool result, or MCP resource. If the client passes that content to the model without separating data from instructions, the content can redirect later agent actions. Invariant's GitHub MCP demonstration used a malicious public issue to cause an agent to obtain private-repository data and publish it in a public pull request, without requiring malicious code in the GitHub MCP server itself.

- **Victim side:** client.
- **Server-side honeypot observability:** **Not observable server-side at the injection point; partially observable second-order.** The server knows which result or resource it returned but cannot see how the model interpreted it or calls made to other servers. It can observe later calls back to itself, including read-then-network sequences, changed arguments, and short response-to-call timing. The existing `exfiltration_chain` flag is relevant (`server/tagging.py:166-175`), but bug B1 currently mixes session state and prevents reliable attribution (`gaps-kimi.md:87-101`).
- **Sources:**
  - https://invariantlabs.ai/blog/mcp-github-vulnerability
  - https://modelcontextprotocol.io/specification/2025-06-18/server/tools

## 5. Hidden-Unicode smuggling

Unicode Tags characters can encode ASCII-like instructions that are invisible in many user interfaces while remaining available to tokenizers and models. In an MCP setting, the hidden text can be placed in descriptions, results, resources, prompts, or tool arguments to bypass human review and simple text filters. The underlying Unicode technique is general to LLM systems, but MCP supplies multiple structured fields through which it can cross the client/server boundary.

- **Victim side:** client when a server hides instructions; both when a compromised client uses the same encoding against server logs or validation.
- **Server-side honeypot observability:** **Directly observable when present in inbound MCP content.** The server can scan raw JSON and recursively decoded string parameters for Unicode Tags U+E0000 through U+E007F and record the affected method and field. Today the wrapper computes only method and serialized size, while tool handlers retain decoded arguments; no existing anomaly flag scans Unicode code points (`server/transport_wrapper.py:164-186`; `server/tagging.py:135-183`). Inbound Tags are a strong smuggling indicator, but they do not prove which upstream injection caused a compromised agent to emit them.
- **Sources:**
  - https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

## 6. ANSI terminal-output deception

A malicious MCP server can place ANSI escape sequences in tool descriptions or results so terminal-based clients render model-visible content differently from what the user sees. Trail of Bits demonstrated white-on-white text, cursor movement that overwrites malicious text, screen clearing, and OSC 8 links whose displayed destination differs from the actual URL. This targets the gap between raw MCP content consumed by the model and terminal output reviewed by a human.

- **Victim side:** client.
- **Server-side honeypot observability:** **Directly observable only when an attacker or compromised agent sends ANSI bytes inbound.** The honeypot can scan request bodies and decoded parameters for ESC (`0x1b`) and associate a match with the JSON-RPC method and field. It cannot observe ANSI content emitted by another server to the client. No current flag checks for terminal control bytes; `param_obfuscation` only tests top-level strings for base64 (`server/tagging.py:145-149`).
- **Sources:**
  - https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

## 7. Sampling abuse

MCP sampling lets a server send `sampling/createMessage` to a client that advertised the `sampling` capability, causing the client to request model generation and return the result. A malicious server can abuse weak approval or rate limits to consume client-side model resources or submit attacker-chosen prompts. The specification recommends human review of requests and responses, content validation, and client-side rate limiting, which establishes the relevant trust and resource-abuse risks.

- **Victim side:** client.
- **Server-side honeypot observability:** **Not observable server-side as an inbound attack.** The abusive request travels from server to client. This honeypot can observe only the precondition in the client's inbound `initialize.params.capabilities.sampling` and any later JSON-RPC response to a request the honeypot itself issued. Capabilities are wire-visible but discarded today (`gaps-kimi.md:15-16`). Issuing sampling requests would make the honeypot an active tester, not a passive observer.
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/client/sampling
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle

## 8. DNS rebinding and browser access to local HTTP MCP servers

A malicious website can attempt to reach an unauthenticated local SSE or Streamable HTTP MCP endpoint, including through DNS rebinding or browser handling of loopback and `0.0.0.0`. The MCP transport specification requires `Origin` validation and recommends loopback binding and authentication. A concrete published case, CVE-2025-49596, affected MCP Inspector before 0.14.1: unauthenticated browser requests could reach its local proxy and launch commands; the fix added authentication and origin checks.

- **Victim side:** server.
- **Server-side honeypot observability:** **Directly observable on the wire.** Relevant evidence includes `Origin`, `Host`, `Referer`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`, browser-like `User-Agent`, query parameters, remote address, and request timing. An unexpected public `Origin` or cross-site fetch is evidence of browser access; an unexpected `Host` can support a rebinding finding, but neither header alone proves DNS rebinding. The current honeypot retains `User-Agent` and logs the SSE remote IP, but discards `Origin`, `Host`, `Referer`, and `Accept` (`gaps-kimi.md:18-20`). Its pinned MCP SDK has no transport-security middleware, and its app defaults to wildcard CORS (`server/middleware.py:163-185`).
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
  - https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596
  - https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g

## 9. Session-id hijacking, guessing, or fixation

In stateful HTTP MCP, an attacker who obtains or predicts another client's session identifier can submit requests as that session or inject events that a distributed server later delivers to the victim. The official security guidance describes both impersonation and prompt-injection variants and requires authorization on every inbound request, non-deterministic session identifiers, and separation of session state from authentication. Stream resumability can enlarge the impact if injected events are later replayed to the legitimate client.

- **Victim side:** both.
- **Server-side honeypot observability:** **Directly observable on the wire.** Signals include a missing or malformed session id, repeated POSTs cycling candidate ids, POSTs for unknown or expired ids, reuse of one id from different source addresses or credentials, and unusual `Last-Event-ID` values where resumability exists. In this legacy SSE server the SDK UUID is in `/messages?session_id=...`; unknown values produce HTTP 404 before the instrumentation wrapper, and the UUID and 404 are not retained by honeypot telemetry (`gaps-kimi.md:23,29-30`). The derived honeypot session id is separate and cannot currently correlate those POSTs (`server/transport_wrapper.py:36-39`).
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

## 10. OAuth confused-deputy attacks

An MCP proxy can become a confused deputy when it uses one static client id to access a third-party authorization server while allowing MCP clients to register dynamically. If the proxy fails to obtain per-client consent, an attacker can register a malicious redirect URI and exploit an existing third-party consent cookie so the user does not see a new consent screen; the resulting MCP authorization code is redirected to the attacker. Official guidance requires per-client consent, exact redirect-URI matching, CSRF protection, and single-use state validation.

- **Victim side:** both. The user/client loses authorization, and the MCP proxy server is abused as the deputy.
- **Server-side honeypot observability:** **Not observable server-side in this honeypot.** It exposes only `/healthz`, `/sse`, and `/messages` and implements no OAuth registration, authorization, consent, callback, or token endpoint (`server/main.py:175-184`). An OAuth-capable honeypot could observe dynamic registration metadata, redirect URIs, repeated authorize/callback sequences, consent state, and token-exchange timing. A bearer header on the current endpoints is not enough to identify a confused-deputy flow.
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

## 11. OAuth token passthrough

Token passthrough occurs when an MCP server accepts a token that was not issued to that MCP server and forwards it to a downstream API. This bypasses audience separation and can weaken rate limiting, identity attribution, authorization checks, and audit trails. The MCP security guidance explicitly forbids accepting tokens not issued for the MCP server.

- **Victim side:** server. The MCP server and downstream resource server have their trust and audit boundaries bypassed.
- **Server-side honeypot observability:** **Partially observable.** The current server can receive an `Authorization` header, but it has no authorization middleware, issuer metadata, audience validator, or downstream token exchange, so it cannot establish token passthrough from presence alone. A suitably instrumented server could retain only safe metadata such as scheme, validation outcome, issuer/audience result, and a non-reversible correlation hash; it must not log the token value. The current header extraction retains only `User-Agent` (`server/transport_wrapper.py:47-55`).
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

## 12. SSRF through OAuth metadata discovery

A malicious MCP server can direct a client to attacker-selected OAuth metadata URLs through `WWW-Authenticate`, protected-resource metadata, authorization-server metadata, or redirects. A client that fetches those URLs without scheme, address, redirect, and DNS validation can be induced to contact loopback services, private networks, or cloud metadata endpoints. Official guidance specifically discusses DNS rebinding and time-of-check/time-of-use hazards in this discovery chain.

- **Victim side:** client.
- **Server-side honeypot observability:** **Not observable server-side as an inbound attack.** The malicious values travel from server to client, and the client's subsequent SSRF requests go to the selected internal target. A malicious-server research fixture could record which metadata URLs a client follows, but this honeypot does not implement `WWW-Authenticate` challenges or OAuth metadata routes. Requests from generic scanners to unimplemented `/.well-known/...` paths would be reconnaissance, not evidence that this SSRF attack succeeded.
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

## 13. Malicious OAuth authorization-URL handling

A malicious MCP server can publish a dangerous `authorization_endpoint` that a client opens without strict scheme validation. Official guidance describes `javascript:` URL execution in browser contexts and command injection when clients invoke a shell to open a URL. CVE-2025-6514 demonstrated this class in `mcp-remote` versions 0.0.5 through 0.1.15: a crafted authorization endpoint reached the platform URL-opening path and enabled code execution; version 0.1.16 fixed the issue.

- **Victim side:** client.
- **Server-side honeypot observability:** **Not observable server-side as an inbound attack.** The exploit value is sent by a malicious server in OAuth metadata. This honeypot neither serves OAuth metadata nor sees the client's local URL-opening behavior. `User-Agent` or `clientInfo` may fingerprint an `mcp-remote` version, but a fingerprint is a vulnerable precondition, not evidence of exploitation (`server/transport_wrapper.py:47-69`).
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
  - https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/
  - https://nvd.nist.gov/vuln/detail/CVE-2025-6514

## 14. Local-server startup and stdio-proxy compromise

Local MCP integrations often cause the client to launch an executable supplied by configuration, and some proxy architectures expose a service that can spawn stdio servers. Published MCP guidance identifies malicious startup commands, malicious server packages, and stolen proxy credentials as paths to arbitrary command execution with the client's local privileges. The risk is specific to the deployment boundary around local MCP servers and stdio proxies rather than to stdio framing itself.

- **Victim side:** client.
- **Server-side honeypot observability:** **Not observable server-side.** Process launch, configuration installation, proxy-token theft, and child-process execution occur on the client host before or outside this remote SSE server. A later connection may expose `User-Agent`, `clientInfo`, methods, and timing, but those do not prove local compromise.
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

## 15. Capability and protocol-version probing

MCP initialization exposes `protocolVersion`, client capabilities, and implementation identity, after which a client can enumerate server features using methods such as `tools/list`, `resources/list`, and `prompts/list`. This is reconnaissance rather than exploitation by itself, but it is MCP-specific and can select later attacks based on sampling, roots, elicitation, resource, prompt, logging, or tool support. The protocol defines initialization ordering and version negotiation, while HTTP MCP adds the `MCP-Protocol-Version` header.

- **Victim side:** server.
- **Server-side honeypot observability:** **Directly observable.** Signals include `initialize.params.protocolVersion`, capability keys, `clientInfo`, the HTTP version header, JSON-RPC ids, method order, requests before initialization, a missing `notifications/initialized`, rapid enumeration of feature methods, error-driven reconnects, and timing between probes. Today only method, size, `User-Agent`, and `clientInfo.name/version` are retained; version, capabilities, header, id, and request kind are discarded (`gaps-kimi.md:13-28`). Two pin-specific behaviors change what a probe looks like on the wire, both verified against the downloaded 1.6.0 wheel this session. First, the pinned server does not negotiate: `session.py:151` answers every `initialize` with the constant `LATEST_PROTOCOL_VERSION = "2024-11-05"` (`types.py:32`) regardless of the version requested, so a version-mismatch probe gets an identical reply for every input and the interesting datum is the client's reaction to the implicit downgrade, not the server's response. Second, the 1.6.0 request branch of `_receive_loop` calls `ClientRequest.model_validate` with no surrounding try/except (`shared/session.py:306-311`; the adjacent notification branch does have one at `:329-349`), so an off-union method string raises `ValidationError`, escapes the loop, and tears down the SSE connection with no JSON-RPC error returned. Systematic enumeration against this pin therefore looks like repeated connect-initialize-one-probe-disconnect rather than one long enumerating session, and a burst of single-probe connections from one source is the signature to watch (`gaps-kimi.md:50-58`). The nine in-union-but-unhandled methods (`resources/*`, `prompts/*`, `logging/setLevel`, `completion/complete`) instead return `-32601`, which is the clean enumeration signal. Existing `rapid_enumeration` counts tool calls, not protocol-method enumeration (`server/tagging.py:151-154`).
- **Sources:**
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
  - https://modelcontextprotocol.io/specification/2025-06-18/server/tools

## Summary

| Class | Victim | Server-side honeypot result |
|---|---|---|
| Tool-description poisoning | client | Not first-order; second-order call arguments only |
| Rug-pull redefinition | client | Not observable server-side |
| Cross-server shadowing | both | Second-order calls, not attributable |
| Injection through results/resources | client | Second-order sequences, not attributable |
| Hidden-Unicode smuggling | both | Direct inbound code-point signal |
| ANSI terminal deception | client | Direct only if relayed inbound |
| Sampling abuse | client | Not inbound; capability precondition only |
| DNS rebinding/browser access | server | Direct HTTP-header and request signal |
| Session-id hijack/fixation | both | Direct session-id, source, and 404 signal |
| OAuth confused deputy | both | Not observable in current non-OAuth server |
| Token passthrough | server | Bearer presence visible; passthrough unprovable here |
| OAuth-discovery SSRF | client | Not observable server-side |
| Malicious authorization URL | client | Not observable server-side |
| Local startup/stdio proxy compromise | client | Not observable server-side |
| Capability/version probing | server | Direct initialization and method-sequence signal |

Five classes provide direct inbound signals at a server honeypot: hidden Unicode, inbound ANSI controls, DNS-rebinding/browser requests, session-id attacks, and capability/version probing. Four provide only partial or second-order evidence: tool poisoning, cross-server shadowing, result/resource injection, and token passthrough. Six are not observable as attacks at this honeypot: rug pulls, sampling abuse, OAuth confused deputy, OAuth-discovery SSRF, malicious authorization URLs, and local startup/stdio compromise.

## Gaps and cautions

1. No published prevalence dataset for real MCP honeypot traffic was found; this survey supports detection design, not base-rate claims.
2. Client-victim attacks dominate the literature. A server honeypot cannot honestly claim first-order detection of poisoning, rug pulls, shadowing, sampling abuse, or malicious OAuth metadata.
3. Several official security pages describe Streamable HTTP and protocol revisions newer than the deployed `mcp==1.6.0` legacy SSE implementation. Detection behavior must be verified against the pinned SDK, as `gaps-kimi.md` does.
4. Session-correlated detections are unreliable until the `session_id_var` task-boundary bug is fixed (`gaps-kimi.md:87-101`). Protocol instrumentation must also handle newer SDK `SessionMessage` wrappers before an SDK upgrade (`gaps-kimi.md:103-109`).
5. Generic malformed-JSON/schema fuzzing was deliberately excluded from the class list: it is observable and currently bypasses traces (`gaps-kimi.md:29`), but it is not MCP-specific. If the lane wants it covered for completeness, the hook is the same as for class 9 (wrap `handle_post_message` and count 400s alongside 404s).
6. CVE-2025-49596 and CVE-2025-6514 are the only CVE identifiers used. Both are tied to fetched primary or researcher sources above; no CVE identifier was inferred.
7. **Unverified** items, flagged per the brief rather than asserted:
   - Whether scanners in the wild probe OAuth discovery paths against MCP servers that implement no OAuth, and at what rate (class 12). No published telemetry found either way; this honeypot is well placed to answer it.
   - Inbound request body-size and JSON nesting limits under the deployed uvicorn/Starlette configuration. Not audited, so no claim is made about resistance to oversized or deeply nested payloads.
   - Prevalence or base rates for any class in this survey. No dataset of observed MCP attack traffic was found.
   - Client-side rendering behavior for hidden-Unicode and ANSI payloads across current MCP clients (classes 5 and 6). The cited research covers specific client versions at time of publication; current behavior was not retested here.
8. Scope judgement made and flagged for the lead: class 14 (local startup and stdio-proxy compromise) is included for taxonomy completeness even though it is wholly unobservable from an SSE server, because the brief asked for published MCP-specific classes. If the lane wants the survey narrowed to detectable classes only, it is the obvious cut.
9. Two active-probe options exist and are deliberately **not** recommended here: planting canary instructions in fake tool results (class 4) and issuing `sampling/createMessage` to see whether a client auto-approves (class 7). Both cross from passive observation into manipulating a connecting agent. Operator and lead decision, not a research-member call.
