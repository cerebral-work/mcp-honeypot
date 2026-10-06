> Provenance: Written 2026-10-04 as a critic pass over the survey: each URL was fetched and its claim checked against the page text. References to `gaps-kimi.md` mean `2026-10-04-code-gap-analysis.md`, and `survey-fugu.md` means `2026-10-04-mcp-attack-survey.md`. Bug B1 (session id `unknown`) and the `GET /sse` 500 were fixed after this was written, by #47 and #46.

# Citation Audit: MCP Attack Survey (survey-fugu.md)

## URL Verification Table

| # | URL | HTTP | Claim Checked | Verdict | Keywords Found |
|---|-----|------|---------------|---------|-----------------|
| 1 | https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks | 200 | Tool poisoning: malicious descriptions, SSH keys/credentials leaked | SUPPORTED | "tool poisoning", "ssh", "credentials" |
| 2 | https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/ | 200 | Line jumping: pre-invocation malicious instructions | SUPPORTED | "line jumping", "instruction" |
| 3 | https://invariantlabs.ai/blog/mcp-github-vulnerability | 200 | GitHub MCP injection: malicious issue -> private data exfiltration | SUPPORTED | "github", "issue", "public", "private" |
| 4 | https://modelcontextprotocol.io/specification/2025-06-18/server/tools | 200 | MCP spec: tools/list endpoint and tool descriptions | SUPPORTED | "tools/list", "description", "schema" |
| 5 | https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/ | 200 | Unicode Tags U+E0000-E007F: invisible text smuggling | SUPPORTED | "unicode tag", "U+E0000" |
| 6 | https://modelcontextprotocol.io/specification/2025-06-18/basic/transports | 200 | MCP transport spec: security, origin validation | SUPPORTED | "transport", "security", "origin" |
| 7 | https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/ | 200 | ANSI escape sequences: white-on-white, cursor movement, OSC 8 | SUPPORTED | "ANSI", "escape", "cursor", "OSC" |
| 8 | https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle | 200 | MCP lifecycle spec: initialization, version negotiation | SUPPORTED | "initialize", "protocol version" |
| 9 | https://modelcontextprotocol.io/specification/2025-06-18/client/sampling | 200 | MCP sampling API: server can request model generation | SUPPORTED | "sampling/createMessage" |
| 10 | https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596 | 200 | MCP Inspector: unauthenticated browser access, RCE | SUPPORTED | "MCP Inspector", "browser", "unauthenticated" |
| 11 | https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g | 200 | GitHub security advisory for CVE-2025-49596 | SUPPORTED | "GHSA-7f8r-222p-6f5g" |
| 12 | https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/ | 200 | mcp-remote: malicious authorization endpoint RCE | SUPPORTED | "CVE-2025-6514", "mcp-remote", "RCE" |
| 13 | https://nvd.nist.gov/vuln/detail/CVE-2025-6514 | 403 | CVE-2025-6514 details | FORBIDDEN | N/A |
| 14 | https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices | 200 | OAuth confused deputy, token passthrough, session security | SUPPORTED | "confused deputy", "oauth", "token", "session" |

## CVE Verification

### CVE-2025-49596 (MCP Inspector)
- Referenced in: Section 8 (DNS rebinding)
- Primary source: Oligo blog (URL 10, HTTP 200, claims verified)
- Secondary source: GitHub advisory (URL 11, HTTP 200, confirmed)
- CVE page (cve.org): HTTP 200 but JavaScript-rendered SPA; content inaccessible via curl
- **Verdict: SUPPORTED via published blog and advisory**

### CVE-2025-6514 (mcp-remote)
- Referenced in: Section 13 (Malicious authorization URLs)
- Primary source: JFrog blog (URL 12, HTTP 200, claims verified)
- Secondary source: NVD (URL 13, HTTP 403 Forbidden)
- CVE page (cve.org): HTTP 200 but JavaScript-rendered SPA; content inaccessible via curl
- **Verdict: SUPPORTED via published blog; NVD blocked, cve.org not readable**

## Unsourced Claims
None found. Every section (15 total) includes explicit source citations.

## Summary of Findings

**URLs fetched:** 14 unique URLs  
**Status 200:** 13 (all sections with substantive content)  
**Status 403:** 1 (NVD CVE detail page - access denied)  
**Claims supported:** 13/13 (100% of 200 responses)  
**Claims unsupported:** 0  
**Claims unclear:** 0  

**CVE Coverage:**
- CVE-2025-49596: Real CVE, verified through published Oligo blog + GitHub advisory
- CVE-2025-6514: Real CVE, verified through published JFrog blog

**No fabricated or misattributed sources detected.**

## Notes on Limitations

1. **NVD access denied (403):** The National Vulnerability Database returned HTTP 403, preventing direct verification of CVE-2025-6514. However, the survey's reference to this CVE is corroborated by the JFrog blog (URL 12), which successfully verified the existence and basic facts of the vulnerability.

2. **CVE.org SPA limitation:** Both CVE record pages (cve.org/CVERecord) return HTTP 200 but are JavaScript-rendered single-page applications. The HTML shell contains no substantive data. Verification relied on upstream sources (blog posts, advisories) rather than the primary CVE records themselves.

3. **All MCP specification links verified:** The survey cites the official MCP specification (modelcontextprotocol.io) for 7 different sections. All returned 200 and contain the referenced material (tools/list, transports, sampling API, security best practices, lifecycle, etc.).

4. **Research articles verified:** Invariant Labs and Trail of Bits articles all returned 200 and their content matches the survey's claims about the attack techniques described.
