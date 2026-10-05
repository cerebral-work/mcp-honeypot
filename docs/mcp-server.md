# MCP Honeypot Server

## Dependencies
    mcp==1.6.0
    opentelemetry-sdk==1.32.0
    opentelemetry-exporter-otlp-proto-grpc==1.32.0
    starlette==0.46.1
    uvicorn[standard]==0.34.0

## Directory Structure
    server/
    ├── main.py
    ├── instrumentation.py
    ├── transport_wrapper.py
    ├── tagging.py
    ├── config.py
    └── tools/
        ├── registry.py
        ├── fake_responses.py
        └── handlers/
            ├── filesystem.py
            ├── web.py
            ├── exec.py
            └── secrets.py

## Protocol Layer
Wraps MCP transport. Every inbound message creates a root span.

    tracer = get_tracer("mcp-honeypot.transport")

    class InstrumentedTransport:
        def _instrument_message(self, message):
            # Extract method from JSONRPCMessage → msg_dict
            findings = self._protocol.inspect(msg_dict)   # protocol_tagging.py, D1-D6
            with tracer.start_as_current_span(findings.span_name) as span:
                span.set_attribute("agent.id", self._agent_id)
                span.set_attribute("mcp.method", method)
                span.set_attribute("mcp.session_id", self.session_id)
                span.set_attribute("honeypot.phase", settings.honeypot_phase)
                span.set_attribute("mcp.message_size", message_size)
                span.set_attribute("anomaly.flags", ",".join(findings.flags))
                # plus findings.attributes; see otel.md "Message Spans"
                span.set_status(StatusCode.OK)

## Tool Layer
Every tool call creates a child span. Fake execution inside span context.

    tracer = get_tracer("mcp-honeypot.server")

    async def call_tool(name, arguments):
        with tracer.start_as_current_span(f"tool.{name}") as span:
            span.set_attribute("mcp.tool", name)
            span.set_attribute("mcp.session_id", session_id)
            span.set_attribute("honeypot.phase", settings.honeypot_phase)
            result = await dispatch(name, params, span, session_id)
            return [TextContent(type="text", text=json.dumps(result))]

## Fake Tool Categories
- Filesystem: read_file, write_file, list_directory, delete_file
- Web: fetch_url, search_web, screenshot
- Execution: run_command, run_python
- Secrets (high value): get_env_var, read_secret, list_secrets, get_api_key

## Config (environment variables via config.py)
    OTLP_ENDPOINT=otel-collector:4317
    OTLP_INSECURE=true
    SERVICE_NAME=mcp-honeypot
    MCP_HOST=0.0.0.0
    MCP_PORT=8000
    HONEYPOT_PHASE=research
    LOG_LEVEL=INFO
