"""MCP Honeypot server — full implementation (T07).

Exposes a fake MCP server over SSE that mimics real tool execution while
logging every interaction via OpenTelemetry.  All 13 tools from the
registry are advertised and dispatched to category-specific handlers that
return plausible fake responses.

Start with::

    uvicorn main:app --host 0.0.0.0 --port 8000

Or::

    python main.py
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

# ---------------------------------------------------------------------------
# Bootstrap logging and telemetry (order matters)
# ---------------------------------------------------------------------------
from logging_config import get_logger, setup_logging
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

setup_logging()

import instrumentation  # noqa: E402
from instrumentation import get_tracer, setup_telemetry  # noqa: E402

setup_telemetry()

from config import settings  # noqa: E402
from middleware import add_middleware, limiter, sse_limit  # noqa: E402
from tools.handlers import dispatch  # noqa: E402
from tools.registry import TOOL_REGISTRY  # noqa: E402
from transport_wrapper import InstrumentedTransport  # noqa: E402

logger = get_logger(__name__)
tracer = get_tracer("mcp-honeypot.server")

# ---------------------------------------------------------------------------
# MCP Server instance
# ---------------------------------------------------------------------------
mcp_server = Server(settings.service_name)


@mcp_server.list_tools()
async def list_tools() -> list[Tool]:
    """Advertise all honeypot tools to connecting agents."""
    tools: list[Tool] = []
    for meta in TOOL_REGISTRY.values():
        tools.append(
            Tool(
                name=meta.name,
                description=meta.description,
                inputSchema=meta.input_schema,
            )
        )
    return tools


@mcp_server.call_tool()
async def call_tool(
    name: str,
    arguments: dict[str, Any] | None = None,
) -> Sequence[TextContent]:
    """Dispatch a tool call to the appropriate handler.

    The handler returns a dict payload which is serialised to JSON and
    returned as a single ``TextContent`` block.  The honeypot never raises
    — every call gets a plausible response.
    """
    params = arguments or {}

    # Retrieve the session_id from the logging context var (set by
    # InstrumentedTransport on each incoming message).
    from logging_config import session_id_var  # noqa: WPS433

    session_id = session_id_var.get() or "unknown"

    with tracer.start_as_current_span(
        f"tool.{name}",
        attributes={
            "mcp.tool": name,
            "mcp.session_id": session_id,
            "honeypot.phase": settings.honeypot_phase,
        },
    ) as span:
        try:
            result = await dispatch(name, params, span, session_id)
        except Exception:
            logger.exception("handler_error", tool=name, session_id=session_id)
            result = {"error": "internal error", "tool": name}

    payload_json = json.dumps(result, default=str)
    return [TextContent(type="text", text=payload_json)]


# ---------------------------------------------------------------------------
# SSE transport
# ---------------------------------------------------------------------------
sse_transport = SseServerTransport("/messages")


@sse_limit
async def handle_sse(request: Request) -> None:
    """``GET /sse`` — establish an SSE connection with per-session tracing."""
    # Extract connection metadata for instrumentation.
    client = request.client
    remote_ip = client.host if client else "0.0.0.0"
    raw_headers: list[tuple[bytes, bytes]] = list(request.scope.get("headers", []))

    transport = InstrumentedTransport(remote_ip=remote_ip, headers=raw_headers)

    logger.info(
        "sse_connection_opened",
        remote_ip=remote_ip,
        session_id=transport.session_id,
        agent_id=transport.agent_id,
    )

    instrumentation.mcp_sessions_active.add(1)
    try:
        async with sse_transport.connect_sse(
            request.scope,
            request.receive,
            request._send,  # noqa: SLF001 — Starlette exposes no public send
        ) as (read_stream, write_stream):
            async with transport.wrap_read_stream(read_stream) as instrumented_stream:
                await mcp_server.run(
                    instrumented_stream,
                    write_stream,
                    mcp_server.create_initialization_options(),
                )
    finally:
        instrumentation.mcp_sessions_active.add(-1)

    logger.info(
        "sse_connection_closed",
        session_id=transport.session_id,
        agent_id=transport.agent_id,
    )


async def handle_messages(request: Request) -> None:
    """``POST /messages`` — forward SSE messages to the transport."""
    await sse_transport.handle_post_message(
        request.scope,
        request.receive,
        request._send,  # noqa: SLF001
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@limiter.exempt
async def healthz(request: Request) -> JSONResponse:
    """``GET /healthz`` — lightweight liveness probe."""
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Starlette application
# ---------------------------------------------------------------------------
app = Starlette(
    debug=False,
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route("/sse", handle_sse, methods=["GET"]),
        Route("/messages", handle_messages, methods=["POST"]),
    ],
)

# T18 — Rate limiting, security headers, CORS.
add_middleware(app)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.mcp_host,
        port=settings.mcp_port,
        log_level=settings.log_level.lower(),
    )
