"""Instrumented transport wrapper for MCP SSE connections.

Intercepts every incoming MCP message to create a root span with honeypot-
specific attributes (agent fingerprint, session ID, method, phase).  Also
sets the ``session_id_var`` context variable for structured log correlation.

The wrapper sits between the Starlette ASGI layer and the MCP Server,
decorating the read stream that ``Server.run()`` consumes.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import instrumentation
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from config import settings
from instrumentation import get_tracer
from logging_config import get_logger, session_id_var
from opentelemetry.trace import StatusCode
from protocol_tagging import ConnectionProtocolState, truncate

logger = get_logger(__name__)
tracer = get_tracer("mcp-honeypot.transport")


# ---------------------------------------------------------------------------
# Session ID derivation
# ---------------------------------------------------------------------------


def derive_session_id(remote_ip: str, connect_ts: float) -> str:
    """SHA-256 of ``remote_ip:connect_timestamp``, first 16 hex chars."""
    raw = f"{remote_ip}:{connect_ts}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Agent fingerprinting
# ---------------------------------------------------------------------------


def _extract_agent_from_user_agent(headers: list[tuple[bytes, bytes]]) -> str | None:
    """Pull the User-Agent value from raw ASGI headers, if present."""
    for name, value in headers:
        if name.lower() == b"user-agent":
            ua = value.decode("utf-8", errors="replace").strip()
            if ua:
                return ua
    return None


def _extract_agent_from_initialize(message: dict[str, Any]) -> str | None:
    """Extract ``clientInfo.name/version`` from an MCP initialize request."""
    params = message.get("params", {})
    client_info = params.get("clientInfo") or params.get("client_info")
    if not client_info:
        return None
    name = client_info.get("name", "")
    version = client_info.get("version", "")
    if name and version:
        return f"{name}/{version}"
    return name or None


# ---------------------------------------------------------------------------
# InstrumentedTransport
# ---------------------------------------------------------------------------


class InstrumentedTransport:
    """Wraps an MCP SSE connection to add per-message tracing.

    Lifecycle
    ---------
    1. Created once per SSE ``/sse`` connection.
    2. ``wrap_read_stream`` is called with the raw read stream from
       ``SseServerTransport.connect_sse``.  It returns a new receive stream
       whose consumer (``Server.run``) sees the same messages, but each
       message is wrapped in an OTel span.
    3. The write stream passes through unchanged.
    """

    def __init__(
        self,
        remote_ip: str,
        headers: list[tuple[bytes, bytes]],
    ) -> None:
        self._connect_ts = time.time()
        self._remote_ip = remote_ip
        self.session_id = derive_session_id(remote_ip, self._connect_ts)

        # Best-effort agent ID from the HTTP headers; may be refined later
        # when the MCP ``initialize`` message arrives.
        self._agent_id: str = _extract_agent_from_user_agent(headers) or self.session_id
        self._agent_id_refined: bool = False

        # Per-connection protocol state for the MCP-native detections
        # (docs/spec-mcp-native-detections.md, D1-D6). Dies with the connection.
        self._protocol = ConnectionProtocolState()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    # ------------------------------------------------------------------
    # Stream wrapping
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def wrap_read_stream(
        self,
        raw_stream: MemoryObjectReceiveStream[Any],
    ) -> AsyncIterator[MemoryObjectReceiveStream[Any]]:
        """Yield a replacement receive stream that instruments each message."""
        send_channel: MemoryObjectSendStream[Any]
        recv_channel: MemoryObjectReceiveStream[Any]
        send_channel, recv_channel = anyio.create_memory_object_stream[Any](0)

        async def _pump() -> None:
            try:
                async with raw_stream, send_channel:
                    async for message in raw_stream:
                        self._instrument_message(message)
                        await send_channel.send(message)
            except anyio.ClosedResourceError:
                pass

        async with anyio.create_task_group() as tg:
            tg.start_soon(_pump)
            try:
                yield recv_channel
            finally:
                tg.cancel_scope.cancel()

    # ------------------------------------------------------------------
    # Per-message instrumentation
    # ------------------------------------------------------------------

    def _instrument_message(self, message: Any) -> None:
        """Start (and immediately end) a root span for *message*."""
        # The MCP SDK passes ``JSONRPCMessage`` objects.  We need to
        # extract the JSON-RPC method and compute the message size for
        # span attributes.
        method = "unknown"
        msg_dict: dict[str, Any] = {}

        # JSONRPCMessage wraps a root model; access the inner dict.
        try:
            if hasattr(message, "root"):
                # pydantic model — message.root is the union variant
                inner = message.root
                if hasattr(inner, "model_dump"):
                    msg_dict = inner.model_dump(mode="python", by_alias=True)
                elif hasattr(inner, "dict"):
                    msg_dict = inner.dict()
                elif isinstance(inner, dict):
                    msg_dict = inner
            elif isinstance(message, dict):
                msg_dict = message
        except Exception:
            pass

        method = msg_dict.get("method", method)
        message_size = len(json.dumps(msg_dict, default=str))

        # MCP-native protocol detections. Pure and never raises; the span name
        # comes from a fixed vocabulary so attacker-chosen methods cannot mint
        # new span names (spec section 3.1).
        findings = self._protocol.inspect(msg_dict)

        # Refine agent ID from the ``initialize`` message if not yet done.
        if method == "initialize" and not self._agent_id_refined:
            agent = _extract_agent_from_initialize(msg_dict)
            if agent:
                self._agent_id = agent
                self._agent_id_refined = True

        # Set session context var for structured logging.
        session_id_var.set(self.session_id)

        # Create a span (immediately ended — handlers create their own
        # child spans for tool execution).
        attributes: dict[str, Any] = {
            "agent.id": self._agent_id,
            "mcp.method": truncate(method),
            "mcp.session_id": self.session_id,
            "honeypot.phase": settings.honeypot_phase,
            "mcp.message_size": message_size,
            "anomaly.flags": ",".join(findings.flags),
        }
        attributes.update(findings.attributes)

        with tracer.start_as_current_span(findings.span_name, attributes=attributes) as span:
            span.set_status(StatusCode.OK)

        # Label values are the fixed flag vocabulary only. Read the counter
        # through the module at call time: it is assigned by setup_telemetry().
        counter = instrumentation.mcp_anomalies_total
        if counter is not None:
            for flag in findings.flags:
                counter.add(1, {"flag": flag})

        if findings.flags:
            logger.info(
                "mcp_protocol_anomaly",
                flags=findings.flags,
                method=truncate(method),
                agent_id=self._agent_id,
            )

        logger.debug(
            "mcp_message_received",
            method=truncate(method),
            agent_id=self._agent_id,
            message_size=message_size,
        )
