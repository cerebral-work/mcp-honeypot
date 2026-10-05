"""Rate limiting and security headers middleware for the MCP Honeypot.

Provides:
- slowapi-based rate limiting (60 req/min global, 10/min on ``/sse``)
- Security headers on every response
- CORS (default ``*``, overridable via ``CORS_ORIGINS``)

Wire into a Starlette app by calling ``add_middleware(app)``.
"""

from __future__ import annotations

import os
from typing import Any

from config import settings
from limits import parse as parse_rate
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter
from logging_config import get_logger
from opentelemetry import trace
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Rate-limiter key function
# ---------------------------------------------------------------------------


def _client_ip(request: Request) -> str:
    """Extract the client IP from a Starlette request.

    Falls back to ``get_remote_address`` (peer IP).  When running behind a
    reverse proxy, ``X-Forwarded-For`` is preferred.
    """
    forwarded: str | None = request.headers.get("x-forwarded-for")
    if forwarded:
        # First entry is the original client.
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)


# ---------------------------------------------------------------------------
# Limiter singleton
# ---------------------------------------------------------------------------

limiter = Limiter(
    key_func=_client_ip,
    default_limits=["60/minute"],
    # Exempt /healthz from all rate limits.
    application_limits=[],
)


# ---------------------------------------------------------------------------
# Rate-limit decorators for specific routes
# ---------------------------------------------------------------------------

# These are importable so that route functions can be decorated directly.
sse_limit = limiter.limit("10/minute")


# ---------------------------------------------------------------------------
# Custom 429 handler — logs, sets span attribute, returns Retry-After
# ---------------------------------------------------------------------------


def _rate_limit_exceeded(request: Request, exc: RateLimitExceeded) -> Response:
    """Return a 429 response with ``Retry-After`` and record the event."""
    client = _client_ip(request)
    path = request.url.path

    log.warning(
        "rate_limit_exceeded",
        client_ip=client,
        path=path,
        limit=str(exc.detail),
    )

    # Tag the active span so downstream analysis can filter on rate-limited
    # requests.
    span = trace.get_current_span()
    if span.is_recording():
        span.set_attribute("honeypot.rate_limited", True)

    retry_after = getattr(exc, "retry_after", 60)

    return Response(
        content=f"Rate limit exceeded: {exc.detail}",
        status_code=429,
        headers={
            "Retry-After": str(retry_after),
            "Content-Type": "text/plain",
        },
    )


# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware:
    """ASGI middleware that injects security headers on every response."""

    HEADERS: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Server": "mcp-honeypot",
    }

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    # Paths that use raw ASGI streaming (SSE) — header wrapping breaks them.
    _SKIP_PATHS: set[str] = {"/sse", "/messages"}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Skip header injection for SSE/streaming endpoints — the MCP SDK
        # manages its own ASGI response lifecycle on these paths.
        path = scope.get("path", "")
        if any(path.startswith(p) for p in self._SKIP_PATHS):
            await self.app(scope, receive, send)
            return

        async def _send_with_headers(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))

                # Remove any existing Server header.
                headers = [(k, v) for k, v in headers if k.lower() != b"server"]

                # Append security headers.
                for name, value in self.HEADERS.items():
                    headers.append((name.encode(), value.encode()))

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, _send_with_headers)


# ---------------------------------------------------------------------------
# POST /messages rate limit (TOD-1056)
# ---------------------------------------------------------------------------

# Every JSON-RPC message of an MCP session is one POST /messages, and the
# rapid_enumeration flag fires above 10 calls in 5 s (~120/min). The limit is
# per client IP and deliberately generous (default 600/min) so floods are
# bounded without suppressing the bursts the honeypot exists to record.
messages_rate_limiter = MovingWindowRateLimiter(MemoryStorage())
messages_rate_item = parse_rate(settings.messages_rate_limit)


def allow_message(scope: Scope) -> tuple[bool, str]:
    """Count one POST /messages for the caller; return (allowed, client_ip)."""
    client_ip = _client_ip(Request(scope))
    return messages_rate_limiter.hit(messages_rate_item, "messages", client_ip), client_ip


# ---------------------------------------------------------------------------
# Request body size limit (TOD-1056)
# ---------------------------------------------------------------------------

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class BodySizeLimitMiddleware:
    """Refuse request bodies larger than ``max_bytes`` with 413.

    ``POST /messages`` carries every JSON-RPC message of an MCP session and
    had no size cap, so one client could make the server parse and serialize
    arbitrarily large payloads. A declared ``Content-Length`` over the limit
    is refused before any body is read; a chunked body is counted as it
    arrives and refused once it crosses the limit. Accepted bodies are
    buffered (at most ``max_bytes``) and replayed to the app unchanged.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _refuse(self, scope: Scope, receive: Receive, send: Send, size: int) -> None:
        client = scope.get("client") or ("unknown", 0)
        log.warning(
            "request_body_too_large",
            path=scope.get("path", ""),
            client_ip=client[0],
            size=size,
            limit=self.max_bytes,
        )
        response = PlainTextResponse("request body too large", status_code=413)
        await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    break
                if declared > self.max_bytes:
                    await self._refuse(scope, receive, send, declared)
                    return
                break

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                # Client went away mid-body: nothing to serve.
                return
            body = message.get("body", b"")
            total += len(body)
            if total > self.max_bytes:
                await self._refuse(scope, receive, send, total)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        buffered = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": buffered, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


# ---------------------------------------------------------------------------
# Public integration point
# ---------------------------------------------------------------------------


def add_middleware(app: Starlette) -> None:
    """Wire rate limiting, security headers, and CORS into *app*.

    Must be called **before** the app starts serving (i.e. at module-load
    time or in a startup factory).
    """
    # -- slowapi ---------------------------------------------------------
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded)  # type: ignore[arg-type]

    # -- Body size limit (TOD-1056) --------------------------------------
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)  # type: ignore[arg-type]

    # -- Security headers ------------------------------------------------
    app.add_middleware(SecurityHeadersMiddleware)  # type: ignore[arg-type]

    # -- CORS ------------------------------------------------------------
    raw_origins = os.environ.get("CORS_ORIGINS", "*").strip()
    if raw_origins == "*":
        allow_origins: list[str] = ["*"]
    else:
        allow_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    log.info(
        "middleware_configured",
        rate_limit_sse="10/minute",
        rate_limit_messages=settings.messages_rate_limit,
        max_body_bytes=settings.max_body_bytes,
        cors_origins=allow_origins,
    )
