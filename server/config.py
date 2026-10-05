from __future__ import annotations

import os
from dataclasses import dataclass

from limits import parse as _parse_rate


def _get(key: str, default: str) -> str:
    return os.environ.get(key, default).strip() or default


def _get_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"Environment variable {key!r} must be an integer, got {raw!r}") from None


def _require(key: str) -> str:
    """Return env var value or raise ValueError if absent or empty."""
    val = os.environ.get(key, "").strip()
    if not val:
        raise ValueError(f"Required environment variable {key!r} is not set")
    return val


_VALID_PHASES = {"research", "public"}
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@dataclass(frozen=True)
class Settings:
    # MCP server
    mcp_host: str
    mcp_port: int

    # Identity
    service_name: str
    honeypot_phase: str  # "research" | "public"
    webhook_secret: str | None

    # Telemetry
    otlp_endpoint: str
    otlp_insecure: bool

    # Logging
    log_level: str

    # Request limits (TOD-1056): largest accepted request body in bytes, and
    # the per-client-IP rate for POST /messages (a `limits` rate string).
    max_body_bytes: int = 1_048_576
    messages_rate_limit: str = "600/minute"

    @classmethod
    def from_env(cls) -> Settings:
        honeypot_phase = _get("HONEYPOT_PHASE", "research")
        if honeypot_phase not in _VALID_PHASES:
            raise ValueError(
                f"HONEYPOT_PHASE must be one of {_VALID_PHASES}, got {honeypot_phase!r}"
            )

        log_level = _get("LOG_LEVEL", "INFO").upper()
        if log_level not in _VALID_LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {_VALID_LOG_LEVELS}, got {log_level!r}")

        mcp_port = _get_int("MCP_PORT", 8000)
        if not (1 <= mcp_port <= 65535):
            raise ValueError(f"MCP_PORT must be 1–65535, got {mcp_port}")

        max_body_bytes = _get_int("MAX_REQUEST_BODY_BYTES", 1_048_576)
        if max_body_bytes < 1024:
            raise ValueError(f"MAX_REQUEST_BODY_BYTES must be >= 1024, got {max_body_bytes}")

        messages_rate_limit = _get("MESSAGES_RATE_LIMIT", "600/minute")
        try:
            _parse_rate(messages_rate_limit)
        except ValueError as exc:
            raise ValueError(
                f"MESSAGES_RATE_LIMIT must be a rate like '600/minute', got {messages_rate_limit!r}"
            ) from exc

        # Required in public phase: agents need a shared secret to authenticate
        # health-check webhooks. Not needed in research phase.
        webhook_secret: str | None = None
        if honeypot_phase == "public":
            webhook_secret = _require("HONEYPOT_WEBHOOK_SECRET")

        return cls(
            mcp_host=_get("MCP_HOST", "0.0.0.0"),
            mcp_port=mcp_port,
            service_name=_get("SERVICE_NAME", "mcp-honeypot"),
            honeypot_phase=honeypot_phase,
            webhook_secret=webhook_secret,
            otlp_endpoint=_get("OTLP_ENDPOINT", "otel-collector:4317"),
            otlp_insecure=os.environ.get("OTLP_INSECURE", "true").lower() != "false",
            log_level=log_level,
            max_body_bytes=max_body_bytes,
            messages_rate_limit=messages_rate_limit,
        )


# Module-level singleton — validated at import time.
settings = Settings.from_env()
