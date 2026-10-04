"""End-to-end SSE session test: a real MCP client connects over /sse.

Regression for the stale ``mcp_sessions_active`` binding: ``main`` imported
the counter by name before ``setup_telemetry()`` assigned it, so every
``GET /sse`` raised ``AttributeError`` on ``None.add`` and returned HTTP 500.
The route-existence tests in ``test_main`` could not see that.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestSseSession:
    """A full initialize + tools/list round trip over the SSE transport."""

    async def test_client_can_open_session_and_list_tools(self):
        import uvicorn
        from main import app
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        port = _free_port()
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="error",
                timeout_graceful_shutdown=1,
            )
        )
        serve_task = asyncio.create_task(server.serve())
        try:
            for _ in range(200):
                if server.started:
                    break
                await asyncio.sleep(0.025)
            assert server.started, "uvicorn did not start"

            async with (
                sse_client(f"http://127.0.0.1:{port}/sse") as (read, write),
                ClientSession(read, write) as session,
            ):
                await asyncio.wait_for(session.initialize(), timeout=10)
                listed = await asyncio.wait_for(session.list_tools(), timeout=10)

            assert len(listed.tools) == 13
        finally:
            # An SSE response stays open until the server tears it down, so
            # bound shutdown rather than waiting on a graceful drain.
            server.should_exit = True
            server.force_exit = True
            await asyncio.wait_for(serve_task, timeout=10)
