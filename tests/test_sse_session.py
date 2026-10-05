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


class TestSessionIdPropagation:
    """Tool handlers must see the session id of the connection that called them.

    Regression: the id was set on a context variable inside the transport's
    pump task, which the tool handlers never inherit, so every call was tagged
    "unknown" and all sessions shared one anomaly-tagging bucket.
    """

    async def test_each_session_reaches_dispatch_with_its_own_id(self, monkeypatch):
        import main
        import uvicorn
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        minted: list[str] = []
        dispatched: list[str] = []

        original_transport = main.InstrumentedTransport

        class RecordingTransport(original_transport):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                minted.append(self.session_id)

        original_dispatch = main.dispatch

        async def recording_dispatch(name, params, span, session_id):
            dispatched.append(session_id)
            return await original_dispatch(name, params, span, session_id)

        monkeypatch.setattr(main, "InstrumentedTransport", RecordingTransport)
        monkeypatch.setattr(main, "dispatch", recording_dispatch)

        port = _free_port()
        server = uvicorn.Server(
            uvicorn.Config(
                main.app,
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

            for tool, args in (
                ("read_secret", {"name": "AWS_SECRET_ACCESS_KEY"}),
                ("read_file", {"path": "/etc/hostname"}),
            ):
                async with (
                    sse_client(f"http://127.0.0.1:{port}/sse") as (read, write),
                    ClientSession(read, write) as session,
                ):
                    await asyncio.wait_for(session.initialize(), timeout=10)
                    await asyncio.wait_for(session.call_tool(tool, args), timeout=10)
        finally:
            server.should_exit = True
            server.force_exit = True
            await asyncio.wait_for(serve_task, timeout=10)

        assert len(minted) == 2
        assert minted[0] != minted[1]
        assert dispatched == minted


async def _serve(app):
    """Start *app* under uvicorn on a free port; return (server, task, port)."""
    import uvicorn

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
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.025)
    assert server.started, "uvicorn did not start"
    return server, task, port


async def _stop(server, task) -> None:
    server.should_exit = True
    server.force_exit = True
    await asyncio.wait_for(task, timeout=10)


class TestProtocolDetectionsEndToEnd:
    """MCP-native detections observed through the real SSE server (spec P1)."""

    async def test_real_client_session_records_version_and_raises_no_flags(
        self, monkeypatch, span_exporter
    ):
        import main
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        minted: list[str] = []
        original_transport = main.InstrumentedTransport

        class RecordingTransport(original_transport):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                minted.append(self.session_id)

        monkeypatch.setattr(main, "InstrumentedTransport", RecordingTransport)
        server, task, port = await _serve(main.app)
        try:
            async with (
                sse_client(f"http://127.0.0.1:{port}/sse") as (read, write),
                ClientSession(read, write) as session,
            ):
                await asyncio.wait_for(session.initialize(), timeout=10)
                await asyncio.wait_for(session.list_tools(), timeout=10)
                await asyncio.wait_for(
                    session.call_tool("read_file", {"path": "/etc/hostname"}),
                    timeout=10,
                )
        finally:
            await _stop(server, task)

        (sid,) = minted
        spans = [
            s
            for s in span_exporter.get_finished_spans()
            if s.attributes.get("mcp.session_id") == sid and s.name.startswith("mcp.")
        ]
        names = [s.name for s in spans]
        assert "mcp.initialize" in names
        assert "mcp.tools/call" in names
        init = next(s for s in spans if s.name == "mcp.initialize")
        assert init.attributes["mcp.client.protocol_version"]
        assert [s.attributes.get("anomaly.flags") for s in spans] == [""] * len(spans)

    async def test_unknown_method_probe_is_flagged(self, span_exporter):
        import main
        from mcp.client.sse import sse_client
        from mcp.types import JSONRPCMessage

        server, task, port = await _serve(main.app)
        try:
            async with sse_client(f"http://127.0.0.1:{port}/sse") as (_read, write):
                probe = JSONRPCMessage.model_validate(
                    {"jsonrpc": "2.0", "id": 99, "method": "admin/exec"}
                )
                await write.send(probe)
                for _ in range(200):
                    if any(
                        s.name == "mcp.unknown_method" for s in span_exporter.get_finished_spans()
                    ):
                        break
                    await asyncio.sleep(0.025)
        finally:
            await _stop(server, task)

        flagged = [s for s in span_exporter.get_finished_spans() if s.name == "mcp.unknown_method"]
        assert flagged, "the unknown-method probe produced no flagged span"
        span = flagged[0]
        assert span.attributes["mcp.method.raw"] == "admin/exec"
        assert "unknown_method" in span.attributes["anomaly.flags"].split(",")
        # No initialize was sent, so the lifecycle rule fires on the same message.
        assert "lifecycle_violation" in span.attributes["anomaly.flags"].split(",")
