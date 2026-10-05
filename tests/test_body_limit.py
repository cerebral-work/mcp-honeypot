"""Request body size limit on the real app (TOD-1056).

``POST /messages`` had no size cap. These drive the assembled Starlette app,
so they also prove the middleware is actually wired in ``add_middleware``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

_UNKNOWN_SESSION = "/messages?session_id=00000000000000000000000000000000"


def _client():
    from httpx import ASGITransport, AsyncClient
    from main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class TestBodySizeLimit:
    async def test_declared_oversized_body_is_413(self):
        from config import settings

        body = b"x" * (settings.max_body_bytes + 1)
        async with _client() as client:
            resp = await client.post(_UNKNOWN_SESSION, content=body)
        assert resp.status_code == 413

    async def test_chunked_oversized_body_is_413(self):
        from config import settings

        chunk = b"y" * 65536
        chunks = settings.max_body_bytes // len(chunk) + 2

        async def stream():
            for _ in range(chunks):
                yield chunk

        async with _client() as client:
            resp = await client.post(_UNKNOWN_SESSION, content=stream())
        assert "content-length" not in {k.lower() for k in resp.request.headers}
        assert resp.status_code == 413

    async def test_body_at_the_limit_reaches_the_handler(self):
        from config import settings

        body = b"z" * settings.max_body_bytes
        async with _client() as client:
            resp = await client.post(_UNKNOWN_SESSION, content=body)
        # The SDK's own answer for an unknown session, not the size refusal.
        assert resp.status_code != 413
        assert resp.status_code == 404

    async def test_small_json_rpc_body_is_unchanged(self):
        async with _client() as client:
            resp = await client.post(
                _UNKNOWN_SESSION, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
            )
        assert resp.status_code == 404

    async def test_get_requests_are_not_buffered(self):
        async with _client() as client:
            resp = await client.get("/healthz")
        assert resp.status_code == 200
