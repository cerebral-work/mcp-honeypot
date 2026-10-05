"""Per-client-IP rate limit on POST /messages (TOD-1056).

Driven through the assembled app. The limit is lowered for the test by
swapping the parsed rate item and the limiter's storage, so the real code
path (allow_message inside the /messages endpoint) is what is exercised.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

_UNKNOWN_SESSION = "/messages?session_id=00000000000000000000000000000000"
_PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


@pytest.fixture
def low_limit(monkeypatch):
    import middleware
    from limits import parse
    from limits.storage import MemoryStorage
    from limits.strategies import MovingWindowRateLimiter

    monkeypatch.setattr(middleware, "messages_rate_item", parse("3/minute"))
    monkeypatch.setattr(
        middleware, "messages_rate_limiter", MovingWindowRateLimiter(MemoryStorage())
    )


def _client():
    from httpx import ASGITransport, AsyncClient
    from main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class TestMessagesRateLimit:
    def test_default_is_generous_and_configurable(self):
        from config import settings

        assert settings.messages_rate_limit == "600/minute"

    async def test_requests_past_the_limit_get_429(self, low_limit):
        headers = {"x-forwarded-for": "198.51.100.10"}
        async with _client() as client:
            codes = [
                (await client.post(_UNKNOWN_SESSION, json=_PING, headers=headers)).status_code
                for _ in range(5)
            ]
        assert codes[:3] == [404, 404, 404]
        assert codes[3:] == [429, 429]

    async def test_the_limit_is_per_client_ip(self, low_limit):
        async with _client() as client:
            for _ in range(3):
                await client.post(
                    _UNKNOWN_SESSION, json=_PING, headers={"x-forwarded-for": "198.51.100.11"}
                )
            other = await client.post(
                _UNKNOWN_SESSION, json=_PING, headers={"x-forwarded-for": "198.51.100.12"}
            )
        assert other.status_code == 404

    def test_an_invalid_rate_string_fails_config_load(self, monkeypatch):
        from config import Settings

        monkeypatch.setenv("MESSAGES_RATE_LIMIT", "lots")
        with pytest.raises(ValueError, match="MESSAGES_RATE_LIMIT"):
            Settings.from_env()
