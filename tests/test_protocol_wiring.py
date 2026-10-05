"""Wiring tests: protocol findings reach spans, metrics and span names.

The detection rules themselves are unit-tested in test_protocol_tagging.
These tests drive real ``JSONRPCMessage`` objects through
``InstrumentedTransport.wrap_read_stream`` and read the spans back from an
in-memory exporter.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path
from typing import Any

import anyio

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

# A distinct address per drive keeps derived session ids distinct.
_octets = itertools.count(1)


def _message(payload: dict[str, Any]):
    from mcp.types import JSONRPCMessage

    return JSONRPCMessage.model_validate({"jsonrpc": "2.0", **payload})


async def _drive(messages: list[Any]) -> str:
    """Push *messages* through a fresh transport; return its session id."""
    from transport_wrapper import InstrumentedTransport

    transport = InstrumentedTransport(remote_ip=f"203.0.113.{next(_octets)}", headers=[])
    send, recv = anyio.create_memory_object_stream[Any](len(messages))
    for message in messages:
        await send.send(message)
    await send.aclose()
    async with transport.wrap_read_stream(recv) as wrapped:
        async for _ in wrapped:
            pass
    return transport.session_id


def _spans_for(exporter, session_id: str):
    return [
        s for s in exporter.get_finished_spans() if s.attributes.get("mcp.session_id") == session_id
    ]


class TestUnknownMethodWiring:
    async def test_unknown_method_flagged_on_span_with_bounded_name(self, span_exporter):
        sid = await _drive([_message({"id": 1, "method": "foo/bar"})])
        (span,) = _spans_for(span_exporter, sid)
        assert span.name == "mcp.unknown_method"
        assert "unknown_method" in span.attributes["anomaly.flags"].split(",")
        assert span.attributes["mcp.method.raw"] == "foo/bar"
        assert span.attributes["mcp.message_kind"] == "request"

    async def test_known_method_keeps_its_span_name_and_no_flags(self, span_exporter):
        sid = await _drive(
            [
                _message(
                    {
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "t", "version": "1"},
                        },
                    }
                ),
                _message({"method": "notifications/initialized"}),
                _message({"id": 2, "method": "tools/list"}),
            ]
        )
        spans = _spans_for(span_exporter, sid)
        assert [s.name for s in spans] == [
            "mcp.initialize",
            "mcp.notifications/initialized",
            "mcp.tools/list",
        ]
        assert all(s.attributes["anomaly.flags"] == "" for s in spans)
        assert spans[0].attributes["mcp.client.protocol_version"] == "2025-06-18"

    async def test_overlong_unknown_method_is_truncated_on_the_span(self, span_exporter):
        from protocol_tagging import MAX_ATTR_LEN

        method = "x" * (MAX_ATTR_LEN * 4)
        sid = await _drive([_message({"id": 1, "method": method})])
        (span,) = _spans_for(span_exporter, sid)
        assert span.name == "mcp.unknown_method"
        assert span.attributes["mcp.method.raw"].startswith("x" * MAX_ATTR_LEN)
        assert span.attributes["mcp.method.raw"].endswith(f"[truncated {len(method)}]")
        assert len(span.attributes["mcp.method"]) < len(method)


class TestLifecycleWiring:
    async def test_tool_call_before_initialize_is_flagged(self, span_exporter):
        sid = await _drive(
            [_message({"id": 1, "method": "tools/call", "params": {"name": "read_file"}})]
        )
        (span,) = _spans_for(span_exporter, sid)
        assert "lifecycle_violation" in span.attributes["anomaly.flags"].split(",")
        assert span.attributes["mcp.lifecycle.reason"] == "no_initialize"

    async def test_state_is_per_connection(self, span_exporter):
        init = _message(
            {
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            }
        )
        await _drive([init, _message({"method": "notifications/initialized"})])
        # A second connection has not initialized, whatever the first one did.
        sid = await _drive([_message({"id": 2, "method": "tools/list"})])
        (span,) = _spans_for(span_exporter, sid)
        assert span.attributes["mcp.lifecycle.reason"] == "no_initialize"


class TestAnomalyMetric:
    async def test_counter_labels_come_only_from_the_flag_vocabulary(self, monkeypatch):
        import instrumentation
        from protocol_tagging import PROTOCOL_FLAGS

        calls: list[tuple[int, dict[str, str]]] = []

        class Recorder:
            def add(self, amount: int, labels: dict[str, str]) -> None:
                calls.append((amount, labels))

        monkeypatch.setattr(instrumentation, "mcp_anomalies_total", Recorder())
        await _drive(
            [
                _message({"id": 1, "method": "foo/bar"}),
                _message({"id": 2, "method": "tools/call", "params": {"name": "x"}}),
            ]
        )
        assert calls, "no anomaly was counted"
        for amount, labels in calls:
            assert amount == 1
            assert set(labels) == {"flag"}
            assert labels["flag"] in PROTOCOL_FLAGS
        assert {"flag": "unknown_method"} in [labels for _, labels in calls]

    async def test_no_counter_assigned_does_not_break_the_stream(self, monkeypatch):
        import instrumentation

        monkeypatch.setattr(instrumentation, "mcp_anomalies_total", None)
        await _drive([_message({"id": 1, "method": "foo/bar"})])
