"""Unit tests for server.tools.handlers (dispatch + handler.handle)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from tools.handlers import (
    dispatch,  # noqa: E402
    filesystem,  # noqa: E402
)

# ======================================================================
# dispatch routing — uses real handlers, verifies return types
# ======================================================================


class TestDispatchRouting:
    """Tests that dispatch routes tool names to correct handlers and returns dicts."""

    async def test_filesystem_tool_returns_dict(self):
        result = await dispatch("read_file", {"path": "/etc/passwd"}, MagicMock(), "s1")
        assert isinstance(result, dict)

    async def test_web_tool_returns_dict(self):
        result = await dispatch("fetch_url", {"url": "http://x.com"}, MagicMock(), "s1")
        assert isinstance(result, dict)

    async def test_exec_tool_returns_dict(self):
        result = await dispatch("run_command", {"command": "ls"}, MagicMock(), "s1")
        assert isinstance(result, dict)

    async def test_secrets_tool_returns_dict(self):
        result = await dispatch("get_env_var", {"name": "HOME"}, MagicMock(), "s1")
        assert isinstance(result, dict)

    async def test_unknown_tool_returns_dict(self):
        """Unknown tools fall back to filesystem handler — still return a dict."""
        result = await dispatch("totally_unknown", {}, MagicMock(), "s1")
        assert isinstance(result, dict)

    async def test_dispatch_returns_payload_with_content(self):
        result = await dispatch("read_file", {"path": "/etc/hosts"}, MagicMock(), "s1")
        assert "content" in result or "status" in result


# ======================================================================
# handler.handle() — test span attributes and metrics via mocking
# ======================================================================


class TestHandlerHandle:
    """Tests for individual handler handle() functions."""

    @pytest.fixture(autouse=True)
    def _setup_mocks(self):
        self.mock_counter = MagicMock()
        self.mock_anomaly = MagicMock()
        self.mock_latency = MagicMock()
        with (
            patch("tools.handlers.filesystem.mcp_tool_calls_total", self.mock_counter),
            patch("tools.handlers.filesystem.mcp_anomalies_total", self.mock_anomaly),
            patch("tools.handlers.filesystem.mcp_response_latency_ms", self.mock_latency),
        ):
            yield

    async def test_returns_dict(self):
        span = MagicMock()
        result = await filesystem.handle("read_file", {"path": "/tmp/a"}, span, "s1")
        assert isinstance(result, dict)

    async def test_sets_span_attributes(self):
        span = MagicMock()
        await filesystem.handle("read_file", {"path": "/tmp/a"}, span, "s1")
        attr_calls = {c[0][0]: c[0][1] for c in span.set_attribute.call_args_list}
        assert attr_calls["mcp.tool"] == "read_file"
        assert "anomaly.flags" in attr_calls

    async def test_increments_tool_calls_counter(self):
        span = MagicMock()
        await filesystem.handle("list_directory", {"path": "."}, span, "s1")
        self.mock_counter.add.assert_called_once()
        args, kwargs = self.mock_counter.add.call_args
        assert args[0] == 1
        assert args[1]["tool"] == "list_directory"

    async def test_increments_anomaly_counter_per_flag(self):
        span = MagicMock()
        with patch(
            "tools.handlers.filesystem.detect_anomalies",
            return_value=["credential_probe", "path_traversal"],
        ):
            await filesystem.handle("read_file", {"path": "../../etc/passwd"}, span, "s1")
        assert self.mock_anomaly.add.call_count == 2

    async def test_never_raises(self):
        """Handler catches exceptions and returns a fallback dict."""
        span = MagicMock()
        with patch(
            "tools.handlers.filesystem.detect_anomalies",
            side_effect=RuntimeError("boom"),
        ):
            result = await filesystem.handle("read_file", {}, span, "s1")
        assert isinstance(result, dict)

    async def test_records_latency(self):
        span = MagicMock()
        with patch("tools.handlers.filesystem.detect_anomalies", return_value=[]):
            await filesystem.handle("list_directory", {"path": "."}, span, "s1")
        self.mock_latency.record.assert_called_once()

    async def test_unknown_tool_bounds_metric_label_to_other_and_truncates_span(self):
        span = MagicMock()
        attacker_tool = "evil_tool_" + ("x" * 400)
        with patch("tools.handlers.filesystem.detect_anomalies", return_value=[]):
            await filesystem.handle(attacker_tool, {}, span, "s1")
        args, _ = self.mock_counter.add.call_args
        assert args[1]["tool"] == "other"
        lat_args, _ = self.mock_latency.record.call_args
        assert lat_args[1]["tool"] == "other"
        attr_calls = {c[0][0]: c[0][1] for c in span.set_attribute.call_args_list}
        assert attr_calls["mcp.tool"].startswith("evil_tool_")
        assert attr_calls["mcp.tool"].endswith("...[truncated 410]")
        assert len(attr_calls["mcp.tool"]) < len(attacker_tool)

    async def test_agent_label_budget_caps_distinct_series_and_span_tool_name_is_fixed(self):
        from tools.registry import (
            MAX_DISTINCT_AGENT_LABELS,
            bounded_agent_label,
            reset_agent_label_budget,
            span_tool_name,
        )

        assert span_tool_name("read_file") == "tool.read_file"
        assert span_tool_name("attacker_invented_tool") == "tool.unknown"

        reset_agent_label_budget()
        for i in range(MAX_DISTINCT_AGENT_LABELS):
            assert bounded_agent_label(f"sess-{i}") == f"sess-{i}"
        assert bounded_agent_label("sess-overflow") == "other"
        assert bounded_agent_label("sess-0") == "sess-0"
        reset_agent_label_budget()
