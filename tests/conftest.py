"""Pytest configuration for the MCP Honeypot test suite."""

import pytest

collect_ignore_glob = ["smoke_test_standalone.py"]

# Auto-assign markers based on test file name
_UNIT_FILES = {"test_tagging", "test_config", "test_registry", "test_fake_responses"}
_MODULE_FILES = {
    "test_handlers",
    "test_transport_wrapper",
    "test_middleware",
    "test_main",
    "test_integration",
    "test_sse_session",
}
_TOOL_FILES = {"test_adversarial_agent", "test_export", "test_harness"}
_INTEGRATION_FILES = {"test_fingerprinting"}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Auto-apply markers based on test file membership."""
    for item in items:
        module_name = item.module.__name__.rsplit(".", 1)[-1] if item.module else ""

        if module_name in _UNIT_FILES:
            item.add_marker(pytest.mark.unit)
        elif module_name in _MODULE_FILES:
            item.add_marker(pytest.mark.module)
        elif module_name in _TOOL_FILES:
            item.add_marker(pytest.mark.tools)
        elif module_name in _INTEGRATION_FILES:
            item.add_marker(pytest.mark.integration)
