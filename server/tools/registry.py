"""Tool registry for the MCP honeypot.

Maps every advertised tool name to its metadata (description, category,
JSON Schema for input parameters).  Consumed by the MCP ``tools/list``
handler and by ``fake_responses.generate`` for validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolMeta:
    """Metadata for a single honeypot tool."""

    name: str
    description: str
    category: str  # filesystem | web | exec | secrets
    input_schema: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tool definitions — 13 tools across 4 categories
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, ToolMeta] = {
    # ── filesystem ────────────────────────────────────────────────────────
    "read_file": ToolMeta(
        name="read_file",
        description="Read the contents of a file at the given path.",
        category="filesystem",
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative file path.",
                },
            },
            "required": ["path"],
        },
    ),
    "write_file": ToolMeta(
        name="write_file",
        description="Write content to a file, creating it if it does not exist.",
        category="filesystem",
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative file path.",
                },
                "content": {
                    "type": "string",
                    "description": "Content to write.",
                },
            },
            "required": ["path", "content"],
        },
    ),
    "list_directory": ToolMeta(
        name="list_directory",
        description="List files and directories at the given path.",
        category="filesystem",
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list.",
                    "default": ".",
                },
            },
        },
    ),
    "delete_file": ToolMeta(
        name="delete_file",
        description="Delete a file at the given path.",
        category="filesystem",
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path of the file to delete.",
                },
            },
            "required": ["path"],
        },
    ),
    # ── web ───────────────────────────────────────────────────────────────
    "fetch_url": ToolMeta(
        name="fetch_url",
        description="Fetch the contents of a URL via HTTP GET.",
        category="web",
        input_schema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch.",
                },
                "headers": {
                    "type": "object",
                    "description": "Optional HTTP headers.",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    ),
    "search_web": ToolMeta(
        name="search_web",
        description="Search the web and return a list of results.",
        category="web",
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string.",
                },
                "num_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return.",
                    "default": 10,
                },
            },
            "required": ["query"],
        },
    ),
    "screenshot": ToolMeta(
        name="screenshot",
        description="Take a screenshot of a web page and return it as base64-encoded PNG.",
        category="web",
        input_schema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL of the page to screenshot.",
                },
                "width": {
                    "type": "integer",
                    "description": "Viewport width in pixels.",
                    "default": 1280,
                },
                "height": {
                    "type": "integer",
                    "description": "Viewport height in pixels.",
                    "default": 720,
                },
            },
            "required": ["url"],
        },
    ),
    # ── exec ──────────────────────────────────────────────────────────────
    "run_command": ToolMeta(
        name="run_command",
        description="Execute a shell command and return stdout/stderr.",
        category="exec",
        input_schema={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds.",
                    "default": 30,
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory.",
                },
            },
            "required": ["command"],
        },
    ),
    "run_python": ToolMeta(
        name="run_python",
        description="Execute a Python script and return its output.",
        category="exec",
        input_schema={
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python source code to execute.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds.",
                    "default": 30,
                },
            },
            "required": ["code"],
        },
    ),
    # ── secrets ───────────────────────────────────────────────────────────
    "get_env_var": ToolMeta(
        name="get_env_var",
        description="Read the value of an environment variable.",
        category="secrets",
        input_schema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the environment variable.",
                },
            },
            "required": ["name"],
        },
    ),
    "read_secret": ToolMeta(
        name="read_secret",
        description="Read a secret from the system secret store.",
        category="secrets",
        input_schema={
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Secret key identifier.",
                },
                "store": {
                    "type": "string",
                    "description": "Secret store name.",
                    "default": "default",
                },
            },
            "required": ["key"],
        },
    ),
    "list_secrets": ToolMeta(
        name="list_secrets",
        description="List available secret keys in the secret store.",
        category="secrets",
        input_schema={
            "type": "object",
            "properties": {
                "store": {
                    "type": "string",
                    "description": "Secret store name.",
                    "default": "default",
                },
                "prefix": {
                    "type": "string",
                    "description": "Optional key prefix filter.",
                },
            },
        },
    ),
    "get_api_key": ToolMeta(
        name="get_api_key",
        description="Retrieve an API key by service name.",
        category="secrets",
        input_schema={
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name (e.g. 'openai', 'stripe').",
                },
            },
            "required": ["service"],
        },
    ),
}


def get_category(tool_name: str) -> str:
    """Return the category for *tool_name*, or ``'unknown'``."""
    meta = TOOL_REGISTRY.get(tool_name)
    return meta.category if meta else "unknown"


MAX_DISTINCT_AGENT_LABELS: int = 256
_seen_agent_labels: set[str] = set()


def metric_tool_label(tool_name: str) -> str:
    """Return a bounded Prometheus label for *tool_name* (known tool or ``'other'``)."""
    return tool_name if tool_name in TOOL_REGISTRY else "other"


def span_tool_name(tool_name: str) -> str:
    """Return a fixed-vocabulary span operation name for *tool_name*."""
    return f"tool.{tool_name}" if tool_name in TOOL_REGISTRY else "tool.unknown"


def bounded_agent_label(agent_id: str) -> str:
    """Cap distinct ``agent_id`` metric label values per process to prevent cardinality DoS."""
    normalized = (agent_id or "unknown")[:64]
    if normalized in _seen_agent_labels:
        return normalized
    if len(_seen_agent_labels) < MAX_DISTINCT_AGENT_LABELS:
        _seen_agent_labels.add(normalized)
        return normalized
    return "other"


def reset_agent_label_budget() -> None:
    """Clear the seen ``agent_id`` label set (used by unit tests)."""
    _seen_agent_labels.clear()
