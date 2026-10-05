"""Pure protocol-level detections for MCP-native traffic (D1-D6).

Takes plain JSON-RPC dicts, returns flags, span attributes and a span name.
No OTel, no logging, no I/O: callers wire the findings into spans and metrics.
"""

from __future__ import annotations

import json
import re
import typing
from dataclasses import dataclass, field

import mcp.types as _types

MAX_ATTR_LEN: int = 256

PROTOCOL_FLAGS: frozenset[str] = frozenset(
    {
        "unknown_method",
        "lifecycle_violation",
        "feature_enumeration",
        "protocol_version_anomaly",
        "hidden_unicode",
        "ansi_escape",
    }
)

MESSAGE_KINDS: frozenset[str] = frozenset(
    {"request", "notification", "response", "error", "unknown"}
)


def _build_known_methods() -> frozenset[str]:
    methods: set[str] = set()
    for union in (_types.ClientRequest, _types.ClientNotification):
        for cls in typing.get_args(union.model_fields["root"].annotation):
            methods.update(typing.get_args(cls.model_fields["method"].annotation))
    return frozenset(methods)


KNOWN_METHODS: frozenset[str] = _build_known_methods()
KNOWN_PROTOCOL_VERSIONS: frozenset[str] = frozenset({"2024-11-05", "2025-03-26", "2025-06-18"})
FEATURE_METHODS: frozenset[str] = frozenset(
    {
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "completion/complete",
        "logging/setLevel",
    }
)

_MAX_DEPTH = 32
_MAX_STRINGS = 10_000
_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FLAG_EMOJI_BASE = "\U0001f3f4"
_OTHER_INVISIBLE = frozenset(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
)
# Fast pre-filter: only strings matching this need the per-character pass.
_INTERESTING_RE = re.compile(
    "[\U000e0000-\U000e007f\x1b\x9b\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]"
)


def truncate(value: object, limit: int = MAX_ATTR_LEN) -> str:
    """str(value), capped at `limit` chars with a suffix recording the original length."""
    try:
        text = str(value)
    except Exception:  # hostile __str__ or recursion-depth blowups
        text = f"<unprintable {type(value).__name__}>"
    if len(text) > limit:
        return f"{text[:limit]}...[truncated {len(text)}]"
    return text


def message_kind(msg: dict) -> str:
    """Classify a JSON-RPC message. id=None is treated as absent."""
    if not isinstance(msg, dict):
        return "unknown"
    if "method" in msg:
        return "request" if msg.get("id") is not None else "notification"
    if "result" in msg:
        return "response"
    if "error" in msg:
        return "error"
    return "unknown"


@dataclass
class ProtocolFindings:
    flags: list[str] = field(default_factory=list)
    attributes: dict[str, str | int] = field(default_factory=dict)
    span_name: str = "mcp.unknown"

    def add_flag(self, flag: str) -> None:
        if flag not in self.flags:
            self.flags.append(flag)


@dataclass
class _ScanResult:
    unicode_path: str | None = None
    tag_count: int = 0
    decoded: list[str] = field(default_factory=list)
    other_invisible: int = 0
    ansi_path: str | None = None
    ansi_kinds: set[str] = field(default_factory=set)
    truncated: bool = False


def _scan_string(text: str, path: str, res: _ScanResult) -> None:
    if not _INTERESTING_RE.search(text):
        return
    n = len(text)
    i = 0
    while i < n:
        cp = ord(text[i])
        if 0xE0000 <= cp <= 0xE007F:
            j = i
            while j < n and 0xE0000 <= ord(text[j]) <= 0xE007F:
                j += 1
            run = text[i:j]
            benign = (
                i > 0
                and text[i - 1] == _FLAG_EMOJI_BASE
                and len(run) >= 2
                and ord(run[-1]) == 0xE007F
                and all(0xE0020 <= ord(c) <= 0xE007E for c in run[:-1])
            )
            if not benign:
                if res.unicode_path is None:
                    res.unicode_path = path
                res.tag_count += len(run)
                res.decoded.extend(chr(ord(c) - 0xE0000) for c in run)
            i = j
            continue
        if cp in _OTHER_INVISIBLE:
            res.other_invisible += 1
        elif cp == 0x1B:
            if res.ansi_path is None:
                res.ansi_path = path
            nxt = text[i + 1] if i + 1 < n else ""
            res.ansi_kinds.add("csi" if nxt == "[" else "osc" if nxt == "]" else "other")
        elif cp == 0x9B:
            if res.ansi_path is None:
                res.ansi_path = path
            res.ansi_kinds.add("csi")
        i += 1


def _child_path(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _walk(msg: dict) -> _ScanResult:
    """Iterative, bounded walk over keys and values (document order)."""
    res = _ScanResult()
    visited = 0
    stack: list[tuple[object, str, int]] = [(msg, "", 0)]
    while stack:
        obj, path, depth = stack.pop()
        if isinstance(obj, str):
            if visited >= _MAX_STRINGS:
                res.truncated = True
                break
            visited += 1
            _scan_string(obj, path, res)
        elif isinstance(obj, dict):
            if depth >= _MAX_DEPTH:
                res.truncated = True
                continue
            items = list(obj.items())
            children: list[tuple[object, str, int]] = []
            for key, val in items:
                if isinstance(key, str):
                    children.append((key, _child_path(path, key), depth + 1))
                    kpath = _child_path(path, key)
                else:
                    kpath = _child_path(path, str(key))
                children.append((val, kpath, depth + 1))
            stack.extend(reversed(children))
        elif isinstance(obj, (list, tuple)):
            if depth >= _MAX_DEPTH:
                res.truncated = True
                continue
            stack.extend(reversed([(v, f"{path}[{idx}]", depth + 1) for idx, v in enumerate(obj)]))
    return res


class ConnectionProtocolState:
    """Per-connection ordering state. One instance per connection."""

    def __init__(self) -> None:
        self._initialize_seen = False
        self._initialized_seen = False
        self._feature_methods: set[str] = set()
        self._feature_flagged = False

    def inspect(self, msg: dict) -> ProtocolFindings:
        findings = ProtocolFindings()
        try:
            self._inspect(msg, findings)
        except Exception as exc:
            findings = ProtocolFindings(
                flags=[],
                attributes={"mcp.inspect.error": truncate(type(exc).__name__)},
                span_name=findings.span_name,
            )
        return findings

    def _inspect(self, msg: dict, out: ProtocolFindings) -> None:
        kind = message_kind(msg)
        attrs = out.attributes
        attrs["mcp.message_kind"] = kind
        has_method = isinstance(msg, dict) and "method" in msg
        method = msg.get("method") if has_method else None
        method_str = method if isinstance(method, str) else None

        if has_method:
            attrs["mcp.method.raw"] = truncate(method if method_str is not None else repr(method))
        if isinstance(msg, dict) and msg.get("id") is not None:
            attrs["mcp.jsonrpc.id"] = truncate(msg["id"])

        if has_method:
            out.span_name = (
                f"mcp.{method_str}" if method_str in KNOWN_METHODS else "mcp.unknown_method"
            )
        else:
            out.span_name = f"mcp.{kind}"

        # D1
        if has_method and method_str not in KNOWN_METHODS:
            out.add_flag("unknown_method")

        if kind == "request":
            self._lifecycle(method_str, out)
            self._features(method_str, out)
            if method_str == "initialize":
                self._initialize(msg, out)
        elif kind == "notification" and method_str == "notifications/initialized":
            self._initialized_seen = True

        self._scan(msg, out)

    def _lifecycle(self, method: str | None, out: ProtocolFindings) -> None:
        if method not in ("initialize", "ping") and not self._initialize_seen:
            out.add_flag("lifecycle_violation")
            out.attributes["mcp.lifecycle.reason"] = "no_initialize"
        elif method == "tools/call" and self._initialize_seen and not self._initialized_seen:
            out.add_flag("lifecycle_violation")
            out.attributes["mcp.lifecycle.reason"] = "no_initialized_notification"
        if method == "initialize":
            self._initialize_seen = True

    def _features(self, method: str | None, out: ProtocolFindings) -> None:
        if method in FEATURE_METHODS:
            self._feature_methods.add(method)
            if len(self._feature_methods) >= 2 and not self._feature_flagged:
                self._feature_flagged = True
                out.add_flag("feature_enumeration")
                out.attributes["mcp.feature_methods"] = truncate(
                    ",".join(sorted(self._feature_methods))
                )

    @staticmethod
    def _initialize(msg: dict, out: ProtocolFindings) -> None:
        params = msg.get("params")
        if not isinstance(params, dict):
            params = {}
        attrs = out.attributes
        version = params.get("protocolVersion")
        anomalous = (
            not isinstance(version, str)
            or len(version) > 32
            or not _VERSION_RE.match(version)
            or version not in KNOWN_PROTOCOL_VERSIONS
        )
        if "protocolVersion" in params:
            attrs["mcp.client.protocol_version"] = truncate(version)
        if anomalous:
            out.add_flag("protocol_version_anomaly")
        caps = params.get("capabilities")
        if isinstance(caps, dict):
            attrs["mcp.client.capabilities"] = truncate(",".join(sorted(str(k) for k in caps)))
            try:
                attrs["mcp.client.capabilities_json"] = truncate(
                    json.dumps(caps, sort_keys=True, default=str)
                )
            except Exception:
                attrs["mcp.client.capabilities_json"] = "<unserializable>"
        info = params.get("clientInfo")
        if isinstance(info, dict):
            attrs["mcp.client.info_extra_keys"] = sum(
                1 for k in info if k not in ("name", "version")
            )

    @staticmethod
    def _scan(msg: dict, out: ProtocolFindings) -> None:
        if not isinstance(msg, dict):
            return
        res = _walk(msg)
        attrs = out.attributes
        if res.unicode_path is not None:
            out.add_flag("hidden_unicode")
            attrs["mcp.unicode.field_path"] = truncate(res.unicode_path)
            attrs["mcp.unicode.tag_count"] = res.tag_count
            attrs["mcp.unicode.decoded"] = truncate("".join(res.decoded))
        if res.other_invisible > 0:
            attrs["mcp.unicode.other_invisible_count"] = res.other_invisible
        if res.ansi_path is not None:
            out.add_flag("ansi_escape")
            attrs["mcp.ansi.field_path"] = truncate(res.ansi_path)
            attrs["mcp.ansi.sequence_kinds"] = ",".join(sorted(res.ansi_kinds))
        if res.truncated:
            attrs["mcp.scan.truncated"] = 1
