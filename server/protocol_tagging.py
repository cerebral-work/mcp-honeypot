"""Pure protocol-level detections for MCP-native traffic (D1-D6).

Takes plain JSON-RPC dicts, returns flags, span attributes and a span name.
No OTel, no logging, no I/O: callers wire the findings into spans and metrics.
"""

from __future__ import annotations

import itertools
import json
import re
import reprlib
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
_MAX_NODES = 10_000
_MAX_CAPS = 64
_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FLAG_EMOJI_BASE = "\U0001f3f4"
_INVISIBLE_CHARS = tuple(
    chr(c)
    for c in [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
)
# Fast pre-filter: only strings matching this need further work.
_INTERESTING_RE = re.compile(
    "[\U000e0000-\U000e007f\x1b\x9b\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]"
)
_ANSI_RE = re.compile("[\x1b\x9b]")
# ESC followed by anything but "[", "]" or "\\" (ST), or at end of string.
_ESC_OTHER_RE = re.compile("\x1b(?![\\[\\]\\\\])")
_TAG_RUN_RE = re.compile("[\U000e0000-\U000e007f]+")
_TAG_CHARS = tuple(chr(0xE0000 + i) for i in range(128))
# The three RGI subdivision flag sequences: base + tag letters + cancel tag.
_FLAG_SEQUENCE_RE = re.compile(
    _FLAG_EMOJI_BASE
    + "(?:"
    + "|".join(
        "".join(chr(0xE0000 + ord(c)) for c in code) + chr(0xE007F)
        for code in ("gbeng", "gbsct", "gbwls")
    )
    + ")(?![\U000e0000-\U000e007f])"
)


class _BoundedRepr(reprlib.Repr):
    """reprlib.Repr that never sorts or walks a whole container."""

    def __init__(self) -> None:
        super().__init__()
        self.maxlevel = 2
        self.maxlist = self.maxtuple = self.maxset = self.maxfrozenset = 6
        self.maxdict = 6
        self.maxstring = 64
        self.maxother = 64
        self.maxlong = 40

    def repr_dict(self, x, level):  # type: ignore[no-untyped-def]
        if not x:
            return "{}"
        if level <= 0:
            return "{...}"
        parts = [
            f"{self.repr1(k, level - 1)}: {self.repr1(v, level - 1)}"
            for k, v in itertools.islice(x.items(), self.maxdict)
        ]
        tail = ", ..." if len(x) > self.maxdict else ""
        return "{" + ", ".join(parts) + tail + "}"

    def _repr_unordered(self, x, level, left, right):  # type: ignore[no-untyped-def]
        if not x:
            return f"{left}{right}"
        if level <= 0:
            return f"{left}...{right}"
        parts = [self.repr1(e, level - 1) for e in itertools.islice(x, self.maxset)]
        tail = ", ..." if len(x) > self.maxset else ""
        return left + ", ".join(parts) + tail + right

    def repr_set(self, x, level):  # type: ignore[no-untyped-def]
        return self._repr_unordered(x, level, "{", "}")

    def repr_frozenset(self, x, level):  # type: ignore[no-untyped-def]
        return self._repr_unordered(x, level, "frozenset({", "})")


_REPR = _BoundedRepr()


def truncate(value: object, limit: int = MAX_ATTR_LEN) -> str:
    """Bounded text of `value`, capped at `limit` chars with the original length recorded.

    Cost is O(limit) regardless of input size. Output is always UTF-8 encodable
    (lone surrogates become backslash escapes).
    """
    if isinstance(value, str):
        text = value[: limit + 1]
        total = len(value)
    else:
        try:
            text = _REPR.repr(value)
        except Exception:  # hostile __repr__, huge ints (ValueError), recursion
            text = f"<unprintable {type(value).__name__}>"
        total = len(text)
    if total > limit:
        text = f"{text[:limit]}...[truncated {total}]"
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


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
    decoded: str = ""
    other_invisible: int = 0
    ansi_path: str | None = None
    ansi_kinds: set[str] = field(default_factory=set)
    truncated: bool = False


def _scan_string(text: str, path: str, res: _ScanResult) -> None:
    if not _INTERESTING_RE.search(text):
        return
    # Tags: drop the benign flag sequences, then everything left is hostile.
    rest = _FLAG_SEQUENCE_RE.sub("", text)
    tag_count = sum(rest.count(c) for c in _TAG_CHARS)
    if tag_count:
        if res.unicode_path is None:
            res.unicode_path = path
        res.tag_count += tag_count
        room = MAX_ATTR_LEN + 1 - len(res.decoded)
        for run in _TAG_RUN_RE.finditer(rest):
            if room <= 0:
                break
            chunk = run.group()[:room]
            res.decoded += "".join(chr(ord(c) - 0xE0000) for c in chunk)
            room -= len(chunk)
    res.other_invisible += sum(text.count(c) for c in _INVISIBLE_CHARS)
    if _ANSI_RE.search(text):
        if res.ansi_path is None:
            res.ansi_path = path
        if "\x9b" in text or "\x1b[" in text:
            res.ansi_kinds.add("csi")
        if "\x1b]" in text:
            res.ansi_kinds.add("osc")
        if _ESC_OTHER_RE.search(text):
            res.ansi_kinds.add("other")


def _child_path(path: str, key: str) -> str:
    key = key[:MAX_ATTR_LEN]
    return f"{path}.{key}" if path else key


def _walk(msg: dict) -> _ScanResult:
    """Iterative walk over keys and values (document order), bounded by node count and depth.

    Every container, key and scalar is a node. The stack never holds more entries
    than the remaining node budget, so cost stays O(_MAX_NODES) for any input.
    """
    res = _ScanResult()
    visited = 0
    stack: list[tuple[object, str, int]] = [(msg, "", 0)]
    while stack:
        obj, path, depth = stack.pop()
        visited += 1
        if isinstance(obj, str):
            _scan_string(obj, path, res)
        elif isinstance(obj, (dict, list, tuple)):
            if depth >= _MAX_DEPTH:
                res.truncated = True
                continue
            room = _MAX_NODES - visited - len(stack)
            children: list[tuple[object, str, int]] = []
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if room - len(children) < 2:
                        res.truncated = True
                        break
                    kpath = _child_path(path, key if isinstance(key, str) else truncate(key, 64))
                    if isinstance(key, str):
                        children.append((key, kpath + "#key", depth + 1))
                    else:
                        children.append((None, kpath + "#key", depth + 1))
                    children.append((val, kpath, depth + 1))
            else:
                for idx, val in enumerate(obj):
                    if len(children) >= room:
                        res.truncated = True
                        break
                    children.append((val, f"{path}[{idx}]", depth + 1))
            stack.extend(reversed(children))
    return res


def _shrink(obj: object, depth: int = 4) -> object:
    """Bounded JSON-ish copy: at most 16 items per container, depth 4, strings capped."""
    if isinstance(obj, str):
        return obj[:MAX_ATTR_LEN]
    if depth <= 0:
        return truncate(obj, 32) if isinstance(obj, (dict, list, tuple, set, frozenset)) else obj
    if isinstance(obj, dict):
        return {
            (k if isinstance(k, str) else truncate(k, 64))[:MAX_ATTR_LEN]: _shrink(v, depth - 1)
            for k, v in itertools.islice(obj.items(), 16)
        }
    if isinstance(obj, (list, tuple)):
        return [_shrink(v, depth - 1) for v in itertools.islice(obj, 16)]
    return obj


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
            attrs["mcp.method.raw"] = truncate(method)
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
        elif (
            kind == "notification"
            and method_str == "notifications/initialized"
            and self._initialize_seen
        ):
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
            attrs["mcp.client.capabilities_count"] = len(caps)
            subset = {k: caps[k] for k in itertools.islice(caps, _MAX_CAPS)}
            attrs["mcp.client.capabilities"] = truncate(
                ",".join(sorted(k if isinstance(k, str) else truncate(k, 64) for k in subset))
            )
            try:
                attrs["mcp.client.capabilities_json"] = truncate(
                    json.dumps(_shrink(subset), sort_keys=True, default=str)
                )
            except Exception:
                attrs["mcp.client.capabilities_json"] = "<unserializable>"
        info = params.get("clientInfo")
        if isinstance(info, dict):
            attrs["mcp.client.info_extra_keys"] = len(info) - sum(
                1 for k in ("name", "version") if k in info
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
            decoded = res.decoded[:MAX_ATTR_LEN]
            if res.tag_count > MAX_ATTR_LEN:
                decoded += f"...[truncated {res.tag_count}]"
            attrs["mcp.unicode.decoded"] = decoded
        if res.other_invisible > 0:
            attrs["mcp.unicode.other_invisible_count"] = res.other_invisible
        if res.ansi_path is not None:
            out.add_flag("ansi_escape")
            attrs["mcp.ansi.field_path"] = truncate(res.ansi_path)
            attrs["mcp.ansi.sequence_kinds"] = ",".join(sorted(res.ansi_kinds or {"other"}))
        if res.truncated:
            attrs["mcp.scan.truncated"] = 1
