"""Unit tests for server.protocol_tagging (detections D1-D6)."""

from __future__ import annotations

import sys
import time
import typing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

import mcp.types as types  # noqa: E402
from protocol_tagging import (  # noqa: E402
    FEATURE_METHODS,
    KNOWN_METHODS,
    MAX_ATTR_LEN,
    MESSAGE_KINDS,
    PROTOCOL_FLAGS,
    ConnectionProtocolState,
    message_kind,
    truncate,
)

ENGLAND = "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"


def req(method, id_=1, params=None):
    msg = {"jsonrpc": "2.0", "method": method, "id": id_}
    if params is not None:
        msg["params"] = params
    return msg


def note(method, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def init(version="2025-06-18", **extra):
    params = {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "c"}}
    params.update(extra)
    return req("initialize", params=params)


def fresh_initialized():
    st = ConnectionProtocolState()
    st.inspect(init())
    st.inspect(note("notifications/initialized"))
    return st


def one(msg):
    return fresh_initialized().inspect(msg)


class TestHelpers:
    def test_truncate_short_unchanged(self):
        assert truncate("abc") == "abc"

    def test_truncate_long_has_suffix(self):
        out = truncate("x" * 300)
        assert out == "x" * MAX_ATTR_LEN + "...[truncated 300]"

    def test_truncate_non_str(self):
        assert truncate(12) == "12"

    def test_message_kinds(self):
        assert message_kind({"method": "a", "id": 1}) == "request"
        assert message_kind({"method": "a"}) == "notification"
        assert message_kind({"method": "a", "id": None}) == "notification"
        assert message_kind({"id": 1, "result": {}}) == "response"
        assert message_kind({"id": 1, "error": {}}) == "error"
        assert message_kind({"foo": 1}) == "unknown"
        assert message_kind({"foo": 1}) in MESSAGE_KINDS


class TestD1UnknownMethod:
    def test_known_methods_parity_with_sdk(self):
        expected = set()
        for union in (types.ClientRequest, types.ClientNotification):
            for cls in typing.get_args(union.model_fields["root"].annotation):
                expected.update(typing.get_args(cls.model_fields["method"].annotation))
        assert expected
        assert set(KNOWN_METHODS) == expected
        for m in ("initialize", "ping", "tools/list", "tools/call", "notifications/initialized"):
            assert m in KNOWN_METHODS

    def test_tools_list_clean(self):
        f = one(req("tools/list"))
        assert f.flags == []
        assert f.span_name == "mcp.tools/list"

    def test_unknown_flagged_with_raw(self):
        f = one(req("foo/bar"))
        assert f.flags == ["unknown_method"]
        assert f.attributes["mcp.method.raw"] == "foo/bar"
        assert f.span_name == "mcp.unknown_method"

    def test_non_string_method_unknown(self):
        f = one({"method": ["x"], "id": 1})
        assert "unknown_method" in f.flags
        assert f.attributes["mcp.method.raw"] == "['x']"
        assert f.span_name == "mcp.unknown_method"

    def test_initialized_notification_not_flagged(self):
        f = ConnectionProtocolState().inspect(note("notifications/initialized"))
        assert f.flags == []
        assert f.attributes["mcp.message_kind"] == "notification"

    def test_long_raw_method_truncated(self):
        f = one(req("a" * 400))
        assert f.attributes["mcp.method.raw"].endswith("...[truncated 400]")


class TestSpanNames:
    def test_response(self):
        f = ConnectionProtocolState().inspect({"id": 1, "result": {}})
        assert f.span_name == "mcp.response"
        assert f.flags == []

    def test_error(self):
        f = ConnectionProtocolState().inspect({"id": 1, "error": {"code": -1}})
        assert f.span_name == "mcp.error"

    def test_unknown_kind(self):
        f = ConnectionProtocolState().inspect({"hello": "x"})
        assert f.span_name == "mcp.unknown"
        assert f.attributes["mcp.message_kind"] == "unknown"

    def test_id_attribute(self):
        f = one(req("tools/list", id_=77))
        assert f.attributes["mcp.jsonrpc.id"] == "77"
        g = ConnectionProtocolState().inspect(note("notifications/initialized"))
        assert "mcp.jsonrpc.id" not in g.attributes


class TestD2Lifecycle:
    def test_clean_sequence(self):
        st = ConnectionProtocolState()
        for m in (init(), note("notifications/initialized"), req("tools/call", 3)):
            assert st.inspect(m).flags == []

    def test_call_first(self):
        f = ConnectionProtocolState().inspect(req("tools/call"))
        assert f.flags == ["lifecycle_violation"]
        assert f.attributes["mcp.lifecycle.reason"] == "no_initialize"

    def test_initialize_then_call(self):
        st = ConnectionProtocolState()
        st.inspect(init())
        f = st.inspect(req("tools/call", 2))
        assert f.flags == ["lifecycle_violation"]
        assert f.attributes["mcp.lifecycle.reason"] == "no_initialized_notification"

    def test_ping_first_clean(self):
        f = ConnectionProtocolState().inspect(req("ping"))
        assert f.flags == []

    def test_each_violation_flagged(self):
        st = ConnectionProtocolState()
        assert st.inspect(req("tools/list", 1)).flags == ["lifecycle_violation"]
        assert st.inspect(req("tools/list", 2)).flags == ["lifecycle_violation"]

    def test_notifications_never_violate(self):
        f = ConnectionProtocolState().inspect(note("notifications/cancelled"))
        assert "lifecycle_violation" not in f.flags

    def test_tools_list_after_initialize_without_initialized_clean(self):
        st = ConnectionProtocolState()
        st.inspect(init())
        assert st.inspect(req("tools/list", 2)).flags == []


class TestD3FeatureEnumeration:
    def test_one_method_clean(self):
        assert one(req("prompts/list")).flags == []

    def test_fires_once_at_second_distinct(self):
        st = fresh_initialized()
        assert st.inspect(req("prompts/list", 2)).flags == []
        f = st.inspect(req("resources/list", 3))
        assert f.flags == ["feature_enumeration"]
        assert f.attributes["mcp.feature_methods"] == "prompts/list,resources/list"
        g = st.inspect(req("completion/complete", 4))
        assert "feature_enumeration" not in g.flags
        assert "mcp.feature_methods" not in g.attributes

    def test_repeated_same_method_never_fires(self):
        st = fresh_initialized()
        for i in range(2, 8):
            assert st.inspect(req("prompts/list", i)).flags == []

    def test_repeated_tools_list_never_fires(self):
        st = fresh_initialized()
        for i in range(2, 8):
            assert st.inspect(req("tools/list", i)).flags == []

    def test_tools_list_does_not_count(self):
        st = fresh_initialized()
        st.inspect(req("tools/list", 2))
        assert st.inspect(req("prompts/list", 3)).flags == []

    def test_state_is_per_connection(self):
        a, b = fresh_initialized(), fresh_initialized()
        a.inspect(req("prompts/list", 2))
        assert b.inspect(req("resources/list", 2)).flags == []

    def test_feature_methods_constant(self):
        assert "tools/list" not in FEATURE_METHODS
        assert len(FEATURE_METHODS) == 5


class TestD4ProtocolVersion:
    def test_known_clean(self):
        f = ConnectionProtocolState().inspect(init("2025-06-18"))
        assert f.flags == []
        assert f.attributes["mcp.client.protocol_version"] == "2025-06-18"

    def test_future_date_flagged(self):
        f = ConnectionProtocolState().inspect(init("2099-01-01"))
        assert f.flags == ["protocol_version_anomaly"]
        assert f.attributes["mcp.client.protocol_version"] == "2099-01-01"

    def test_non_string_flagged(self):
        f = ConnectionProtocolState().inspect(init({"x": 1}))
        assert f.flags == ["protocol_version_anomaly"]

    def test_100_char_string_flagged_and_kept_under_cap(self):
        f = ConnectionProtocolState().inspect(init("9" * 100))
        assert f.flags == ["protocol_version_anomaly"]
        assert f.attributes["mcp.client.protocol_version"] == "9" * 100

    def test_oversized_string_flagged_and_truncated(self):
        f = ConnectionProtocolState().inspect(init("9" * 300))
        assert f.flags == ["protocol_version_anomaly"]
        assert (
            f.attributes["mcp.client.protocol_version"] == "9" * MAX_ATTR_LEN + "...[truncated 300]"
        )

    def test_bad_format_flagged(self):
        f = ConnectionProtocolState().inspect(init("latest"))
        assert f.flags == ["protocol_version_anomaly"]

    def test_missing_version_flagged_no_attr(self):
        f = ConnectionProtocolState().inspect(req("initialize", params={"capabilities": {}}))
        assert f.flags == ["protocol_version_anomaly"]
        assert "mcp.client.protocol_version" not in f.attributes

    def test_missing_params_flagged(self):
        f = ConnectionProtocolState().inspect(req("initialize"))
        assert f.flags == ["protocol_version_anomaly"]

    def test_missing_capabilities_alone_clean(self):
        f = ConnectionProtocolState().inspect(
            req("initialize", params={"protocolVersion": "2025-03-26"})
        )
        assert f.flags == []
        assert "mcp.client.capabilities" not in f.attributes

    def test_capabilities_recorded(self):
        f = ConnectionProtocolState().inspect(
            init(capabilities={"sampling": {}, "roots": {"listChanged": True}})
        )
        assert f.attributes["mcp.client.capabilities"] == "roots,sampling"
        assert f.attributes["mcp.client.capabilities_json"] == (
            '{"roots": {"listChanged": true}, "sampling": {}}'
        )

    def test_client_info_extra_keys(self):
        f = ConnectionProtocolState().inspect(
            init(clientInfo={"name": "a", "version": "1", "x": 1, "y": 2})
        )
        assert f.attributes["mcp.client.info_extra_keys"] == 2

    def test_non_initialize_not_checked(self):
        f = one(req("tools/list", params={"protocolVersion": "bogus"}))
        assert "protocol_version_anomaly" not in f.flags


class TestD5HiddenUnicode:
    def test_tag_char_flagged_decoded(self):
        f = one(req("tools/call", params={"arguments": {"q": "hi" + chr(0xE0041)}}))
        assert "hidden_unicode" in f.flags
        assert f.attributes["mcp.unicode.decoded"] == "A"
        assert f.attributes["mcp.unicode.tag_count"] == 1
        assert f.attributes["mcp.unicode.field_path"] == "params.arguments.q"

    def test_england_flag_clean(self):
        f = one(req("tools/call", params={"arguments": {"q": "x" + ENGLAND}}))
        assert "hidden_unicode" not in f.flags
        assert "mcp.unicode.tag_count" not in f.attributes

    def test_flag_run_with_trailing_extra_tags_flagged(self):
        f = one(req("tools/call", params={"arguments": {"q": ENGLAND + chr(0xE0041)}}))
        assert "hidden_unicode" in f.flags

    def test_tag_run_without_base_flagged(self):
        s = "\U000e0067\U000e007f"
        f = one(req("tools/call", params={"arguments": {"q": s}}))
        assert "hidden_unicode" in f.flags
        assert f.attributes["mcp.unicode.tag_count"] == 2

    def test_nested_path(self):
        f = one(req("tools/call", params={"arguments": {"a": {"b": ["ok", "x" + chr(0xE0042)]}}}))
        assert f.attributes["mcp.unicode.field_path"] == "params.arguments.a.b[1]"

    def test_nested_index_zero(self):
        f = one(req("tools/call", params={"arguments": {"a": {"b": [chr(0xE0042)]}}}))
        assert f.attributes["mcp.unicode.field_path"] == "params.arguments.a.b[0]"

    def test_key_scanned(self):
        f = one(req("tools/call", params={"arguments": {"k" + chr(0xE0041): 1}}))
        assert "hidden_unicode" in f.flags
        assert f.attributes["mcp.unicode.field_path"].startswith("params.arguments.k")

    def test_clean_ascii(self):
        f = one(req("tools/call", params={"arguments": {"q": "hello"}}))
        assert "hidden_unicode" not in f.flags
        assert "ansi_escape" not in f.flags

    def test_counts_all_and_decoded_joined(self):
        s = chr(0xE0048) + chr(0xE0069)
        f = one(req("tools/call", params={"arguments": {"a": s, "b": chr(0xE0021)}}))
        assert f.attributes["mcp.unicode.tag_count"] == 3
        assert f.attributes["mcp.unicode.decoded"] == "Hi!"

    def test_decoded_truncated(self):
        s = "".join(chr(0xE0041) for _ in range(400))
        f = one(req("tools/call", params={"arguments": {"a": s}}))
        assert f.attributes["mcp.unicode.decoded"].endswith("...[truncated 400]")

    def test_zero_width_counted_not_flagged(self):
        s = "a\u200bb\u200c\u202ec\u2066d\ufeff"
        f = one(req("tools/call", params={"arguments": {"q": s}}))
        assert f.flags == []
        assert f.attributes["mcp.unicode.other_invisible_count"] == 5

    def test_no_other_invisible_attr_when_zero(self):
        f = one(req("tools/call", params={"arguments": {"q": "plain"}}))
        assert "mcp.unicode.other_invisible_count" not in f.attributes


class TestD6Ansi:
    def kinds(self, s):
        f = one(req("tools/call", params={"arguments": {"q": s}}))
        return f

    def test_csi(self):
        f = self.kinds("\x1b[31mred")
        assert "ansi_escape" in f.flags
        assert f.attributes["mcp.ansi.sequence_kinds"] == "csi"
        assert f.attributes["mcp.ansi.field_path"] == "params.arguments.q"

    def test_osc_8_hyperlink(self):
        f = self.kinds("\x1b]8;;http://x\x1b\\t")
        assert f.attributes["mcp.ansi.sequence_kinds"] == "osc"

    def test_osc_only(self):
        f = self.kinds("\x1b]0;title")
        assert f.attributes["mcp.ansi.sequence_kinds"] == "osc"

    def test_c1_csi(self):
        f = self.kinds("a\x9b31m")
        assert "ansi_escape" in f.flags
        assert f.attributes["mcp.ansi.sequence_kinds"] == "csi"

    def test_other(self):
        f = self.kinds("a\x1bc")
        assert f.attributes["mcp.ansi.sequence_kinds"] == "other"

    def test_trailing_esc_other(self):
        f = self.kinds("a\x1b")
        assert f.attributes["mcp.ansi.sequence_kinds"] == "other"

    def test_mixed_sorted(self):
        f = self.kinds("\x1b[1m\x1b]8;;u\x1b\\")
        assert f.attributes["mcp.ansi.sequence_kinds"] == "csi,osc"

    def test_literal_backslash_x1b_not_flagged(self):
        f = self.kinds("\\x1b[31m")
        assert len(f.attributes["mcp.message_kind"]) > 0
        assert "ansi_escape" not in f.flags
        assert "mcp.ansi.field_path" not in f.attributes

    def test_ansi_in_key(self):
        f = one(req("tools/call", params={"arguments": {"\x1b[0mk": 1}}))
        assert "ansi_escape" in f.flags


class TestBounds:
    def test_deep_nesting_does_not_raise(self):
        deep: dict = {}
        cur = deep
        for _ in range(10_000):
            cur["a"] = {}
            cur = cur["a"]
        cur["a"] = chr(0xE0041)
        f = one(req("tools/call", params=deep))
        assert f.attributes["mcp.scan.truncated"] == 1
        assert "mcp.inspect.error" not in f.attributes

    def test_deep_list_nesting(self):
        deep: list = []
        cur = deep
        for _ in range(5_000):
            nxt: list = []
            cur.append(nxt)
            cur = nxt
        f = one(req("tools/call", params={"x": deep}))
        assert f.attributes["mcp.scan.truncated"] == 1

    def test_wide_message_bounded(self):
        f = one(req("tools/call", params={"arguments": {"l": ["x"] * 20_000}}))
        assert f.attributes["mcp.scan.truncated"] == 1

    def test_normal_message_not_truncated(self):
        f = one(req("tools/call", params={"arguments": {"q": "x"}}))
        assert "mcp.scan.truncated" not in f.attributes

    def test_hostile_id_does_not_raise(self):
        deep: list = []
        for _ in range(5_000):
            deep = [deep]
        f = one({"method": "tools/list", "id": deep})
        assert "mcp.jsonrpc.id" in f.attributes

    def test_never_raises_on_odd_input(self):
        st = ConnectionProtocolState()
        for m in ({}, {"method": None}, {"method": 5, "id": 1}, {"params": None, "result": 1}):
            f = st.inspect(m)
            assert f.span_name.startswith("mcp.")

    def test_internal_error_reported(self, monkeypatch):
        import protocol_tagging

        def boom(_msg):
            raise ValueError("x")

        monkeypatch.setattr(protocol_tagging, "_walk", boom)
        f = ConnectionProtocolState().inspect(req("tools/list"))
        assert f.flags == []
        assert f.attributes == {"mcp.inspect.error": "ValueError"}


class TestInvariants:
    MESSAGES = [
        req("foo/bar"),
        req("tools/call"),
        init("2099-01-01", capabilities={"a": {}}),
        req("prompts/list", 5),
        req("resources/list", 6),
        req("tools/call", params={"arguments": {"q": "\x1b[1m" + chr(0xE0041) + "\u200b"}}),
        {"id": 1, "result": {}},
        {"id": 1, "error": {}},
        {"x": "y" * 5000},
        req("m" * 1000, id_="i" * 1000),
    ]

    def test_flags_in_vocabulary_no_dupes_and_attrs_bounded(self):
        st = ConnectionProtocolState()
        seen = set()
        for m in self.MESSAGES:
            f = st.inspect(m)
            seen.update(f.flags)
            assert len(f.flags) == len(set(f.flags))
            assert set(f.flags) <= PROTOCOL_FLAGS
            assert f.attributes["mcp.message_kind"] in MESSAGE_KINDS
            for k, v in f.attributes.items():
                assert isinstance(v, (str, int)), k
                if isinstance(v, str):
                    suffix = len(f"...[truncated {10**6}]")
                    assert len(v) <= MAX_ATTR_LEN + suffix, k
        assert {
            "unknown_method",
            "lifecycle_violation",
            "protocol_version_anomaly",
            "feature_enumeration",
            "hidden_unicode",
            "ansi_escape",
        } <= seen

    def test_vocabularies(self):
        flags = {
            "unknown_method",
            "lifecycle_violation",
            "feature_enumeration",
            "protocol_version_anomaly",
            "hidden_unicode",
            "ansi_escape",
        }
        assert flags == PROTOCOL_FLAGS
        assert {"request", "notification", "response", "error", "unknown"} == MESSAGE_KINDS


def tagged(text):
    return "".join(chr(0xE0000 + ord(c)) for c in text)


class TestHardening:
    def test_flag_base_with_arbitrary_tag_payload_flagged(self):
        s = "\U0001f3f4" + tagged("ignore all") + chr(0xE007F)
        f = one(req("tools/call", params={"arguments": {"q": s}}))
        assert "hidden_unicode" in f.flags
        assert f.attributes["mcp.unicode.decoded"].startswith("ignore all")

    def test_all_three_subdivision_flags_benign(self):
        for code in ("gbeng", "gbsct", "gbwls"):
            s = "x\U0001f3f4" + tagged(code) + chr(0xE007F) + "y"
            f = one(req("tools/call", params={"arguments": {"q": s}}))
            assert "hidden_unicode" not in f.flags, code

    def test_other_subdivision_flagged(self):
        s = "\U0001f3f4" + tagged("usca") + chr(0xE007F)
        f = one(req("tools/call", params={"arguments": {"q": s}}))
        assert "hidden_unicode" in f.flags

    def test_depth_33_esc_sets_truncated_attr(self):
        x: dict = {"k": "\x1b[31m"}
        for _ in range(40):
            x = {"a": x}
        f = one(req("tools/call", params=x))
        assert f.attributes["mcp.scan.truncated"] == 1

    def test_10001_node_padding_sets_truncated_attr(self):
        f = one(req("tools/call", params={"a": ["x"] * 10_001}))
        assert f.attributes["mcp.scan.truncated"] == 1

    def test_empty_container_padding_counts_nodes(self):
        f = one(req("tools/call", params={"a": [[]] * 20_000}))
        assert f.attributes["mcp.scan.truncated"] == 1

    def test_truncate_huge_int_and_container(self):
        assert truncate(10**100000) == "<unprintable int>"
        assert len(truncate([1] * 1000)) < 400
        assert len(truncate({str(i): i for i in range(1000)})) < 400

    def test_truncate_lone_surrogate_encodable(self):
        out = truncate("\ud800")
        out.encode("utf-8")
        assert "\\ud800" in out

    def test_capabilities_bounded_and_counted(self):
        caps = {str(i): 1 for i in range(1000)}
        f = ConnectionProtocolState().inspect(init(capabilities=caps))
        assert f.attributes["mcp.client.capabilities_count"] == 1000
        assert isinstance(f.attributes["mcp.client.capabilities_count"], int)

    def test_initialized_before_initialize_does_not_count(self):
        st = ConnectionProtocolState()
        st.inspect(note("notifications/initialized"))
        st.inspect(init())
        f = st.inspect(req("tools/call"))
        assert "lifecycle_violation" in f.flags
        assert f.attributes["mcp.lifecycle.reason"] == "no_initialized_notification"

    def test_osc_string_terminator_not_other(self):
        f = one(req("tools/call", params={"a": "\x1b]8;;http://x\x1b\\t"}))
        assert f.attributes["mcp.ansi.sequence_kinds"] == "osc"

    def test_key_hit_marked(self):
        f = one(req("tools/call", params={"arguments": {"k\x1b[0m": 1}}))
        assert f.attributes["mcp.ansi.field_path"] == "params.arguments.k\x1b[0m#key"
        f = one(req("tools/call", params={"arguments": {"k": "\x1b[0m"}}))
        assert f.attributes["mcp.ansi.field_path"] == "params.arguments.k"

    def test_surrogate_attrs_encodable(self):
        f = one({"id": "\ud800", "method": "\ud800x"})
        for v in f.attributes.values():
            if isinstance(v, str):
                v.encode("utf-8")


class TestPerformance:
    @staticmethod
    def timed(msg):
        st = ConnectionProtocolState()
        t = time.perf_counter()
        st.inspect(msg)
        return time.perf_counter() - t

    def test_hostile_inputs_fast(self):
        big_caps = {str(i): 1 for i in range(1_000_000)}
        cases = {
            "empty lists": req("tools/call", params={"a": [[]] * 1_000_000}),
            "id list": {"id": [1] * 2_000_000, "method": "ping"},
            "caps": init(capabilities=big_caps),
            "zwsp": req("tools/call", params={"a": "\u200b" * 1_000_000}),
            "tags": req("tools/call", params={"a": ("a" + chr(0xE0041)) * 500_000}),
        }
        for name, msg in cases.items():
            assert self.timed(msg) < 0.1, name
