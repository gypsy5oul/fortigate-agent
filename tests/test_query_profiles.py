"""Tests for query profiles, LogQL parameter rendering, escaping, and extended log formats."""

import pytest
from src.sources.query_profiles import (
    escape_logql_string,
    UTM_DETECTIONS_PROFILE,
    FIREWALL_EVENTS_PROFILE,
    TRAFFIC_CONTEXT_PROFILE,
    TRAFFIC_BASELINE_PROFILE,
    get_query_profile,
)
from src.parsing.fortios_parser import parse_fortios_line
from src.parsing.normalizer import normalize_event
from tests.fixtures.fortios_logs import (
    SAMPLE_JSON_ENVELOPE,
    SAMPLE_SYSLOG_PREFIX,
    SAMPLE_EVENT_ADMIN_LOGIN,
    SAMPLE_MALFORMED_LINE,
    SAMPLE_IPV6_LOG,
)


def test_escape_logql_string():
    raw = 'test\\"value\nwith\rspecial\tchars\\and"quotes'
    escaped = escape_logql_string(raw)
    assert "\n" not in escaped
    assert "\r" not in escaped
    assert "\t" not in escaped
    assert '\\"' in escaped


def test_render_utm_detections_profile():
    selector = '{service_name="forticlient"}'
    
    # Default bare UTM profile
    rendered = UTM_DETECTIONS_PROFILE.render(selector)
    assert rendered == '{service_name="forticlient"} |= "type=\\"utm\\""'
    assert UTM_DETECTIONS_PROFILE.stream_key(selector) == '{service_name="forticlient"}#utm_detections@v1'

    # With subtype allowlist
    rendered_sub = UTM_DETECTIONS_PROFILE.render(selector, {"subtypes": ["ips", "waf", "virus"]})
    assert '|= "type=\\"utm\\""' in rendered_sub
    assert '|~ "subtype=\\\"(?:ips|waf|virus)\\\""' in rendered_sub


def test_render_firewall_events_profile():
    selector = '{service_name="forticlient"}'
    rendered = FIREWALL_EVENTS_PROFILE.render(selector, {"subtypes": ["system", "admin"]})
    assert '|= "type=\\"event\\""' in rendered
    assert '|~ "subtype=\\\"(?:system|admin)\\\""' in rendered
    assert FIREWALL_EVENTS_PROFILE.stream_key(selector) == '{service_name="forticlient"}#firewall_events@v1'


def test_render_traffic_context_profile():
    selector = '{service_name="forticlient"}'
    params = {
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.120",
        "srcport": 44812,
        "dstport": 443,
        "sessionid": 1125640999,
        "devid": "FGT-CORP-01",
        "vd": "root",
    }
    rendered = TRAFFIC_CONTEXT_PROFILE.render(selector, params)
    assert '|= "type=\\"traffic\\""' in rendered
    assert '|= "srcip=198.51.100.45"' in rendered
    assert '|= "dstip=10.0.14.120"' in rendered
    assert '|= "srcport=44812"' in rendered
    assert '|= "dstport=443"' in rendered
    assert '|= "sessionid=1125640999"' in rendered
    assert '|= "devid=\\"FGT-CORP-01\\""' in rendered
    assert '|= "vd=\\"root\\""' in rendered


def test_render_traffic_baseline_profile():
    selector = '{service_name="forticlient"}'
    rendered = TRAFFIC_BASELINE_PROFILE.render(selector, {"vd": "root"})
    assert '|= "type=\\"traffic\\""' in rendered
    assert '|= "vd=\\"root\\""' in rendered


def test_profile_version_bump_changes_stream_key():
    selector = '{service_name="forticlient"}'
    p_v1 = UTM_DETECTIONS_PROFILE
    key_v1 = p_v1.stream_key(selector)
    assert key_v1.endswith("@v1")

    # If version increments, stream key changes, triggering bounded bootstrap instead of silent reuse
    p_v2 = UTM_DETECTIONS_PROFILE.__class__(
        name="utm_detections",
        version=2,
        template_fn=UTM_DETECTIONS_PROFILE.template_fn,
    )
    key_v2 = p_v2.stream_key(selector)
    assert key_v2.endswith("@v2")
    assert key_v1 != key_v2


def test_parse_json_envelope():
    parsed = parse_fortios_line(SAMPLE_JSON_ENVELOPE)
    assert parsed.get("type") == "traffic"
    assert parsed.get("srcip") == "10.0.1.5"
    assert parsed.get("dstip") == "93.184.216.34"
    assert parsed.get("action") == "accept"


def test_parse_syslog_prefix():
    parsed = parse_fortios_line(SAMPLE_SYSLOG_PREFIX)
    assert parsed.get("type") == "traffic"
    assert parsed.get("devname") == "FGT"
    assert parsed.get("srcip") == "10.0.1.5"
    assert parsed.get("dstip") == "93.184.216.34"


def test_normalize_event_admin_login_without_dstip():
    base_ts = 1791271940000000000
    ev = normalize_event(base_ts, SAMPLE_EVENT_ADMIN_LOGIN)
    assert ev is not None
    assert ev["log_type"] == "event"
    assert ev["subtype"] == "system"
    assert ev["srcip"] == "192.168.1.99"
    assert ev["dstip"] is None
    assert ev["action_normalized"] in ("ALLOWED_OR_DETECTED", "UNKNOWN")


def test_parse_malformed_line():
    parsed = parse_fortios_line(SAMPLE_MALFORMED_LINE)
    assert parsed == {}
    ev = normalize_event(1791271940000000000, SAMPLE_MALFORMED_LINE)
    assert ev is None


def test_parse_ipv6_line():
    base_ts = 1791271940000000000
    ev = normalize_event(base_ts, SAMPLE_IPV6_LOG)
    assert ev is not None
    assert ev["srcip"] == "2001:db8:85a3::8a2e:370:7334"
    assert ev["dstip"] == "2001:db8:85a3::1"
    assert ev["action_normalized"] == "BLOCKED"
