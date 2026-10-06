"""Unit tests for FortiOS parser and normalizer."""

import pytest
from src.parsing.fortios_parser import parse_fortios_line
from src.parsing.normalizer import normalize_event, normalize_action
from tests.fixtures.fortios_logs import (
    SAMPLE_TRAFFIC_DENY,
    SAMPLE_WEBFILTER_BLOCKED,
    SAMPLE_IPS_NONBLOCKED_EXPLOIT,
    SAMPLE_ESCAPED_QUOTES,
    SAMPLE_IPV6_LOG,
)


def test_parse_traffic_deny():
    parsed = parse_fortios_line(SAMPLE_TRAFFIC_DENY)
    assert parsed["type"] == "traffic"
    assert parsed["subtype"] == "forward"
    assert parsed["action"] == "deny"
    assert parsed["srcip"] == "10.0.14.120"
    assert parsed["dstip"] == "185.45.192.135"
    assert parsed["dstcountry"] == "Netherlands"


def test_parse_webfilter_blocked():
    parsed = parse_fortios_line(SAMPLE_WEBFILTER_BLOCKED)
    assert parsed["type"] == "utm"
    assert parsed["subtype"] == "webfilter"
    assert parsed["action"] == "blocked"
    assert parsed["url"] == "https://play.google.com/"
    assert parsed["msg"] == "URL belongs to a denied category in policy"


def test_parse_escaped_quotes():
    parsed = parse_fortios_line(SAMPLE_ESCAPED_QUOTES)
    assert 'nested' in parsed["msg"]
    assert parsed["srcip"] == "10.0.1.5"


def test_normalize_action():
    assert normalize_action("deny") == "BLOCKED"
    assert normalize_action("drop") == "BLOCKED"
    assert normalize_action("blocked") == "BLOCKED"
    assert normalize_action("detected") == "ALLOWED_OR_DETECTED"
    assert normalize_action("pass") == "ALLOWED_OR_DETECTED"
    assert normalize_action("passthrough") == "ALLOWED_OR_DETECTED"
    assert normalize_action("unknown_xyz") == "UNKNOWN"


def test_normalize_event():
    ev = normalize_event(1791271940000000000, SAMPLE_IPS_NONBLOCKED_EXPLOIT)
    assert ev is not None
    assert ev["log_type"] == "utm"
    assert ev["subtype"] == "ips"
    assert ev["action_normalized"] == "ALLOWED_OR_DETECTED"
    assert ev["signature"] == "Apache.Log4j.Error.Log.Remote.Code.Execution"
    assert ev["srcip"] == "198.51.100.45"
    assert ev["dstip"] == "10.0.14.120"
    assert len(ev["id"]) == 64  # SHA-256 fingerprint


def test_normalize_ipv6():
    ev = normalize_event(1791271940000000000, SAMPLE_IPV6_LOG)
    assert ev is not None
    assert ev["srcip"] == "2001:db8:85a3::8a2e:370:7334"
    assert ev["action_normalized"] == "BLOCKED"
