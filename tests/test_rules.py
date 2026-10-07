"""Unit tests for deterministic rule evaluation engine."""

import pytest
from src.rules.engine import RuleEngine
from src.parsing.normalizer import normalize_event
from tests.fixtures.fortios_logs import (
    SAMPLE_IPS_NONBLOCKED_EXPLOIT,
    SAMPLE_WAF_SQLI_PASSTHROUGH,
    SAMPLE_SSL_DPI_ANOMALY,
    SAMPLE_TRAFFIC_DENY,
)


@pytest.fixture
def rule_engine():
    return RuleEngine()


def test_nonblocked_exploit_rule(rule_engine):
    ev1 = normalize_event(1791271940000000000, SAMPLE_IPS_NONBLOCKED_EXPLOIT)
    episode = {
        "incident_id": "INC-TEST-001",
        "source_ip": ev1["srcip"],
        "target_ip": ev1["dstip"],
        "enforcement": "ALLOWED_OR_DETECTED",
        "event_count": 1,
        "signatures": [ev1["signature"]],
        "events": [ev1],
    }

    result = rule_engine.evaluate_episode(episode)
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" in result["matched_rule_ids"]
    assert result["severity_floor"] == "CRITICAL"
    assert result["routing_outcome"] == "URGENT_ALERT_AND_INVESTIGATE"
    assert len(result["reasons"]) > 0


def test_ssl_anomaly_rule(rule_engine):
    ev = normalize_event(1791271940000000000, SAMPLE_SSL_DPI_ANOMALY)
    episode = {
        "incident_id": "INC-TEST-002",
        "source_ip": ev["srcip"],
        "target_ip": ev["dstip"],
        "enforcement": "UNKNOWN",
        "event_count": 1,
        "signatures": [],
        "events": [ev],
    }

    result = rule_engine.evaluate_episode(episode)
    assert "RULE_SSL_INSPECTION_ANOMALY" in result["matched_rule_ids"]
    assert result["severity_floor"] == "HIGH"
    assert result["routing_outcome"] == "INVESTIGATE"


def test_scanner_digest_rule(rule_engine):
    ev = normalize_event(1791271940000000000, SAMPLE_TRAFFIC_DENY)
    episode = {
        "incident_id": "INC-TEST-003",
        "source_ip": "198.51.100.5",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "enforcement": "BLOCKED",
        "event_count": 15,
        "signatures": [],
        "events": [ev] * 15,
    }

    result = rule_engine.evaluate_episode(episode)
    assert "RULE_HIGH_FREQUENCY_SCANNER" in result["matched_rule_ids"]
    assert result["severity_floor"] == "MEDIUM"
    assert result["routing_outcome"] == "DIGEST"
