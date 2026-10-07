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


def test_dynamic_custom_rule_without_code_changes():
    """Acceptance test B8: A completely new rule defined in YAML fires dynamically without code modifications."""
    custom_rule = {
        "id": "RULE_CUSTOM_OUTBOUND_EXFIL",
        "name": "Custom Outbound Spike Rule",
        "priority": "INVESTIGATE",
        "min_severity": "HIGH",
        "condition": {
            "direction": "OUTBOUND",
            "min_events": 5,
        },
        "reason_template": "Outbound exfiltration anomaly: {event_count} events from {source_ip}",
    }
    engine = RuleEngine(rules=[custom_rule])

    # Positive episode
    pos_ep = {
        "incident_id": "INC-DYNAMIC-POS",
        "source_ip": "10.0.1.25",
        "target_ip": "203.0.113.88",
        "direction": "OUTBOUND",
        "event_count": 8,
        "events": [{"srcip": "10.0.1.25", "dstip": "203.0.113.88"}] * 8,
    }
    pos_res = engine.evaluate_episode(pos_ep)
    assert "RULE_CUSTOM_OUTBOUND_EXFIL" in pos_res["matched_rule_ids"]
    assert pos_res["severity_floor"] == "HIGH"
    assert pos_res["routing_outcome"] == "INVESTIGATE"
    assert "8 events from 10.0.1.25" in pos_res["reasons"][0]

    # Negative episode (inbound direction should not match)
    neg_ep = {
        "incident_id": "INC-DYNAMIC-NEG",
        "source_ip": "203.0.113.88",
        "target_ip": "10.0.1.25",
        "direction": "INBOUND",
        "event_count": 8,
        "events": [],
    }
    neg_res = engine.evaluate_episode(neg_ep)
    assert "RULE_CUSTOM_OUTBOUND_EXFIL" not in neg_res["matched_rule_ids"]


def test_multi_service_port_scanner_rule(rule_engine):
    """RULE_PORT_SCAN_MULTI_SERVICE matches when 3+ distinct ports/services are probed."""
    # Positive case: 3 distinct ports
    pos_ep = {
        "incident_id": "INC-SCAN-POS",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "event_count": 4,
        "services": ["HTTP", "SSH", "RDP"],
        "target_ports": [80, 22, 3389],
        "events": [
            {"srcip": "198.51.100.99", "dstip": "10.0.14.120", "dstport": 80, "service": "HTTP"},
            {"srcip": "198.51.100.99", "dstip": "10.0.14.120", "dstport": 22, "service": "SSH"},
            {"srcip": "198.51.100.99", "dstip": "10.0.14.120", "dstport": 3389, "service": "RDP"},
        ],
    }
    res = rule_engine.evaluate_episode(pos_ep)
    assert "RULE_PORT_SCAN_MULTI_SERVICE" in res["matched_rule_ids"]

    # Negative case: only 1 port
    neg_ep = {
        "incident_id": "INC-SCAN-NEG",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "event_count": 4,
        "services": ["HTTP"],
        "target_ports": [80],
        "events": [{"srcip": "198.51.100.99", "dstip": "10.0.14.120", "dstport": 80, "service": "HTTP"}] * 4,
    }
    neg_res = rule_engine.evaluate_episode(neg_ep)
    assert "RULE_PORT_SCAN_MULTI_SERVICE" not in neg_res["matched_rule_ids"]


def test_distributed_attack_rule(rule_engine):
    """RULE_DISTRIBUTED_ATTACK matches when multiple sources target the same destination."""
    pos_ep = {
        "incident_id": "INC-DIST-POS",
        "source_ip": "198.51.100.1",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "source_ips": ["198.51.100.1", "198.51.100.2", "198.51.100.3"],
        "event_count": 3,
        "events": [],
    }
    res = rule_engine.evaluate_episode(pos_ep)
    assert "RULE_DISTRIBUTED_ATTACK" in res["matched_rule_ids"]
    assert res["severity_floor"] == "HIGH"
    assert res["routing_outcome"] == "INVESTIGATE"


def test_antivirus_blocked_vs_allowed(rule_engine):
    """RULE_ANTIVIRUS_DETECTION (CRITICAL/URGENT) vs RULE_ANTIVIRUS_BLOCKED (MEDIUM/DIGEST)."""
    # Blocked AV
    blocked_ev = {
        "log_type": "utm",
        "subtype": "virus",
        "action_normalized": "BLOCKED",
        "signature": "Eicar-Test-Signature",
    }
    blocked_ep = {
        "incident_id": "INC-AV-BLOCKED",
        "source_ip": "10.0.1.50",
        "target_ip": "203.0.113.10",
        "enforcement": "BLOCKED",
        "event_count": 1,
        "events": [blocked_ev],
    }
    res_b = rule_engine.evaluate_episode(blocked_ep)
    assert "RULE_ANTIVIRUS_BLOCKED" in res_b["matched_rule_ids"]
    assert "RULE_ANTIVIRUS_DETECTION" not in res_b["matched_rule_ids"]
    assert res_b["severity_floor"] == "MEDIUM"
    assert res_b["routing_outcome"] == "DIGEST"

    # Allowed / detected AV
    allowed_ev = {
        "log_type": "utm",
        "subtype": "virus",
        "action_normalized": "ALLOWED_OR_DETECTED",
        "signature": "W32/Stuxnet",
    }
    allowed_ep = {
        "incident_id": "INC-AV-ALLOWED",
        "source_ip": "198.51.100.77",
        "target_ip": "10.0.14.120",
        "enforcement": "ALLOWED_OR_DETECTED",
        "event_count": 1,
        "events": [allowed_ev],
    }
    res_a = rule_engine.evaluate_episode(allowed_ep)
    assert "RULE_ANTIVIRUS_DETECTION" in res_a["matched_rule_ids"]
    assert res_a["severity_floor"] == "CRITICAL"
    assert res_a["routing_outcome"] == "URGENT_ALERT_AND_INVESTIGATE"


def test_health_alert_rules(rule_engine):
    """Health alerts route to RETAIN_WITH_VISIBILITY_GAP with priority DIGEST."""
    health_ep = {
        "incident_id": "INC-HEALTH-GAP",
        "source_ip": "127.0.0.1",
        "target_ip": "127.0.0.1",
        "health_metric": "parser_errors",
        "event_count": 6,
        "events": [],
    }
    res = rule_engine.evaluate_episode(health_ep)
    assert "RULE_HIGH_PARSER_ERROR_RATE" in res["matched_rule_ids"]
    assert res["routing_outcome"] == "RETAIN_WITH_VISIBILITY_GAP"
