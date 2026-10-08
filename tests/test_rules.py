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


def test_restored_episode_evaluation(rule_engine):
    """Restored episodes without raw events in memory evaluate against signatures and enforcement_counts."""
    restored_ep = {
        "incident_id": "INC-RESTORED-001",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "enforcement": "ALLOWED_OR_DETECTED",
        "enforcement_counts": {"ALLOWED_OR_DETECTED": 3},
        "event_count": 3,
        "signatures": ["CVE-2021-44228"],
        "utm_subtypes": ["ips"],
        "restored": True,
        "events": [],  # No raw events in memory
    }
    res = rule_engine.evaluate_episode(restored_ep)
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" in res["matched_rule_ids"]
    assert res["severity_floor"] == "CRITICAL"
    assert res["routing_outcome"] == "URGENT_ALERT_AND_INVESTIGATE"
    assert "CVE-2021-44228" in res["reasons"][0]



def test_restored_episode_with_new_deny_keeps_exploit_rule(rule_engine):
    """B.1 Defect A: after a restart the episode's stored signatures and enforcement counts
    stay in force when new events arrive; one blocked probe must not reduce a CRITICAL
    non-blocked exploit episode to a port-scan match."""
    deny = normalize_event(
        1791271950000000000,
        'date=2026-10-08 time=12:02:00 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
        'subtype="forward" level="notice" vd="root" sessionid=500001 srcip=198.51.100.45 srcport=46000 '
        'dstip=10.0.14.120 dstport=22 proto=6 service="SSH" action="deny" policyid=0',
    )
    assert deny is not None
    restored_ep = {
        "incident_id": "INC-RESTORED-002",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "enforcement": "MIXED",
        "enforcement_counts": {"BLOCKED": 13, "ALLOWED_OR_DETECTED": 1},
        "event_count": 14,
        "signatures": ["Apache.Log4j.Error.Log.Remote.Code.Execution"],
        "utm_subtypes": ["ips"],
        "services": ["HTTPS", "HTTP", "SSH"],
        "target_ports": [443, 80, 22],
        "restored": True,
        "events": [deny],  # only the post-restart event is in memory
    }
    res = rule_engine.evaluate_episode(restored_ep)
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" in res["matched_rule_ids"]
    assert "RULE_PORT_SCAN_MULTI_SERVICE" in res["matched_rule_ids"]
    assert res["severity_floor"] == "CRITICAL"
    assert res["routing_outcome"] == "URGENT_ALERT_AND_INVESTIGATE"
    assert any("Apache.Log4j" in r for r in res["reasons"])


def test_stored_evidence_does_not_invent_utm_for_pure_denies(rule_engine):
    """A restored scanner episode (denies only, no signatures) still matches no UTM rule."""
    deny = normalize_event(
        1791271950000000000,
        'date=2026-10-08 time=12:02:01 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
        'subtype="forward" level="notice" vd="root" sessionid=500002 srcip=198.51.100.99 srcport=46001 '
        'dstip=10.0.14.120 dstport=8443 proto=6 service="HTTPS" action="deny" policyid=0',
    )
    restored_ep = {
        "incident_id": "INC-RESTORED-003",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "enforcement": "BLOCKED",
        "enforcement_counts": {"BLOCKED": 12, "ALLOWED": 0, "ALLOWED_OR_DETECTED": 0, "SESSION_CLOSED": 0, "UNKNOWN": 0},
        "event_count": 13,
        "signatures": [],
        "restored": True,
        "events": [deny],
    }
    res = rule_engine.evaluate_episode(restored_ep)
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" not in res["matched_rule_ids"]
    assert "RULE_MIXED_ENFORCEMENT_SEQUENCE" not in res["matched_rule_ids"]
    assert "RULE_HIGH_FREQUENCY_SCANNER" in res["matched_rule_ids"]
    assert res["severity_floor"] == "MEDIUM"


def test_stored_subtypes_gate_subtype_specific_rules(rule_engine):
    """Stored evidence from an antivirus episode must not satisfy the IPS/WAF or SSL rules."""
    deny = normalize_event(
        1791271950000000000,
        'date=2026-10-08 time=12:02:02 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
        'subtype="forward" level="notice" vd="root" sessionid=500003 srcip=198.51.100.60 srcport=46002 '
        'dstip=10.0.14.120 dstport=80 proto=6 service="HTTP" action="deny" policyid=0',
    )
    restored_av = {
        "incident_id": "INC-RESTORED-004",
        "source_ip": "198.51.100.60",
        "target_ip": "10.0.14.120",
        "direction": "INBOUND",
        "enforcement": "BLOCKED",
        "enforcement_counts": {"BLOCKED": 2},
        "event_count": 2,
        "signatures": ["EICAR_Test_File"],
        "utm_subtypes": ["virus"],
        "restored": True,
        "events": [deny],
    }
    res = rule_engine.evaluate_episode(restored_av)
    assert "RULE_ANTIVIRUS_BLOCKED" in res["matched_rule_ids"]
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" not in res["matched_rule_ids"]
    assert "RULE_SSL_INSPECTION_ANOMALY" not in res["matched_rule_ids"]
    assert res["severity_floor"] == "MEDIUM"
