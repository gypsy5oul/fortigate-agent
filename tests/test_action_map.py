"""Table-driven unit tests for action mapping and detection rules."""

import pytest
import yaml
from pathlib import Path

from src.parsing.normalizer import normalize_action, normalize_event
from src.correlator.session_aggregator import Episode
from src.rules.engine import RuleEngine
from tests.fixtures.fortios_logs import SAMPLE_IPS_NONBLOCKED_EXPLOIT


ACTION_MAP_FILE = Path(__file__).resolve().parent.parent / "config" / "action_map.yaml"


def test_action_map_yaml_table_driven():
    """Verify every (type, subtype, action) tuple in action_map.yaml normalizes as expected."""
    with open(ACTION_MAP_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    mappings = data.get("mappings", {})
    assert len(mappings) > 0

    for log_type, subtypes in mappings.items():
        for subtype_name, actions in subtypes.items():
            st = None if subtype_name == "default" else subtype_name
            for act_name, meta in actions.items():
                expected_enforcement = meta["enforcement"]
                norm = normalize_action(act_name, log_type=log_type, subtype=st)
                assert norm == expected_enforcement, (
                    f"Mismatch for ({log_type}, {st}, {act_name}): expected {expected_enforcement}, got {norm}"
                )


def test_ips_drop_session_blocked():
    """IPS drop_session maps to BLOCKED."""
    assert normalize_action("drop_session", log_type="utm", subtype="ips") == "BLOCKED"
    assert normalize_action("dropped", log_type="utm", subtype="ips") == "BLOCKED"
    assert normalize_action("pass_session", log_type="utm", subtype="ips") == "ALLOWED_OR_DETECTED"


def test_ips_dropped_plus_accepted_traffic_same_session():
    """IPS dropped + accepted traffic log of same session does not trigger urgent alert or MIXED enforcement."""
    ep = Episode("198.51.100.45", "10.0.14.120", first_seen_ts=1700000000.0, vdom="root", direction="INBOUND")

    # 1. Accepted traffic log for session 99999
    traffic_log = {
        "id": "t1",
        "log_type": "traffic",
        "subtype": "forward",
        "sessionid": 99999,
        "action_raw": "accept",
        "action_normalized": "ALLOWED",
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.120",
    }
    # 2. IPS dropped log for the same session 99999
    ips_log = {
        "id": "ips1",
        "log_type": "utm",
        "subtype": "ips",
        "sessionid": 99999,
        "action_raw": "dropped",
        "action_normalized": "BLOCKED",
        "signature": "Exploit.Attempt",
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.120",
    }

    ep.add_event(traffic_log, 1700000000.0)
    ep.add_event(ips_log, 1700000001.0)

    # The episode overall enforcement must NOT be MIXED or ALLOWED
    assert ep.overall_enforcement == "BLOCKED"

    engine = RuleEngine()
    result = engine.evaluate_episode(ep.to_dict())

    # Must NOT produce URGENT alert
    assert result["routing_outcome"] != "URGENT_ALERT_AND_INVESTIGATE"
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" not in result["matched_rule_ids"]
    assert "RULE_MIXED_ENFORCEMENT_SEQUENCE" not in result["matched_rule_ids"]


def test_av_blocked_not_critical():
    """Antivirus detection that was blocked is MEDIUM/DIGEST, not CRITICAL/URGENT."""
    ep = Episode("198.51.100.45", "10.0.14.120", first_seen_ts=1700000000.0, vdom="root", direction="INBOUND")

    av_blocked_log = {
        "id": "av1",
        "log_type": "utm",
        "subtype": "virus",
        "action_raw": "blocked",
        "action_normalized": "BLOCKED",
        "signature": "EICAR_Test_File",
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.120",
    }
    ep.add_event(av_blocked_log, 1700000000.0)

    engine = RuleEngine()
    result = engine.evaluate_episode(ep.to_dict())

    assert "RULE_ANTIVIRUS_DETECTION" in result["matched_rule_ids"]
    assert result["severity_floor"] == "MEDIUM"
    assert result["routing_outcome"] == "DIGEST"


def test_existing_nonblocked_ips_fixture_still_critical_urgent():
    """Non-blocked IPS detection fixture must trigger CRITICAL and URGENT_ALERT_AND_INVESTIGATE."""
    ev = normalize_event(1700000000000000000, SAMPLE_IPS_NONBLOCKED_EXPLOIT)
    assert ev is not None
    assert ev["action_normalized"] == "ALLOWED_OR_DETECTED"

    ep = Episode(ev["srcip"], ev["dstip"], first_seen_ts=1700000000.0, vdom="root", direction="INBOUND")
    ep.add_event(ev, 1700000000.0)

    engine = RuleEngine()
    result = engine.evaluate_episode(ep.to_dict())

    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" in result["matched_rule_ids"]
    assert result["severity_floor"] == "CRITICAL"
    assert result["routing_outcome"] == "URGENT_ALERT_AND_INVESTIGATE"


def test_internal_to_external_denies_never_match_scanner():
    """Internal -> external denies (e.g. from 10.0.1.5 or 192.168.1.10) must never trigger RULE_HIGH_FREQUENCY_SCANNER."""
    ep = Episode("10.0.1.5", "8.8.8.8", first_seen_ts=1700000000.0, vdom="root", direction="OUTBOUND")

    for i in range(15):
        deny_ev = {
            "id": f"deny_{i}",
            "log_type": "traffic",
            "subtype": "forward",
            "action_raw": "deny",
            "action_normalized": "BLOCKED",
            "srcip": "10.0.1.5",
            "dstip": "8.8.8.8",
            "direction": "OUTBOUND",
        }
        ep.add_event(deny_ev, 1700000000.0 + i)

    engine = RuleEngine()
    result = engine.evaluate_episode(ep.to_dict())

    assert "RULE_HIGH_FREQUENCY_SCANNER" not in result["matched_rule_ids"]
