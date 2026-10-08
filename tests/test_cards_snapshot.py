"""Snapshot tests asserting HTML escaping and CLI safety in Google Chat cards."""

import json
import pytest
from src.notifications.gchat_cards import build_gchat_card
from src.investigation.schemas import IncidentPacket
from src.investigation.adk_workflow import ADKInvestigationWorkflow


def test_cards_snapshot_html_escaping():
    """Card inputs containing <script>, <a href>, quotes, and & must be escaped, with no raw injection."""
    malicious_input = '<script>alert("xss")</script> & <a href="http://evil.com">click me</a>'

    incident = {
        "id": "INC-TEST-XSS",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.1.5",
        "target_app": f"Target App {malicious_input}",
        "rule_name": f"Rule {malicious_input}",
        "severity": "CRITICAL",
        "enforcement": "BLOCKED",
        "event_count": 5,
    }

    assessment = {
        "severity": "CRITICAL",
        "enforcement": "BLOCKED",
        "summary": f"Attack payload injected: {malicious_input}",
        "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"],
        "exploitation_assessment": f"ATTEMPT {malicious_input}",
    }

    card_payload = build_gchat_card(
        incident=incident,
        revision=1,
        assessment=assessment,
        grafana_base_url="https://grafana.6dcorp.internal",
        datasource_uid="loki",
        cli_recommendations_enabled=False,
    )

    card_json_str = json.dumps(card_payload)

    # 1. Assert raw malicious strings are NEVER present in card JSON
    assert "<script>" not in card_json_str
    assert "</script>" not in card_json_str
    assert '<a href="http://evil.com">' not in card_json_str
    assert 'alert("xss")' not in card_json_str

    # 2. Assert properly escaped substrings exist
    assert "&lt;script&gt;" in card_json_str
    assert "&lt;/script&gt;" in card_json_str
    assert "&amp;" in card_json_str

    # 3. Assert no external http:// URLs exist in the card payload
    # Only allowed URL is the grafana explore URL
    for card in card_payload.get("cardsV2", []):
        card_content_str = json.dumps(card)
        assert "http://evil.com" not in card_content_str
        assert "http://img.icons8.com" not in card_content_str
        assert "imageUrl" not in card_content_str


def test_cli_recommendations_disabled_by_default():
    """When cli_recommendations_enabled is False, no card ever contains banned-ip or executable commands."""
    incident = {
        "id": "INC-TEST-CLI",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.1.5",
        "rule_name": "Test Rule",
        "severity": "HIGH",
        "enforcement": "BLOCKED",
    }
    assessment = {
        "severity": "HIGH",
        "enforcement": "BLOCKED",
        "summary": "High severity event.",
        "recommended_action_ids": ["ACT_QUARANTINE_SRC_IP", "ACT_INSPECT_APPLICATION_LOGS"],
    }

    card_payload = build_gchat_card(
        incident=incident,
        revision=1,
        assessment=assessment,
        cli_recommendations_enabled=False,
    )

    card_json_str = json.dumps(card_payload)
    assert "banned-ip" not in card_json_str
    assert "diagnose user" not in card_json_str
    assert "Manual review: ACT_QUARANTINE_SRC_IP" in card_json_str


def test_fallback_assessment_never_recommends_quarantine():
    """Fallback assessment must never contain ACT_QUARANTINE_SRC_IP."""
    workflow = ADKInvestigationWorkflow(base_url="http://127.0.0.1:9999/v1")
    packet = IncidentPacket(
        incident_id="INC-FALLBACK-1",
        incident_revision=1,
        visibility_scope="FIREWALL_ONLY",
        source_ip="198.51.100.10",
        target_ip="10.0.14.120",
        first_seen="2026-10-06 12:00:00",
        last_seen="2026-10-06 12:05:00",
        event_count=10,
        enforcement="BLOCKED",
        enforcement_counts={"BLOCKED": 10},
        deterministic_rule_ids=["RULE_HIGH_FREQUENCY_SCANNER"],
        deterministic_severity_floor="CRITICAL",
        deterministic_reasons=["Scanner detected"],
        signatures=["scanner"],
        evidence_events=[],
        action_catalog=[],
    )

    fallback = workflow._build_fallback_assessment(packet, error_reason="Connection refused")
    assert "ACT_QUARANTINE_SRC_IP" not in fallback.recommended_action_ids
    assert fallback.recommended_action_ids == ["ACT_INSPECT_APPLICATION_LOGS"]
    assert "Connection refused" not in fallback.summary
    assert "MODEL_UNREACHABLE" in fallback.summary
