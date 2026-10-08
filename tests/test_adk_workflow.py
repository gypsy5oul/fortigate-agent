"""Unit tests for ADK workflow, guardrails, and deterministic fallback."""

import pytest
from src.investigation.adk_workflow import ADKInvestigationWorkflow
from src.investigation.schemas import IncidentPacket, QwenAssessment, FindingItem


@pytest.fixture
def workflow():
    return ADKInvestigationWorkflow(
        base_url="http://127.0.0.1:9999/v1",  # Dummy URL to test offline fallback
        model="qwen3.8-27b",
        timeout_seconds=1.0,
    )


@pytest.mark.asyncio
async def test_offline_fallback(workflow):
    packet = IncidentPacket(
        incident_id="INC-002",
        incident_revision=1,
        source_ip="198.51.100.45",
        target_ip="10.0.14.120",
        first_seen="2026-10-06T12:00:00Z",
        last_seen="2026-10-06T12:01:00Z",
        event_count=3,
        enforcement="MIXED",
        enforcement_counts={"BLOCKED": 2, "ALLOWED_OR_DETECTED": 1},
        deterministic_rule_ids=["RULE_MIXED_ENFORCEMENT_SEQUENCE"],
        deterministic_severity_floor="HIGH",
        deterministic_reasons=["Mixed enforcement sequence observed"],
        signatures=["Log4Shell"],
        evidence_events=[{"id": "EV-001"}],
        action_catalog=[],
    )

    # Calling with dummy endpoint will fail and trigger fallback
    assessment = await workflow.investigate_packet(packet)
    assert assessment.severity == "HIGH"
    assert assessment.enforcement == "MIXED"
    assert "fallback" in assessment.summary.lower() or "deterministic" in assessment.summary.lower()
    assert len(assessment.recommended_action_ids) > 0
