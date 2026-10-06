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


def test_guardrails_severity_floor(workflow):
    packet = IncidentPacket(
        incident_id="INC-001",
        incident_revision=1,
        source_ip="198.51.100.45",
        target_ip="10.0.14.120",
        first_seen="2026-10-06T12:00:00Z",
        last_seen="2026-10-06T12:01:00Z",
        event_count=5,
        enforcement="ALLOWED_OR_DETECTED",
        enforcement_counts={"ALLOWED_OR_DETECTED": 5},
        deterministic_rule_ids=["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        deterministic_severity_floor="CRITICAL",
        deterministic_reasons=["Exploit detected without perimeter blocking"],
        signatures=["CVE-2021-44228"],
        evidence_events=[{"id": "EV-001"}],
        action_catalog=[],
    )

    # Simulated hallucinated assessment where model tried to downplay severity to LOW
    hallucinated = QwenAssessment(
        incident_id="INC-001",
        incident_revision=1,
        severity="LOW",
        attack_category="RECONNAISSANCE",
        exploitation_assessment="INSUFFICIENT_EVIDENCE",
        enforcement="ALLOWED_OR_DETECTED",
        summary="Looks benign.",
        findings=[FindingItem(kind="OBSERVATION", statement="Probe seen", evidence_ids=["EV-001", "FABRICATED-999"])],
        recommended_action_ids=["ACT_INSPECT_APPLICATION_LOGS", "ACT_UNAUTHORIZED_SHELL_COMMAND"],
    )

    guarded = workflow._apply_guardrails(hallucinated, packet)
    # 1. Severity floor must force it to CRITICAL
    assert guarded.severity == "CRITICAL"
    # 2. Fabricated evidence ID must be stripped
    assert guarded.findings[0].evidence_ids == ["EV-001"]
    # 3. Unauthorized action ID must be stripped
    assert "ACT_UNAUTHORIZED_SHELL_COMMAND" not in guarded.recommended_action_ids


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
