"""Unit tests for deterministic assessment validator and guardrails."""

import pytest
from src.investigation.schemas import IncidentPacket, QwenAssessment, FindingItem
from src.investigation.validator import validate_assessment


@pytest.fixture
def base_packet():
    return IncidentPacket(
        incident_id="INC-VAL-001",
        incident_revision=1,
        visibility_scope="FIREWALL_ONLY",
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
        signatures=["Apache.Log4j.Error.Log.Remote.Code.Execution"],
        evidence_events=[{"id": "EV-001", "log_type": "utm", "signature": "Apache.Log4j.Error.Log.Remote.Code.Execution"}],
        action_catalog=[{"id": "ACT_INSPECT_APPLICATION_LOGS"}, {"id": "ACT_NOTIFY_SOC_ANALYST"}],
    )


@pytest.fixture
def valid_assessment():
    return QwenAssessment(
        incident_id="INC-VAL-001",
        incident_revision=1,
        visibility_scope="FIREWALL_ONLY",
        severity="CRITICAL",
        attack_category="EXPLOITATION_ATTEMPT",
        exploitation_assessment="ATTEMPT_OBSERVED",
        enforcement="ALLOWED_OR_DETECTED",
        summary="Exploit probe observed without perimeter block.",
        findings=[FindingItem(kind="OBSERVATION", statement="Observed JNDI lookup string", evidence_ids=["EV-001"])],
        cve_references=["CVE-2021-44228"],
        recommended_action_ids=["ACT_INSPECT_APPLICATION_LOGS"],
    )


def test_valid_assessment_passes_untouched(base_packet, valid_assessment):
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert report.assessment is not None
    assert report.assessment.severity == "CRITICAL"
    assert report.assessment.incident_id == "INC-VAL-001"
    assert report.assessment.findings[0].evidence_ids == ["EV-001"]


def test_identity_mismatch_incident_id(base_packet, valid_assessment):
    valid_assessment.incident_id = "INC-FABRICATED-999"
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is False
    assert "IDENTITY_MISMATCH_INCIDENT_ID" in report.reason_codes


def test_identity_mismatch_revision(base_packet, valid_assessment):
    valid_assessment.incident_revision = 99
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is False
    assert "IDENTITY_MISMATCH_REVISION" in report.reason_codes


def test_invalid_visibility_scope(base_packet, valid_assessment):
    valid_assessment.visibility_scope = "FULL_ENDPOINT_VISIBILITY"
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is False
    assert "INVALID_VISIBILITY_SCOPE" in report.reason_codes


def test_enforcement_pinned_override(base_packet, valid_assessment):
    valid_assessment.enforcement = "BLOCKED"
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert report.assessment.enforcement == "ALLOWED_OR_DETECTED"
    assert "ENFORCEMENT_PINNED_OVERRIDE" in report.reason_codes


def test_severity_floor_enforced(base_packet, valid_assessment):
    valid_assessment.severity = "LOW"
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert report.assessment.severity == "CRITICAL"
    assert "SEVERITY_FLOOR_ENFORCED" in report.reason_codes


def test_exploitation_assessment_unsupported_without_utm(valid_assessment):
    packet_no_utm = IncidentPacket(
        incident_id="INC-VAL-001",
        incident_revision=1,
        visibility_scope="FIREWALL_ONLY",
        source_ip="198.51.100.45",
        target_ip="10.0.14.120",
        first_seen="2026-10-06T12:00:00Z",
        last_seen="2026-10-06T12:01:00Z",
        event_count=5,
        enforcement="ALLOWED_OR_DETECTED",
        enforcement_counts={"ALLOWED_OR_DETECTED": 5},
        deterministic_rule_ids=["RULE_GENERIC"],
        deterministic_severity_floor="LOW",
        deterministic_reasons=["Baseline traffic"],
        signatures=[],
        evidence_events=[{"id": "EV-002", "log_type": "traffic"}],
        action_catalog=[],
    )
    valid_assessment.findings[0].evidence_ids = ["EV-002"]
    valid_assessment.exploitation_assessment = "ATTEMPT_OBSERVED"
    report = validate_assessment(valid_assessment, packet_no_utm)
    assert report.assessment.exploitation_assessment == "INSUFFICIENT_EVIDENCE"
    assert "EXPLOITATION_ASSESSMENT_UNSUPPORTED" in report.reason_codes


def test_forbidden_claim_in_summary(base_packet, valid_assessment):
    valid_assessment.summary = "Attacker achieved confirmed compromise of the host."
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is False
    assert "FORBIDDEN_CLAIM_UNGROUNDED" in report.reason_codes


def test_forbidden_claim_in_findings(base_packet, valid_assessment):
    valid_assessment.findings.append(
        FindingItem(kind="OBSERVATION", statement="Attacker exfiltrated data via DNS", evidence_ids=["EV-001"])
    )
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is False
    assert "FORBIDDEN_CLAIM_UNGROUNDED" in report.reason_codes


def test_observation_downgraded_to_hypothesis(base_packet, valid_assessment):
    valid_assessment.findings[0].kind = "OBSERVATION"
    valid_assessment.findings[0].statement = "Target system likely running vulnerable software"
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert report.assessment.findings[0].kind == "HYPOTHESIS"
    assert "OBSERVATION_DOWNGRADED_TO_HYPOTHESIS" in report.reason_codes


def test_finding_missing_evidence_ids(base_packet, valid_assessment):
    valid_assessment.findings[0].evidence_ids = []
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is False
    assert "FINDING_MISSING_EVIDENCE_IDS" in report.reason_codes


def test_ungrounded_evidence_id(base_packet, valid_assessment):
    valid_assessment.findings[0].evidence_ids = ["EV-FABRICATED-999"]
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is False
    assert any("UNGROUNDED_EVIDENCE_ID" in r for r in report.reason_codes)


def test_ungrounded_cve_stripped(base_packet, valid_assessment):
    valid_assessment.cve_references = ["CVE-2021-44228", "CVE-1999-9999"]
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert "CVE-1999-9999" not in report.assessment.cve_references
    assert "CVE-2021-44228" in report.assessment.cve_references
    assert "UNGROUNDED_CVE_STRIPPED" in report.reason_codes


def test_ineligible_action_stripped(base_packet, valid_assessment):
    valid_assessment.recommended_action_ids = [
        "ACT_INSPECT_APPLICATION_LOGS",
        "ACT_UNAUTHORIZED_SHELL_COMMAND",
    ]
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert "ACT_UNAUTHORIZED_SHELL_COMMAND" not in report.assessment.recommended_action_ids
    assert "ACT_INSPECT_APPLICATION_LOGS" in report.assessment.recommended_action_ids
    assert "INELIGIBLE_ACTION_STRIPPED" in report.reason_codes


def test_default_action_applied_when_all_stripped(base_packet, valid_assessment):
    valid_assessment.recommended_action_ids = ["ACT_UNAUTHORIZED_SHELL_COMMAND"]
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert report.assessment.recommended_action_ids == ["ACT_INSPECT_APPLICATION_LOGS"]
    assert "DEFAULT_ACTION_APPLIED" in report.reason_codes


def test_summary_length_capped(base_packet, valid_assessment):
    valid_assessment.summary = "A" * 350
    report = validate_assessment(valid_assessment, base_packet)
    assert report.is_valid is True
    assert len(report.assessment.summary) <= 280
    assert "SUMMARY_LENGTH_CAPPED" in report.reason_codes
