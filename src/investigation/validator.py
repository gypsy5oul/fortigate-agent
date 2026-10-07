"""Deterministic investigation validator enforcing identity, evidence grounding, and safety lexicon."""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional, Tuple

from src.investigation.schemas import QwenAssessment, IncidentPacket, FindingItem
from src.context.signatures import get_signature_manager

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

FORBIDDEN_CLAIMS_PATTERN = re.compile(
    r"\b(confirmed compromise|exfiltrated|reverse shell|successfully exploited|attacker is)\b",
    re.IGNORECASE,
)

UNCERTAINTY_WORDS_PATTERN = re.compile(
    r"\b(likely|probably|may have)\b",
    re.IGNORECASE,
)


@dataclass
class ValidationReport:
    is_valid: bool
    assessment: Optional[QwenAssessment]
    reason_codes: List[str] = field(default_factory=list)
    needs_repair: bool = False
    repair_prompt: Optional[str] = None


def validate_assessment(
    assessment: QwenAssessment,
    packet: IncidentPacket,
    eligible_action_ids: Optional[Set[str]] = None,
) -> ValidationReport:
    """Validates and enforces deterministic guardrails on model investigation output."""
    reasons: List[str] = []
    hard_reject = False

    # 1. Identity Pinning
    if assessment.incident_id != packet.incident_id:
        reasons.append("IDENTITY_MISMATCH_INCIDENT_ID")
        hard_reject = True

    if assessment.incident_revision != packet.incident_revision:
        reasons.append("IDENTITY_MISMATCH_REVISION")
        hard_reject = True

    if assessment.visibility_scope != "FIREWALL_ONLY":
        reasons.append("INVALID_VISIBILITY_SCOPE")
        hard_reject = True

    # 2. Enforcement Pinning
    if assessment.enforcement != packet.enforcement:
        assessment.model_reported_enforcement = assessment.enforcement
        assessment.enforcement = packet.enforcement
        reasons.append("ENFORCEMENT_PINNED_OVERRIDE")

    # 3. Severity Floor Pinning
    floor = packet.deterministic_severity_floor
    floor_idx = SEVERITY_LEVELS.index(floor) if floor in SEVERITY_LEVELS else 0
    model_idx = SEVERITY_LEVELS.index(assessment.severity) if assessment.severity in SEVERITY_LEVELS else 0
    if model_idx < floor_idx:
        assessment.severity = floor
        reasons.append("SEVERITY_FLOOR_ENFORCED")

    # 4. Exploitation Assessment Grounding
    has_utm = any(
        ev.get("log_type", "").lower() == "utm" or ev.get("signature")
        for ev in packet.evidence_events
    )
    if assessment.exploitation_assessment == "ATTEMPT_OBSERVED" and not has_utm:
        assessment.exploitation_assessment = "INSUFFICIENT_EVIDENCE"
        reasons.append("EXPLOITATION_ASSESSMENT_UNSUPPORTED")

    # 5. Forbidden Lexicon Claims
    if FORBIDDEN_CLAIMS_PATTERN.search(assessment.summary):
        reasons.append("FORBIDDEN_CLAIM_UNGROUNDED")
        hard_reject = True

    for f in assessment.findings:
        if FORBIDDEN_CLAIMS_PATTERN.search(f.statement):
            reasons.append("FORBIDDEN_CLAIM_UNGROUNDED")
            hard_reject = True
            break

    # 6. Observation vs Hypothesis Downgrade
    for f in assessment.findings:
        if f.kind == "OBSERVATION" and UNCERTAINTY_WORDS_PATTERN.search(f.statement):
            f.kind = "HYPOTHESIS"
            reasons.append("OBSERVATION_DOWNGRADED_TO_HYPOTHESIS")

    # 7. Evidence ID Grounding
    packet_evidence_ids = {str(ev.get("id")) for ev in packet.evidence_events if ev.get("id")}
    for f in assessment.findings:
        if not f.evidence_ids:
            reasons.append("FINDING_MISSING_EVIDENCE_IDS")
            hard_reject = True
        for eid in f.evidence_ids:
            if eid not in packet_evidence_ids:
                reasons.append(f"UNGROUNDED_EVIDENCE_ID_{eid}")
                hard_reject = True

    # 8. CVE Grounding (B3)
    sig_mgr = get_signature_manager()
    grounded_cves = sig_mgr.get_grounded_cves(packet.signatures)
    clean_cves: List[str] = []
    for cve in assessment.cve_references:
        cve_norm = cve.strip().upper()
        if cve_norm in grounded_cves:
            clean_cves.append(cve_norm)
        else:
            reasons.append("UNGROUNDED_CVE_STRIPPED")
    assessment.cve_references = clean_cves

    # 9. Recommended Actions Eligibility (B2)
    allowed_actions = eligible_action_ids
    if allowed_actions is None:
        allowed_actions = {a.get("id") for a in packet.action_catalog if a.get("id")}

    clean_actions: List[str] = []
    for act_id in assessment.recommended_action_ids:
        if act_id in allowed_actions:
            clean_actions.append(act_id)
        else:
            reasons.append("INELIGIBLE_ACTION_STRIPPED")
    assessment.recommended_action_ids = clean_actions

    # 10. Length Caps
    if len(assessment.summary) > 280:
        assessment.summary = assessment.summary[:277] + "..."
        reasons.append("SUMMARY_LENGTH_CAPPED")

    for f in assessment.findings:
        if len(f.statement) > 280:
            f.statement = f.statement[:277] + "..."
            reasons.append("FINDING_STATEMENT_LENGTH_CAPPED")

    if hard_reject:
        repair_msg = (
            f"Validation rejected the assessment due to: {', '.join(reasons)}. "
            "Please fix the issues, remove ungrounded evidence IDs or forbidden claims, "
            "and output strictly valid JSON matching the schema."
        )
        return ValidationReport(
            is_valid=False,
            assessment=None,
            reason_codes=reasons,
            needs_repair=True,
            repair_prompt=repair_msg,
        )

    return ValidationReport(
        is_valid=True,
        assessment=assessment,
        reason_codes=reasons,
        needs_repair=False,
    )
