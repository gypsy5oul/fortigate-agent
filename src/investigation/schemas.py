"""Pydantic schemas and guardrails for bounded ADK investigation."""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict

VisibilityScope = Literal["FIREWALL_ONLY"]
SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
EnforcementState = Literal["BLOCKED", "ALLOWED_OR_DETECTED", "MIXED", "UNKNOWN"]
ExploitationAssessment = Literal["ATTEMPT_OBSERVED", "SUSPICIOUS_SEQUENCE", "INSUFFICIENT_EVIDENCE"]
FindingKind = Literal["OBSERVATION", "HYPOTHESIS"]
AttackCategory = Literal[
    "RECONNAISSANCE",
    "EXPLOITATION_ATTEMPT",
    "MALWARE_TRANSFER",
    "DENIAL_OF_SERVICE",
    "ANOMALOUS_TRAFFIC",
    "UNKNOWN",
]


class FindingItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: FindingKind
    statement: str = Field(..., max_length=400)
    evidence_ids: List[str] = Field(..., min_length=1, max_length=10)


class QwenAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    incident_revision: int
    visibility_scope: VisibilityScope = "FIREWALL_ONLY"
    severity: SeverityLevel
    attack_category: AttackCategory
    exploitation_assessment: ExploitationAssessment
    enforcement: EnforcementState
    summary: str = Field(..., max_length=1200)
    findings: List[FindingItem] = Field(default_factory=list, max_length=10)
    cve_references: List[str] = Field(
        default_factory=list,
        max_length=10,
    )
    visibility_gaps: List[str] = Field(default_factory=list, max_length=10)
    recommended_action_ids: List[str] = Field(default_factory=list, max_length=6)
    analyst_follow_up: List[str] = Field(default_factory=list, max_length=5)
    model_reported_enforcement: Optional[str] = Field(default=None)
    assessment_source: Optional[str] = Field(default="DETERMINISTIC")


class IncidentPacket(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    incident_revision: int
    visibility_scope: VisibilityScope = "FIREWALL_ONLY"
    source_ip: str
    target_ip: str
    target_app: Optional[str] = None
    first_seen: str
    last_seen: str
    event_count: int
    enforcement: EnforcementState
    enforcement_counts: dict
    deterministic_rule_ids: List[str]
    deterministic_severity_floor: SeverityLevel
    deterministic_reasons: List[str]
    signatures: List[str]
    evidence_events: List[dict]
    action_catalog: List[dict]
