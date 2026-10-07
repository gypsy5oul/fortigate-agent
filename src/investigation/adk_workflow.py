"""Google ADK integration and local Qwen investigation workflow with strict guardrails."""

import os
import json
import yaml
import logging
from typing import Dict, Any, Optional, List
import httpx

from src.investigation.schemas import IncidentPacket, QwenAssessment, FindingItem
from src.investigation.prompts import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
RANK_TO_SEVERITY = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}


class ADKInvestigationWorkflow:
    def __init__(
        self,
        base_url: str = "http://10.0.6.31:8000/v1",
        model: str = "qwen3.8-27b",
        api_key: str = "EMPTY",
        timeout_seconds: float = 60.0,
        action_catalog_path: Optional[str] = None,
        max_output_tokens: int = 3500,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout_seconds
        self.max_output_tokens = max_output_tokens

        if not action_catalog_path:
            action_catalog_path = os.path.join(
                os.path.dirname(__file__), "..", "..", "config", "action_catalog.yaml"
            )
        self.valid_action_ids = self._load_action_catalog(action_catalog_path)

        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout_seconds,
        )

    def _load_action_catalog(self, path: str) -> List[str]:
        if not os.path.exists(path):
            return ["ACT_QUARANTINE_SRC_IP", "ACT_INSPECT_APPLICATION_LOGS", "ACT_MONITOR_AND_DIGEST"]
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return [a["id"] for a in data.get("actions", [])]
        except Exception:
            return ["ACT_QUARANTINE_SRC_IP", "ACT_INSPECT_APPLICATION_LOGS", "ACT_MONITOR_AND_DIGEST"]

    async def close(self):
        await self._client.aclose()

    async def investigate_packet(self, packet: IncidentPacket) -> QwenAssessment:
        """Execute bounded model investigation on incident packet with deterministic guardrails."""
        packet_json = packet.model_dump_json(indent=2)
        url = f"{self.base_url}/chat/completions"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(packet_json)},
            ],
            "temperature": 0.1,
            "max_tokens": self.max_output_tokens,
            "response_format": {"type": "json_object"},
        }

        try:
            resp = await self._client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            assessment_dict = json.loads(content)
            assessment = QwenAssessment(**assessment_dict)
            return self._apply_guardrails(assessment, packet)
        except Exception as e:
            logger.warning("Local Qwen inference failed or timed out: %s. Using deterministic fallback.", e)
            return self._build_fallback_assessment(packet, error_reason=str(e))

    def _apply_guardrails(self, assessment: QwenAssessment, packet: IncidentPacket) -> QwenAssessment:
        """Enforce architectural constraints: severity floors, action allowlists, and evidence integrity."""
        # Enforce incident identity
        assessment.incident_id = packet.incident_id
        assessment.incident_revision = packet.incident_revision

        # 0. Enforcement is ALWAYS deterministic from packet
        assessment.model_reported_enforcement = assessment.enforcement
        assessment.enforcement = packet.enforcement
        assessment.assessment_source = "MODEL_VALIDATED"

        # 1. Enforce deterministic severity floor
        floor_rank = SEVERITY_RANKS.get(packet.deterministic_severity_floor, 1)
        model_rank = SEVERITY_RANKS.get(assessment.severity, 1)
        effective_rank = max(floor_rank, model_rank)
        assessment.severity = RANK_TO_SEVERITY.get(effective_rank, packet.deterministic_severity_floor)

        # 2. Strict allowlist check on recommended action IDs (quarantine removed automatically if not valid)
        assessment.recommended_action_ids = [
            act_id for act_id in assessment.recommended_action_ids
            if act_id in self.valid_action_ids and act_id != "ACT_QUARANTINE_SRC_IP"
        ]
        if not assessment.recommended_action_ids:
            assessment.recommended_action_ids = ["ACT_INSPECT_APPLICATION_LOGS"]

        # 3. Grounded CVE validation: strip hallucinated CVEs not grounded in packet evidence
        import re
        cve_regex = re.compile(r"^CVE-\d{4}-\d{4,}$")
        evidence_text = json.dumps([e.get("raw_message", "") for e in packet.evidence_events] + packet.signatures + packet.deterministic_reasons)
        grounded_cves = []
        for cve in assessment.cve_references:
            cve_clean = cve.strip().upper()
            if cve_regex.match(cve_clean) and cve_clean in evidence_text.upper():
                grounded_cves.append(cve_clean)
        assessment.cve_references = grounded_cves

        # 4. Evidence ID integrity: remove fabricated evidence references
        valid_evidence_ids = {e["id"] for e in packet.evidence_events if "id" in e}
        cleaned_findings = []
        for finding in assessment.findings:
            valid_ids = [eid for eid in finding.evidence_ids if eid in valid_evidence_ids]
            if valid_ids:
                finding.evidence_ids = valid_ids
                cleaned_findings.append(finding)

        if not cleaned_findings and valid_evidence_ids:
            first_id = next(iter(valid_evidence_ids))
            cleaned_findings.append(FindingItem(
                kind="OBSERVATION",
                statement=f"Observed network traffic matching {', '.join(packet.deterministic_rule_ids)}.",
                evidence_ids=[first_id],
            ))
        assessment.findings = cleaned_findings

        return assessment

    def _build_fallback_assessment(self, packet: IncidentPacket, error_reason: str) -> QwenAssessment:
        """Deterministic fallback when Qwen inference is unavailable."""
        evidence_ids = [e["id"] for e in packet.evidence_events][:5]
        default_finding = FindingItem(
            kind="OBSERVATION",
            statement=f"Observed {packet.event_count} firewall events from {packet.source_ip} to {packet.target_ip} with {packet.enforcement} enforcement.",
            evidence_ids=evidence_ids or ["FALLBACK"],
        )

        actions = ["ACT_INSPECT_APPLICATION_LOGS"] if packet.deterministic_severity_floor in ("CRITICAL", "HIGH") else ["ACT_MONITOR_AND_DIGEST"]

        err_lower = error_reason.lower()
        if "timeout" in err_lower:
            reason_code = "MODEL_TIMEOUT"
        elif "json" in err_lower or "validation" in err_lower or "format" in err_lower:
            reason_code = "MODEL_INVALID_OUTPUT"
        else:
            reason_code = "MODEL_UNREACHABLE"

        return QwenAssessment(
            incident_id=packet.incident_id,
            incident_revision=packet.incident_revision,
            visibility_scope="FIREWALL_ONLY",
            severity=packet.deterministic_severity_floor,
            attack_category="EXPLOITATION_ATTEMPT" if packet.deterministic_severity_floor in ("CRITICAL", "HIGH") else "ANOMALOUS_TRAFFIC",
            exploitation_assessment="ATTEMPT_OBSERVED" if packet.enforcement in ("ALLOWED_OR_DETECTED", "MIXED") else "INSUFFICIENT_EVIDENCE",
            enforcement=packet.enforcement,
            summary=f"Deterministic assessment only. Model analysis unavailable (reason code: {reason_code}).",
            findings=[default_finding],
            visibility_gaps=["Local LLM inference unavailable; evaluated using deterministic firewall rules."],
            recommended_action_ids=actions,
            analyst_follow_up=["Review backend web server access logs for anomalous response sizes or HTTP 200/500 codes."],
            model_reported_enforcement=None,
            assessment_source="MODEL_REJECTED_FALLBACK",
        )
