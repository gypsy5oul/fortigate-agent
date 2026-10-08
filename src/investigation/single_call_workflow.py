"""Single-call investigation workflow with structured output, repair loop, and deterministic fallback.

One bounded request to the local OpenAI-compatible model endpoint, with at most one
format fallback and one repair call, all under a single shared deadline.
"""

import os
import json
import time
import hashlib
import logging
from typing import Dict, Any, Optional, List, Set
import httpx

from src.investigation.schemas import IncidentPacket, QwenAssessment, FindingItem
from src.investigation.prompts import (
    SYSTEM_PROMPT,
    SYSTEM_PROMPT_VERSION,
    USER_PROMPT_VERSION,
    build_user_prompt,
)
from src.investigation.eligibility import get_eligible_actions, load_action_catalog
from src.investigation.validator import validate_assessment, ValidationReport
from src.parsing.redaction import redact_evidence_record, wrap_untrusted_evidence
from src.observability.metrics import MODEL_FAILURES_TOTAL

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
RANK_TO_SEVERITY = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}


def estimate_tokens(text: str) -> int:
    """Conservative token count estimation (~3.5 chars per token)."""
    return max(1, int(len(text) / 3.5))


class SingleCallInvestigationWorkflow:
    def __init__(
        self,
        base_url: str = "http://localhost:8000/v1",
        model: str = "qwen3.8-27b",
        api_key: str = "EMPTY",
        timeout_seconds: float = 60.0,
        action_catalog_path: Optional[str] = None,
        max_input_tokens: int = 12000,
        max_output_tokens: int = 3500,
        fortios_build: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout_seconds
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.fortios_build = fortios_build

        self._all_catalog_actions = load_action_catalog()
        self.valid_action_ids = [a["id"] for a in self._all_catalog_actions if "id" in a] or [
            "ACT_QUARANTINE_SRC_IP",
            "ACT_INSPECT_APPLICATION_LOGS",
            "ACT_MONITOR_AND_DIGEST",
        ]

        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout_seconds,
        )

    async def close(self):
        await self._client.aclose()

    def _prepare_evidence_and_catalog(self, packet: IncidentPacket):
        # 1. Action catalog
        if packet.action_catalog:
            eligible_actions = packet.action_catalog
        else:
            eligible_actions = get_eligible_actions(
                packet.model_dump(),
                configured_build=self.fortios_build,
            )
        eligible_action_ids = {a["id"] for a in eligible_actions if "id" in a}

        prompt_catalog = [
            {
                "id": a["id"],
                "name": a.get("name", a["id"]),
                "category": a.get("category", "REMEDIATION"),
                "risk": a.get("risk", "LOW"),
                "requires_approval": a.get("requires_approval", True),
            }
            for a in eligible_actions
            if "id" in a
        ]

        # 2. Evidence sanitization & wrapping
        sanitized_events = []
        for ev in packet.evidence_events:
            redacted_ev = redact_evidence_record(ev)
            ev_id = str(redacted_ev.get("id", "UNKNOWN"))
            ev_repr = json.dumps(redacted_ev, sort_keys=True)
            sanitized_events.append({
                "id": ev_id,
                "wrapped_evidence": wrap_untrusted_evidence(ev_id, ev_repr),
                "log_type": redacted_ev.get("log_type", "traffic"),
                "has_sig": bool(redacted_ev.get("signature")),
                "action": redacted_ev.get("action_normalized"),
            })

        return prompt_catalog, eligible_action_ids, sanitized_events

    def _shrink_packet_evidence(self, sanitized_events: List[Dict[str, Any]], target_max_tokens: int) -> List[Dict[str, Any]]:
        """Shrink evidence list to fit token budget by prioritizing security UTM logs over traffic logs."""
        priority_order = {
            "utm": 1,
            "event": 2,
            "traffic": 3,
        }
        sorted_events = sorted(
            sanitized_events,
            key=lambda e: (
                priority_order.get(e.get("log_type", "traffic"), 4),
                not e.get("has_sig", False),
                e.get("action") != "BLOCKED",
            )
        )

        selected = []
        current_tokens = 500  # Base envelope cost
        for ev in sorted_events:
            ev_tokens = estimate_tokens(ev["wrapped_evidence"])
            if current_tokens + ev_tokens > target_max_tokens:
                break
            selected.append(ev)
            current_tokens += ev_tokens

        logger.info(
            "Evidence budget packing: selected %s of %s events (~%s tokens)",
            len(selected), len(sanitized_events), current_tokens,
        )
        return selected

    async def investigate_packet(self, packet: IncidentPacket) -> QwenAssessment:
        """Runs single-pass Qwen structured assessment with schema enforcement and bounded repair."""
        if packet is None:
            raise ValueError("IncidentPacket cannot be None")

        t_start = time.time()
        url = f"{self.base_url}/chat/completions"

        # One deadline for the whole investigation. The primary call, the json_object
        # fallback on HTTP 400 and the single repair call all share it, so the worst case
        # is ``timeout_seconds`` in total rather than one timeout per request.
        deadline = time.monotonic() + self.timeout

        def _remaining() -> float:
            return max(0.05, deadline - time.monotonic())

        prompt_catalog, eligible_action_ids, sanitized_events = self._prepare_evidence_and_catalog(packet)

        # Budget token check & shrink if needed
        budget_for_evidence = self.max_input_tokens - 2000
        packed_evidence = self._shrink_packet_evidence(sanitized_events, budget_for_evidence)

        packet_dict = packet.model_dump()
        packet_dict["evidence_events"] = packed_evidence
        packet_json = json.dumps(packet_dict, indent=2)
        action_catalog_json = json.dumps(prompt_catalog, indent=2)
        json_schema_str = json.dumps(QwenAssessment.model_json_schema(), indent=2)

        user_prompt = build_user_prompt(
            packet_json=packet_json,
            action_catalog_json=action_catalog_json,
            json_schema=json_schema_str,
        )

        input_tokens = estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(user_prompt)
        input_hash = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()

        server_reported_model = self.model
        structured_mode = "json_schema"
        validation_result = "VALID"
        reason_codes: List[str] = []
        output_tokens = 0
        final_assessment = None

        # 1. Primary Structured Inference Call
        try:
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
                "max_tokens": self.max_output_tokens,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "QwenAssessment",
                        "schema": QwenAssessment.model_json_schema(),
                        "strict": True,
                    },
                },
            }

            try:
                resp = await self._client.post(url, json=payload, timeout=_remaining())
                if resp.status_code == 400:
                    # Fall back to json_object mode if server does not support json_schema
                    logger.info("vLLM rejected json_schema; falling back to json_object response_format")
                    structured_mode = "json_object"
                    payload["response_format"] = {"type": "json_object"}
                    resp = await self._client.post(url, json=payload, timeout=_remaining())
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                if structured_mode == "json_schema" and e.response.status_code == 400:
                    structured_mode = "json_object"
                    payload["response_format"] = {"type": "json_object"}
                    resp = await self._client.post(url, json=payload, timeout=_remaining())
                    resp.raise_for_status()
                else:
                    raise

            resp_data = resp.json()
            server_reported_model = resp_data.get("model", self.model)
            content = resp_data["choices"][0]["message"]["content"]
            output_tokens = resp_data.get("usage", {}).get("completion_tokens", estimate_tokens(content))
            input_tokens = resp_data.get("usage", {}).get("prompt_tokens", input_tokens)

            # 2. Parse JSON & Validate
            parsed_dict = None
            try:
                parsed_dict = json.loads(content)
            except Exception as e:
                logger.warning("Model returned invalid JSON: %s. Attempting repair.", e)

            repaired = False
            if parsed_dict is not None:
                try:
                    assessment_candidate = QwenAssessment(**parsed_dict)
                    v_report = validate_assessment(assessment_candidate, packet, eligible_action_ids)
                except Exception as e:
                    v_report = ValidationReport(
                        is_valid=False,
                        assessment=None,
                        reason_codes=["SCHEMA_VALIDATION_ERROR"],
                        needs_repair=True,
                        repair_prompt=f"Validation error: {e}. Please return valid JSON matching the schema.",
                    )
            else:
                v_report = ValidationReport(
                    is_valid=False,
                    assessment=None,
                    reason_codes=["INVALID_JSON"],
                    needs_repair=True,
                    repair_prompt="Your previous output was not valid JSON. Please return valid JSON matching the schema.",
                )

            # 3. One Repair Attempt if needed
            if not v_report.is_valid and v_report.needs_repair:
                try:
                    repair_payload = {
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                            {"role": "assistant", "content": content},
                            {"role": "user", "content": v_report.repair_prompt or "Please correct and output valid JSON."},
                        ],
                        "temperature": 0.1,
                        "max_tokens": self.max_output_tokens,
                        "response_format": {"type": "json_object"},
                    }
                    rep_resp = await self._client.post(url, json=repair_payload, timeout=_remaining())
                    rep_resp.raise_for_status()
                    rep_data = rep_resp.json()
                    rep_content = rep_data["choices"][0]["message"]["content"]
                    output_tokens += rep_data.get("usage", {}).get("completion_tokens", estimate_tokens(rep_content))
                    rep_dict = json.loads(rep_content)
                    rep_assessment = QwenAssessment(**rep_dict)
                    rep_v_report = validate_assessment(rep_assessment, packet, eligible_action_ids)
                    if rep_v_report.is_valid and rep_v_report.assessment:
                        v_report = rep_v_report
                        repaired = True
                    else:
                        v_report.reason_codes.extend(rep_v_report.reason_codes)
                except Exception as e:
                    logger.warning("Repair prompt failed: %s", e)
                    v_report.reason_codes.append(f"REPAIR_FAILED_{type(e).__name__}")

            # 4. Final Assessment Decision
            if v_report.is_valid and v_report.assessment is not None:
                final_assessment = v_report.assessment
                final_assessment.assessment_source = "MODEL_REPAIRED" if repaired else "MODEL_VALIDATED"
                validation_result = "REPAIRED" if repaired else "VALID"
                reason_codes = v_report.reason_codes
            else:
                MODEL_FAILURES_TOTAL.inc()
                validation_result = "REJECTED"
                reason_codes = v_report.reason_codes
                final_assessment = self._build_fallback_assessment(packet, error_reason="MODEL_INVALID_OUTPUT")
                final_assessment.assessment_source = "MODEL_REJECTED_FALLBACK"

        except Exception as e:
            MODEL_FAILURES_TOTAL.inc()
            logger.warning("Local Qwen inference failed or timed out: %s. Using deterministic fallback.", e)
            final_assessment = self._build_fallback_assessment(packet, error_reason=str(e))
            final_assessment.assessment_source = "MODEL_REJECTED_FALLBACK"
            validation_result = "TIMEOUT" if isinstance(e, httpx.TimeoutException) or "timeout" in str(e).lower() else "ERROR"
            reason_codes = [validation_result, str(e)[:100]]

        latency_ms = int((time.time() - t_start) * 1000)

        # Attach audited model_run metadata
        final_assessment.model_run = {
            "incident_id": packet.incident_id,
            "revision": packet.incident_revision,
            "model_id": self.model,
            "server_reported_model": server_reported_model,
            "prompt_version": USER_PROMPT_VERSION,
            "schema_version": "1.0.0",
            "rule_pack_version": "1.0.0",
            "catalog_version": "1.0.0",
            "action_map_version": "1.0.0",
            "input_hash": input_hash,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "latency_ms": latency_ms,
            "structured_output_mode": structured_mode,
            "validation_result": validation_result,
            "reason_codes": reason_codes,
        }

        return final_assessment

    def _build_fallback_assessment(self, packet: IncidentPacket, error_reason: str) -> QwenAssessment:
        """Deterministic fallback when Qwen inference is unavailable."""
        evidence_ids = [str(e.get("id")) for e in packet.evidence_events if isinstance(e, dict) and "id" in e][:5]
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

