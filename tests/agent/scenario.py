"""The scripted investigation used by the pipeline, budget and injection tests (plan C1.6).

Model calls: master 3 (call evidence_agent, call context_agent, notes), evidence_agent 2 (both tools
in one turn, then notes), context_agent 2 (five tool calls in one turn, then notes), writer 1: eight
in total, exactly the default AGENT_MAX_LLM_CALLS.
"""

from typing import Any, Dict

from config.settings import Settings
from tests.agent.agent_fixtures import SIGNATURE, SOURCE_IP, TARGET_IP
from tests.agent.fake_llm import call, json_answer, text


def settings_for(database_url: str, **overrides) -> Settings:
    values = dict(
        database_url=database_url,
        llm_model="scripted-fake",
        llm_base_url="http://127.0.0.1:9/v1",
        agent_max_llm_calls=8,
        agent_timeout_seconds=30,
        llm_max_input_tokens=12000,
        loki_selector='{service_name="forticlient"}',
    )
    values.update(overrides)
    return Settings(**values)


def writer_object(packet, evidence_id: str, **overrides) -> Dict[str, Any]:
    obj = {
        "incident_id": packet.incident_id,
        "incident_revision": packet.incident_revision,
        "severity": "CRITICAL",
        "attack_category": "EXPLOITATION_ATTEMPT",
        "exploitation_assessment": "ATTEMPT_OBSERVED",
        "enforcement": packet.enforcement,
        "summary": "Log4j exploit signature detected against the protected VIP and not blocked by IPS.",
        "findings": [{"kind": "OBSERVATION", "statement": "IPS matched the Log4j signature in detect mode.", "evidence_ids": [evidence_id]}],
        "cve_references": ["CVE-2021-44228"],
        "visibility_gaps": ["No application or endpoint telemetry."],
        "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"],
        "analyst_follow_up": ["Confirm the application's Log4j version."],
    }
    obj.update(overrides)
    return obj


def notes(packet, evidence_id: str) -> str:
    return (
        f"INCIDENT: {packet.incident_id} revision {packet.incident_revision}, source {SOURCE_IP}, target {TARGET_IP}.\n"
        f"DETERMINISTIC FLOOR: {packet.deterministic_severity_floor}; RULE_NONBLOCKED_EXPLOIT_ATTEMPT.\n"
        f"OBSERVED: one IPS detection of {SIGNATURE} [{evidence_id}].\n"
        f"ENFORCEMENT: {packet.enforcement} (ALLOWED_OR_DETECTED=1).\n"
        "CONTEXT: target is a production VIP (config/assets.yaml); signature reviewed, CVE-2021-44228.\n"
        "UNKNOWN: whether the application was vulnerable.\n"
        "ELIGIBLE ACTIONS: ACT_INSPECT_APPLICATION_LOGS, ACT_SWITCH_IPS_TO_BLOCK, ACT_MONITOR_AND_DIGEST."
    )


def happy_script(packet, evidence_id: str, writer: Dict[str, Any] = None):
    return {
        "incident_investigator": [
            call(("evidence_agent", {"request": "Report what the firewall observed for this incident."})),
            call(("context_agent", {"request": f"Context for source {SOURCE_IP}, target {TARGET_IP}, signature {SIGNATURE}."})),
            text(notes(packet, evidence_id)),
        ],
        "evidence_agent": [
            call(("get_incident_packet", {}), ("query_traffic_context", {"direction": "to_target", "minutes_before": 45})),
            text(f"One IPS detection, not blocked, evidence {evidence_id}."),
        ],
        "context_agent": [
            call(
                ("lookup_asset", {"ip": TARGET_IP}),
                ("lookup_asset", {"ip": SOURCE_IP}),
                ("lookup_signature", {"signature": SIGNATURE}),
                ("recent_incidents_for_source", {}),
                ("get_action_catalog", {}),
            ),
            text("Target is a production VIP; signature reviewed (CVE-2021-44228); eligible: ACT_INSPECT_APPLICATION_LOGS."),
        ],
        "assessment_writer": [json_answer(writer or writer_object(packet, evidence_id))],
    }
