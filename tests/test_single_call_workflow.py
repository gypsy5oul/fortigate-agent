"""Unit tests for single-call investigation workflow with mock HTTP transport (D7)."""

import json
import pytest
import httpx

from src.investigation.single_call_workflow import SingleCallInvestigationWorkflow
from src.investigation.schemas import IncidentPacket


@pytest.fixture
def base_packet():
    return IncidentPacket(
        incident_id="INC-WORKFLOW-001",
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
        deterministic_reasons=["Exploit probe observed without perimeter block"],
        signatures=["Apache.Log4j.Error.Log.Remote.Code.Execution"],
        evidence_events=[{
            "id": "EV-001",
            "log_type": "utm",
            "subtype": "ips",
            "signature": "Apache.Log4j.Error.Log.Remote.Code.Execution",
            "msg": "Log4j RCE attempt",
            "action_normalized": "ALLOWED_OR_DETECTED",
        }],
        action_catalog=[{"id": "ACT_INSPECT_APPLICATION_LOGS"}],
    )


def _make_valid_response_dict():
    return {
        "incident_id": "INC-WORKFLOW-001",
        "incident_revision": 1,
        "visibility_scope": "FIREWALL_ONLY",
        "severity": "CRITICAL",
        "attack_category": "EXPLOITATION_ATTEMPT",
        "exploitation_assessment": "ATTEMPT_OBSERVED",
        "enforcement": "ALLOWED_OR_DETECTED",
        "summary": "Observed exploit probe targeting application.",
        "findings": [{
            "kind": "OBSERVATION",
            "statement": "JNDI payload in request headers",
            "evidence_ids": ["EV-001"],
        }],
        "cve_references": ["CVE-2021-44228"],
        "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"],
    }


@pytest.mark.asyncio
async def test_json_schema_fallback_to_json_object(base_packet):
    """When vLLM returns HTTP 400 on json_schema, workflow falls back to json_object and succeeds."""
    call_modes = []

    def handle_request(request: httpx.Request):
        body = json.loads(request.content)
        fmt = body.get("response_format", {})
        mode = fmt.get("type")
        call_modes.append(mode)

        if mode == "json_schema":
            return httpx.Response(400, json={"error": {"message": "json_schema not supported"}})
        elif mode == "json_object":
            content = json.dumps(_make_valid_response_dict())
            resp_data = {
                "id": "chatcmpl-test",
                "model": "qwen3.8-27b",
                "choices": [{"message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            }
            return httpx.Response(200, json=resp_data)
        return httpx.Response(500)

    workflow = SingleCallInvestigationWorkflow(
        base_url="http://fake-vllm/v1",
        model="qwen3.8-27b",
        timeout_seconds=5.0,
    )
    workflow._client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))

    assessment = await workflow.investigate_packet(base_packet)
    await workflow.close()

    assert assessment.severity == "CRITICAL"
    assert assessment.assessment_source == "MODEL_VALIDATED"
    assert call_modes == ["json_schema", "json_object"]
    assert assessment.model_run["structured_output_mode"] == "json_object"
    assert assessment.model_run["validation_result"] == "VALID"


@pytest.mark.asyncio
async def test_invalid_json_triggers_one_repair(base_packet):
    """Invalid JSON response triggers exactly one repair call which succeeds."""
    attempt_count = 0

    def handle_request(request: httpx.Request):
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count == 1:
            # First attempt: invalid truncated JSON
            return httpx.Response(200, json={
                "choices": [{"message": {"role": "assistant", "content": "{ invalid json {"}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 10},
            })
        else:
            # Second attempt (repair): valid JSON
            content = json.dumps(_make_valid_response_dict())
            return httpx.Response(200, json={
                "choices": [{"message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": 80, "completion_tokens": 50},
            })

    workflow = SingleCallInvestigationWorkflow(
        base_url="http://fake-vllm/v1",
        model="qwen3.8-27b",
        timeout_seconds=5.0,
    )
    workflow._client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))

    assessment = await workflow.investigate_packet(base_packet)
    await workflow.close()

    assert attempt_count == 2
    assert assessment.assessment_source == "MODEL_REPAIRED"
    assert assessment.model_run["validation_result"] == "REPAIRED"


@pytest.mark.asyncio
async def test_repair_failure_yields_fallback(base_packet):
    """When both primary call and repair attempt fail, returns deterministic fallback with REJECTED."""
    attempt_count = 0

    def handle_request(request: httpx.Request):
        nonlocal attempt_count
        attempt_count += 1
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "not json at all"}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10},
        })

    workflow = SingleCallInvestigationWorkflow(
        base_url="http://fake-vllm/v1",
        model="qwen3.8-27b",
        timeout_seconds=5.0,
    )
    workflow._client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))

    assessment = await workflow.investigate_packet(base_packet)
    await workflow.close()

    assert attempt_count == 2  # Primary + 1 repair
    assert assessment.assessment_source == "MODEL_REJECTED_FALLBACK"
    assert assessment.model_run["validation_result"] == "REJECTED"
    assert "MODEL_INVALID_OUTPUT" in assessment.summary or "Deterministic" in assessment.summary


@pytest.mark.asyncio
async def test_model_run_metadata_populated(base_packet):
    """Audited model_run metadata dictionary is populated with all required audit fields."""
    def handle_request(request: httpx.Request):
        content = json.dumps(_make_valid_response_dict())
        return httpx.Response(200, json={
            "model": "qwen3.8-27b",
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 45},
        })

    workflow = SingleCallInvestigationWorkflow(
        base_url="http://fake-vllm/v1",
        model="qwen3.8-27b",
        timeout_seconds=5.0,
    )
    workflow._client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))

    assessment = await workflow.investigate_packet(base_packet)
    await workflow.close()

    mrun = assessment.model_run
    assert mrun is not None
    assert mrun["incident_id"] == "INC-WORKFLOW-001"
    assert mrun["revision"] == 1
    assert mrun["model_id"] == "qwen3.8-27b"
    assert mrun["prompt_version"] == "1.0.0"
    assert mrun["schema_version"] == "1.0.0"
    assert len(mrun["input_hash"]) == 64
    assert mrun["input_tokens"] == 120
    assert mrun["output_tokens"] == 45
    assert mrun["latency_ms"] >= 0
    assert mrun["validation_result"] == "VALID"
