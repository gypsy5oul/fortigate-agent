"""Phase C.0: the scripted fake vLLM and steps 1 and 2 of the ADK spike, run through the real ADK.

The fake-server contract tests need only FastAPI and run everywhere. The ADK tests are skipped
(pytest.importorskip) where google-adk is not installed, which is the case for the runtime
requirements and for CI until the C.1 dependency decision. Nothing here touches the network
beyond 127.0.0.1 and nothing touches PostgreSQL: the ADK steps use InMemorySessionService.
"""

import importlib.util
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

# Must be set before litellm is imported anywhere in this process: no model price map download.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

from src.investigation.schemas import QwenAssessment  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FAKE_SCRIPT = ROOT / "scripts" / "adk_spike_fake_vllm.py"
SPIKE_SCRIPT = ROOT / "scripts" / "adk_spike.py"
MODEL = "test-fake-qwen"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fake_module():
    return _load("adk_spike_fake_vllm", FAKE_SCRIPT)


# ---------------------------------------------------------------------------------------
# Fake server contract (no ADK needed)
# ---------------------------------------------------------------------------------------

ECHO_TOOL = {"type": "function", "function": {"name": "echo_evidence", "parameters": {"type": "object", "properties": {"evidence_id": {"type": "string"}}}}}


def test_fake_first_call_with_tools_requests_echo_evidence(fake_module):
    client = TestClient(fake_module.create_app(MODEL))
    body = client.post("/v1/chat/completions", json={"model": MODEL, "messages": [{"role": "user", "content": "go"}], "tools": [ECHO_TOOL]}).json()
    choice = body["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    calls = choice["message"]["tool_calls"]
    assert len(calls) == 1 and calls[0]["function"]["name"] == "echo_evidence"
    assert calls[0]["function"]["arguments"] == '{"evidence_id": "EVID-1"}'
    assert body["usage"]["total_tokens"] == body["usage"]["prompt_tokens"] + body["usage"]["completion_tokens"] > 0


def test_fake_quotes_the_tool_result_once_a_tool_message_exists(fake_module):
    client = TestClient(fake_module.create_app(MODEL))
    messages = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "echo_evidence", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": '{"echo": "echo-abc123"}'},
    ]
    body = client.post("/v1/chat/completions", json={"model": MODEL, "messages": messages, "tools": [ECHO_TOOL]}).json()
    choice = body["choices"][0]
    assert choice["finish_reason"] == "stop" and "tool_calls" not in choice["message"]
    assert "echo-abc123" in choice["message"]["content"]


@pytest.mark.parametrize("response_format", [
    {"type": "json_schema", "json_schema": {"name": "QwenAssessment", "strict": True, "schema": {}}},
    {"type": "json_object"},
])
def test_fake_returns_a_valid_qwen_assessment_for_structured_requests(fake_module, response_format):
    client = TestClient(fake_module.create_app(MODEL))
    system = "Copy incident_id and incident_revision exactly.\nincident_id: INC-T-9\nincident_revision: 7\nenforcement: BLOCKED\nEVID-5"
    body = client.post(
        "/v1/chat/completions",
        json={"model": MODEL, "messages": [{"role": "system", "content": system}], "response_format": response_format},
    ).json()
    assessment = QwenAssessment.model_validate_json(body["choices"][0]["message"]["content"])
    assert (assessment.incident_id, assessment.incident_revision, assessment.enforcement) == ("INC-T-9", 7, "BLOCKED")
    assert assessment.findings[0].evidence_ids == ["EVID-5"]


def test_fake_records_requests_and_serves_models(fake_module):
    client = TestClient(fake_module.create_app(MODEL))
    assert client.get("/v1/models").json()["data"][0]["id"] == MODEL
    client.post("/v1/chat/completions", json={"model": MODEL, "messages": [{"role": "user", "content": "x"}], "tools": [ECHO_TOOL], "temperature": 0.0})
    capture = client.get("/capture").json()
    assert capture["count"] == 1
    record = capture["requests"][0]
    assert record["tools"][0]["function"]["name"] == "echo_evidence"
    assert record["response_format"] is None and "temperature" in record["request_keys"]
    assert record["usage"]["total_tokens"] > 0 and record["response_kind"] == "tool_call"
    client.post("/reset")
    assert client.get("/capture").json()["count"] == 0


# ---------------------------------------------------------------------------------------
# Steps 1 and 2 through the real ADK against the fake server on a free port
# ---------------------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def fake_server():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(FAKE_SCRIPT), "--port", str(port), "--model", MODEL],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"fake vLLM exited early: {proc.stderr.read().decode(errors='replace')[:500]}")
            try:
                if httpx.get(f"{base}/health", timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            pytest.fail("fake vLLM did not become ready")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="module")
def spike():
    pytest.importorskip("google.adk")
    if importlib.util.find_spec("litellm") is None:
        pytest.skip("litellm is not installed")
    return _load("adk_spike", SPIKE_SCRIPT)


async def test_adk_steps_1_and_2_against_the_scripted_fake(spike, fake_server):
    cfg = spike.SpikeConfig(base_url=f"{fake_server}/v1", model=MODEL, fake=True)
    tr = spike.Transcript(spike.Redactor(cfg), echo=False)
    ctx = spike.Ctx(cfg=cfg, tr=tr, rec=spike.CallRecorder(), cap=spike.FakeCapture.detect(cfg.root_url))
    assert ctx.cap is not None, "the fake server must expose /capture"

    await spike.step1_tool_roundtrip(ctx)
    await spike.step2_output_schema(ctx)

    assert not tr.failures, "failed spike assertions:\n" + "\n".join(tr.failures) + "\n\n" + tr.render()
    assert tr.passed >= 15

    # Independent of the spike's own assertions: what the endpoint actually saw.
    requests = ctx.cap.requests()
    assert [r["response_kind"] for r in requests] == ["tool_call", "final_text_after_tool", "structured_json"]
    assert requests[0]["tools"] and not requests[2]["tools"]
    assert requests[2]["response_format"]["json_schema"]["name"] == "QwenAssessment"
