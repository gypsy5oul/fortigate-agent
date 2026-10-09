"""C.1 dependency decision, executable: ADK's native OpenAI-compatible model class against the C.0 fake.

The runtime image carries google-adk without litellm (ADR 005). This proves, in every environment that
installs requirements.txt (CI included), what the C.0 spike's steps 1 and 2 proved for LiteLlm, using
the same scripted fake (scripts/adk_spike_fake_vllm.py): a plain-function tool round trip, and an
output_schema writer whose request carries response_format json_schema and whose answer validates.
"""

import importlib.util
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

pytest.importorskip("google.adk")
pytest.importorskip("openai")

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.agents.run_config import RunConfig  # noqa: E402
from google.adk.runners import Runner  # noqa: E402
from google.adk.sessions import InMemorySessionService  # noqa: E402
from google.genai import types  # noqa: E402

from src.investigation.agent.agents import build_model  # noqa: E402
from src.investigation.schemas import QwenAssessment  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FAKE_SCRIPT = ROOT / "scripts" / "adk_spike_fake_vllm.py"
MODEL = "c1-fake-qwen"
TOOL_RUNS = []


def echo_evidence(evidence_id: str) -> dict:
    """Echo an evidence id back with a marker that proves this function ran."""
    TOOL_RUNS.append(evidence_id)
    return {"status": "success", "evidence_id": evidence_id, "echo": f"echo-{len(TOOL_RUNS)}-c1"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def fake_vllm():
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


async def _run(agent, state=None):
    svc = InMemorySessionService()
    runner = Runner(app_name="c1-openai-model", agent=agent, session_service=svc)
    await svc.create_session(app_name="c1-openai-model", user_id="system", session_id="s1", state=state or {})
    events = []
    async for ev in runner.run_async(
        user_id="system",
        session_id="s1",
        new_message=types.Content(role="user", parts=[types.Part(text="Run the task.")]),
        run_config=RunConfig(max_llm_calls=4),
    ):
        events.append(ev)
    session = await svc.get_session(app_name="c1-openai-model", user_id="system", session_id="s1")
    await runner.close()
    return events, session


def _requests(base):
    return httpx.get(f"{base}/capture", timeout=5).json()["requests"]


async def test_openai_llm_tool_round_trip_against_spike_fake(fake_vllm):
    httpx.post(f"{fake_vllm}/reset", timeout=5)
    TOOL_RUNS.clear()
    agent = LlmAgent(
        name="tool_agent",
        model=build_model(base_url=f"{fake_vllm}/v1", model=MODEL, api_key="EMPTY", timeout_seconds=10),
        instruction="Call echo_evidence once with evidence_id EVID-1, then quote the echo field.",
        tools=[echo_evidence],
    )
    events, _ = await _run(agent)

    calls = [fc for ev in events for fc in (ev.get_function_calls() or [])]
    assert [(c.name, dict(c.args)) for c in calls] == [("echo_evidence", {"evidence_id": "EVID-1"})]
    assert TOOL_RUNS == ["EVID-1"]
    final = "".join(p.text or "" for ev in events if ev.is_final_response() and ev.content for p in ev.content.parts)
    assert "echo-1-c1" in final

    reqs = _requests(fake_vllm)
    assert [r["response_kind"] for r in reqs] == ["tool_call", "final_text_after_tool"]
    assert [t["function"]["name"] for t in reqs[0]["tools"]] == ["echo_evidence"]
    assert any(m.get("role") == "tool" for m in reqs[1]["messages"])


async def test_openai_llm_output_schema_against_spike_fake(fake_vllm):
    httpx.post(f"{fake_vllm}/reset", timeout=5)
    note = "incident_id: INC-C1-0001\nincident_revision: 4\nenforcement: BLOCKED\nevidence EVID-7"
    writer = LlmAgent(
        name="assessment_writer",
        model=build_model(base_url=f"{fake_vllm}/v1", model=MODEL, api_key="EMPTY", timeout_seconds=10),
        instruction="Produce one assessment from the note.\n{note}",
        output_schema=QwenAssessment,
        include_contents="none",
        output_key="assessment_json",
    )
    _, session = await _run(writer, state={"note": note})

    assessment = QwenAssessment.model_validate(session.state["assessment_json"])
    assert (assessment.incident_id, assessment.incident_revision, assessment.enforcement) == ("INC-C1-0001", 4, "BLOCKED")
    reqs = _requests(fake_vllm)
    assert len(reqs) == 1 and reqs[0]["response_kind"] == "structured_json"
    rf = reqs[0]["response_format"]
    assert rf["type"] == "json_schema" and rf["json_schema"]["name"] == "QwenAssessment" and rf["json_schema"]["strict"] is True
    assert not reqs[0]["tools"]
    assert "INC-C1-0001" in json.dumps(reqs[0]["messages"])
