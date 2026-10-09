"""C2.2 golden set, offline: the evalsets are ADK EvalSets that cannot drift from the spine, their
reference answers pass the validator, and every golden case runs through the real investigator
(AgentInvestigator, the runtime the service uses) against the scripted e2e fake vLLM with the
expected trajectory, a VALID outcome and no tool write.

The fake vLLM is ``tests/e2e/fake_endpoints.py`` served in process over an ASGI transport, so this
needs no port and no eval extras; ``adk eval`` against a real model is the lab wrapper's job
(``tests/agent/test_golden_eval_lab.py``).
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

pytest.importorskip("google.adk")

from google.adk.evaluation.eval_config import EvalConfig  # noqa: E402
from google.adk.evaluation.eval_metrics import ToolTrajectoryCriterion  # noqa: E402
from google.adk.evaluation.eval_set import EvalSet  # noqa: E402
from google.adk.integrations.openai import OpenAILlm  # noqa: E402
from openai import AsyncOpenAI  # noqa: E402

from src.investigation.agent.evaluation import EVAL_FIXTURE_KEY, FixtureLoki  # noqa: E402
from src.investigation.agent.runtime import AgentInvestigator  # noqa: E402
from src.investigation.agent.tools import ToolDeps, configure_tools  # noqa: E402
from src.investigation.schemas import IncidentPacket, QwenAssessment, WriterAssessment  # noqa: E402
from src.investigation.validator import validate_assessment  # noqa: E402
from src.storage.database import Database  # noqa: E402
from tests.agent.agent_fixtures import DatabaseSpy  # noqa: E402
from tests.agent.scenario import settings_for  # noqa: E402
from tests.e2e import fake_endpoints  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = ROOT / "evals" / "golden"
TEST_PG_URL = os.getenv("TEST_DATABASE_URL", "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test")
CASES = list(fake_endpoints.GOLDEN_SCENARIOS)


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_golden_set", ROOT / "scripts" / "build_golden_set.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_golden_set"] = module
    spec.loader.exec_module(module)
    return module


builder = _load_builder()


def _case(case_id: str):
    eval_set = EvalSet.model_validate_json((GOLDEN_DIR / f"{case_id}.test.json").read_text(encoding="utf-8"))
    assert len(eval_set.eval_cases) == 1
    return eval_set.eval_cases[0]


def _packet(case) -> IncidentPacket:
    return IncidentPacket.model_validate(case.session_input.state["packet"])


def test_golden_set_covers_the_c2_2_scenarios_and_nothing_else():
    assert sorted(p.name for p in GOLDEN_DIR.glob("*.test.json")) == sorted(f"{c}.test.json" for c in CASES)
    assert set(CASES) == {
        "nonblocked_ips_exploit", "blocked_exploit", "mixed_enforcement_escalation", "av_blocked",
        "blocked_scanner", "injection_payload", "model_silence",
    }


@pytest.mark.parametrize("case_id", CASES)
def test_golden_file_is_what_the_builder_produces(case_id):
    """The committed evalset is exactly what the real normalizer, aggregator, rules and eligibility
    produce for the scenario today (rerun scripts/build_golden_set.py after changing any of them)."""
    assert (GOLDEN_DIR / f"{case_id}.test.json").read_text(encoding="utf-8") == builder.render(case_id)


def test_test_config_is_the_c2_2_criteria_in_adks_schema():
    config = EvalConfig.model_validate_json((ROOT / "evals" / "test_config.json").read_text(encoding="utf-8"))
    trajectory = ToolTrajectoryCriterion.model_validate(config.criteria["tool_trajectory_avg_score"].model_dump())
    assert trajectory.threshold == 1.0
    assert trajectory.match_type == ToolTrajectoryCriterion.MatchType.EXACT and trajectory.ignore_args is True
    assert config.criteria["response_match_score"] == 0.6
    assert set(config.criteria) == {"tool_trajectory_avg_score", "response_match_score"}


@pytest.mark.parametrize("case_id", CASES)
def test_golden_case_shape_and_reference_passes_the_validator_unchanged(case_id):
    case = _case(case_id)
    packet = _packet(case)
    invocation = case.conversation[0]
    assert [t.name for t in invocation.intermediate_data.tool_uses] == ["evidence_agent", "context_agent"]
    assert case.session_input.state["incident_id"] == packet.incident_id and packet.incident_revision == 2
    assert EVAL_FIXTURE_KEY in case.session_input.state

    reference = WriterAssessment.model_validate_json(invocation.final_response.parts[0].text)
    assert reference.severity == packet.deterministic_severity_floor and reference.enforcement == packet.enforcement
    candidate = QwenAssessment(**reference.model_dump(), visibility_scope="FIREWALL_ONLY", assessment_source="MODEL_VALIDATED")
    eligible = {a["id"] for a in packet.action_catalog}
    report = validate_assessment(candidate, packet, eligible)
    assert report.is_valid and report.reason_codes == [], report.reason_codes
    assert "ACT_QUARANTINE_SRC_IP" not in reference.recommended_action_ids


# ------------------------------------------------------------------------------------------------
# Every golden case through the real investigator and the scripted fake vLLM
# ------------------------------------------------------------------------------------------------


@pytest_asyncio.fixture
async def pg():
    db = Database(TEST_PG_URL)
    await db.connect()
    async with db._pg_pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE agent_runs, agent_events, shadow_assessments CASCADE")
    yield db
    await db.close()


def _fake_model() -> OpenAILlm:
    transport = httpx.ASGITransport(app=fake_endpoints.app)
    client = AsyncOpenAI(
        base_url="http://fake-vllm.test/v1", api_key="EMPTY", max_retries=0,
        http_client=httpx.AsyncClient(transport=transport, base_url="http://fake-vllm.test"),
    )
    return OpenAILlm(model="scripted-fake", client=client)


@pytest.mark.parametrize("case_id", CASES)
async def test_golden_case_runs_valid_through_the_investigator_with_the_expected_trajectory(pg, case_id):
    case = _case(case_id)
    packet = _packet(case)
    expected = [t.name for t in case.conversation[0].intermediate_data.tool_uses]
    loki = FixtureLoki(case.session_input.state[EVAL_FIXTURE_KEY]["traffic_lines"])
    fake_endpoints.state.reset()

    inv = AgentInvestigator(settings_for(TEST_PG_URL, llm_model="scripted-fake"), pg, loki, model=_fake_model())
    spy = DatabaseSpy(pg)
    configure_tools(ToolDeps(loki=loki, selector='{service_name="forticlient"}', db=spy))
    try:
        result = await inv.investigate(packet, "shadow")
    finally:
        await inv.close()

    # 0 validator hard rejects and the deterministic floor kept.
    assert result.outcome == "VALID", result.reason_codes
    assert result.assessment.assessment_source == "MODEL_VALIDATED"
    assert result.assessment.severity == packet.deterministic_severity_floor

    # The master's trajectory is the golden one; the specialists used their tools and nothing was refused.
    events = result.record.events
    master_calls = [e["tool_name"] for e in events if e["kind"] == "tool" and e["agent_name"] == "incident_investigator"]
    assert master_calls == expected
    tools = [(e["agent_name"], e["tool_name"]) for e in events if e["kind"] == "tool"]
    assert ("evidence_agent", "get_incident_packet") in tools and ("context_agent", "get_action_catalog") in tools
    asset_ips = [e["args"]["ip"] for e in events if e.get("tool_name") == "lookup_asset"]
    assert sorted(asset_ips) == sorted([packet.source_ip, packet.target_ip])
    assert not any(e.get("refused") for e in events)
    assert result.record.llm_calls == 8

    # Agents never write: the tools sent SELECTs only.
    assert spy.statements and spy.writes() == []

    requests = fake_endpoints.state.adk_requests
    if case_id == "injection_payload":
        hostile = {r["hostile_text"] for r in requests} - {None}
        assert hostile == {"delimited"}, hostile
        assert "ACT_QUARANTINE_SRC_IP" not in result.assessment.recommended_action_ids
    if case_id == "model_silence":
        assert not case.session_input.state[EVAL_FIXTURE_KEY]["traffic_lines"]
        assert "Traffic context returned nothing for the incident window." in result.assessment.visibility_gaps
    assert not any(r["hostile_text"] == "undelimited" for r in requests)
    assert json.dumps(result.assessment.model_dump()).count("ignore previous instructions") == 0
