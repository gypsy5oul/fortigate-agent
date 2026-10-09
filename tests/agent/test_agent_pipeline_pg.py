"""C1.6: the investigation pipeline end to end on PostgreSQL with a scripted model.

Real ADK (Workflow, AgentTool, callbacks, DatabaseSessionService in schema adk), real tools against a
fake Loki and the scratch PostgreSQL database, real validator, real audit writer. Also the budget and
timeout mappings, and the proof that the run-wide ceiling trips on a specialist's call made through
AgentTool (which RunConfig.max_llm_calls does not count).
"""

import os

import pytest
import pytest_asyncio

pytest.importorskip("google.adk")

from src.investigation.agent.runtime import (  # noqa: E402
    APP_NAME,
    AgentInvestigator,
    OUTCOME_BUDGET,
    classify_failure,
)
from src.investigation.agent.audit import AgentRunRecord  # noqa: E402
from src.investigation.agent.tools import ToolDeps, configure_tools  # noqa: E402
from src.storage.database import Database  # noqa: E402
from tests.agent.agent_fixtures import DatabaseSpy, FakeLoki, make_packet, traffic_line  # noqa: E402
from tests.agent.fake_llm import FakeLlm, call, json_answer, text  # noqa: E402
from tests.agent.scenario import happy_script, settings_for, writer_object  # noqa: E402

TEST_PG_URL = os.getenv("TEST_DATABASE_URL", "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test")
SERVICE_TABLES = ("incidents", "incident_revisions", "notification_outbox", "jobs", "model_runs", "selected_events", "episodes")


@pytest_asyncio.fixture
async def pg():
    db = Database(TEST_PG_URL)
    await db.connect()
    async with db._pg_pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE agent_runs, agent_events, shadow_assessments CASCADE")
    yield db
    await db.close()


def _loki(packet):
    from src.investigation.agent.tools import session_state_for

    end = session_state_for(packet)["window_end_ns"]
    return FakeLoki([(end - (5 - i) * 1_000_000_000, traffic_line(i)) for i in range(5)])


async def _counts(db):
    return {t: (await db.fetch_one(f"SELECT COUNT(*) AS n FROM {t}"))["n"] for t in SERVICE_TABLES}


async def test_pipeline_end_to_end_on_postgresql(pg):
    packet = make_packet("INC-C1-PIPE-0001", 2)
    ev_id = packet.evidence_events[0]["id"]
    model = FakeLlm(happy_script(packet, ev_id))
    inv = AgentInvestigator(settings_for(TEST_PG_URL), pg, _loki(packet), model=model)
    # The audit writer (the runtime's) keeps the real database; the tools read through the spy.
    spy = DatabaseSpy(pg)
    configure_tools(ToolDeps(loki=_loki(packet), selector='{service_name="forticlient"}', db=spy))
    before = await _counts(pg)
    try:
        result = await inv.investigate(packet, "shadow")
    finally:
        await inv.close()

    # The master called both specialists once, in order, and the writer ran last.
    assert model.agents_called() == [
        "incident_investigator", "evidence_agent", "evidence_agent",
        "incident_investigator", "context_agent", "context_agent",
        "incident_investigator", "assessment_writer",
    ]
    assert result.outcome == "VALID", result.reason_codes
    a = result.assessment
    assert a.assessment_source == "MODEL_VALIDATED"
    assert (a.incident_id, a.incident_revision, a.severity) == ("INC-C1-PIPE-0001", 2, "CRITICAL")
    assert a.recommended_action_ids == ["ACT_INSPECT_APPLICATION_LOGS"] and a.cve_references == ["CVE-2021-44228"]
    assert a.findings[0].evidence_ids == [ev_id]

    # The writer received the master's notes through {investigation_notes}.
    writer_req = next(r["request"] for r in model.requests if r["agent"] == "assessment_writer")
    assert f"OBSERVED: one IPS detection" in str(writer_req.config.system_instruction)

    # The evidence agent's tool results reached its second model call, clamped and delimited.
    seen = {s["name"]: s["response"] for s in model.tool_results_seen("evidence_agent")}
    assert seen["query_traffic_context"]["minutes_before"] == 30  # 45 was clamped by the callback
    assert seen["get_incident_packet"]["evidence"][0]["data"].startswith(f"<<UNTRUSTED id={ev_id}>>")

    # agent_runs / agent_events rows on PostgreSQL.
    run = await pg.fetch_one("SELECT * FROM agent_runs WHERE id = $1", result.run_id)
    assert run["session_id"] == "INC-C1-PIPE-0001:2" and run["mode"] == "shadow" and run["outcome"] == "VALID"
    assert run["total_llm_calls"] == 8 and run["total_tool_calls"] == 9
    assert run["input_tokens"] == 800 and run["output_tokens"] == 160 and run["adk_version"] == "2.11.0"
    events = await pg.fetch_all("SELECT * FROM agent_events WHERE run_id = $1 ORDER BY seq", result.run_id)
    assert [e["seq"] for e in events] == list(range(1, 18))
    assert sum(e["kind"] == "llm" for e in events) == 8 and sum(e["kind"] == "tool" for e in events) == 9
    tools = sorted(e["tool_name"] for e in events if e["kind"] == "tool")
    assert tools == sorted([
        "evidence_agent", "context_agent", "get_incident_packet", "query_traffic_context",
        "lookup_asset", "lookup_asset", "lookup_signature", "recent_incidents_for_source", "get_action_catalog",
    ])
    assert all(e["request_hash"] for e in events if e["kind"] == "llm") and not any(e["refused"] for e in events)

    # ADK's own session row lives in schema adk under <incident>:<revision>.
    session = await pg.fetch_one("SELECT id, app_name FROM adk.sessions WHERE id = $1", "INC-C1-PIPE-0001:2")
    assert session == {"id": "INC-C1-PIPE-0001:2", "app_name": APP_NAME}

    # Agents never write: the tools sent only SELECTs, and no service table changed.
    assert spy.writes() == [] and spy.statements
    assert await _counts(pg) == before


async def test_specialist_call_via_agent_tool_trips_the_run_wide_budget(pg):
    """RunConfig(max_llm_calls) does not count AgentTool calls (C.0); the callback counter does."""
    packet = make_packet("INC-C1-BUDGET-0001", 2)
    model = FakeLlm(happy_script(packet, packet.evidence_events[0]["id"]))
    inv = AgentInvestigator(settings_for(TEST_PG_URL, agent_max_llm_calls=4), pg, _loki(packet), model=model)
    try:
        result = await inv.investigate(packet, "shadow")
    finally:
        await inv.close()

    # Calls 1-4: master, evidence, evidence, master. Call 5 is context_agent's, inside an AgentTool
    # run, where ADK's own counter for the master's invocation stands at 2 of 4.
    assert model.agents_called() == ["incident_investigator", "evidence_agent", "evidence_agent", "incident_investigator"]
    assert result.outcome == OUTCOME_BUDGET and result.reason_codes == ["AGENT_BUDGET_EXHAUSTED"]
    assert result.assessment.assessment_source == "MODEL_REJECTED_FALLBACK"
    assert "AGENT_BUDGET_EXHAUSTED" in result.assessment.summary
    assert result.assessment.severity == packet.deterministic_severity_floor

    run = await pg.fetch_one("SELECT * FROM agent_runs WHERE id = $1", result.run_id)
    assert run["outcome"] == "BUDGET_EXHAUSTED" and list(run["reason_codes"]) == ["AGENT_BUDGET_EXHAUSTED"] and run["total_llm_calls"] == 4
    last = await pg.fetch_one("SELECT * FROM agent_events WHERE run_id = $1 ORDER BY seq DESC LIMIT 1", result.run_id)
    assert (last["agent_name"], last["kind"], last["refused"]) == ("context_agent", "llm", True)


async def test_timeout_maps_to_agent_timeout(pg):
    packet = make_packet("INC-C1-TIMEOUT-0001", 2)
    model = FakeLlm(happy_script(packet, packet.evidence_events[0]["id"]), delays={"evidence_agent": 5.0})
    inv = AgentInvestigator(settings_for(TEST_PG_URL, agent_timeout_seconds=0.5), pg, _loki(packet), model=model)
    try:
        result = await inv.investigate(packet, "live")
    finally:
        await inv.close()
    assert result.outcome == "TIMEOUT" and result.reason_codes == ["AGENT_TIMEOUT"]
    assert result.assessment.assessment_source == "MODEL_REJECTED_FALLBACK"
    assert result.latency_ms < 3000
    run = await pg.fetch_one("SELECT outcome, mode, reason_codes FROM agent_runs WHERE id = $1", result.run_id)
    assert (run["outcome"], run["mode"], list(run["reason_codes"])) == ("TIMEOUT", "live", ["AGENT_TIMEOUT"])


async def test_writer_output_that_fails_the_schema_maps_to_agent_schema_invalid(pg):
    packet = make_packet("INC-C1-SCHEMA-0001", 2)
    ev_id = packet.evidence_events[0]["id"]
    script = happy_script(packet, ev_id, writer=writer_object(packet, ev_id, severity="APOCALYPTIC"))
    model = FakeLlm(script)
    inv = AgentInvestigator(settings_for(TEST_PG_URL), pg, _loki(packet), model=model)
    try:
        result = await inv.investigate(packet, "shadow")
    finally:
        await inv.close()
    assert result.outcome == "SCHEMA_INVALID" and result.reason_codes == ["AGENT_SCHEMA_INVALID"]
    assert result.assessment.assessment_source == "MODEL_REJECTED_FALLBACK"


async def test_validator_hard_reject_falls_back_with_its_reason_codes(pg):
    packet = make_packet("INC-C1-REJECT-0001", 2)
    ev_id = packet.evidence_events[0]["id"]
    script = happy_script(packet, ev_id, writer=writer_object(packet, ev_id, summary="Confirmed compromise of the VIP."))
    inv = AgentInvestigator(settings_for(TEST_PG_URL), pg, _loki(packet), model=FakeLlm(script))
    try:
        result = await inv.investigate(packet, "shadow")
    finally:
        await inv.close()
    assert result.outcome == "REJECTED"
    assert result.reason_codes[0] == "AGENT_VALIDATION_REJECTED" and "FORBIDDEN_CLAIM_UNGROUNDED" in result.reason_codes
    assert "FORBIDDEN_CLAIM_UNGROUNDED" in result.validation_reason_codes
    assert result.assessment.assessment_source == "MODEL_REJECTED_FALLBACK"


async def test_retried_revision_replaces_the_adk_session(pg):
    packet = make_packet("INC-C1-RETRY-0001", 2)
    ev_id = packet.evidence_events[0]["id"]
    for _ in range(2):
        inv = AgentInvestigator(settings_for(TEST_PG_URL), pg, _loki(packet), model=FakeLlm(happy_script(packet, ev_id)))
        try:
            assert (await inv.investigate(packet, "shadow")).outcome == "VALID"
        finally:
            await inv.close()
    rows = await pg.fetch_all("SELECT id FROM adk.sessions WHERE id = $1", "INC-C1-RETRY-0001:2")
    assert len(rows) == 1
    assert len(await pg.fetch_all("SELECT id FROM agent_runs WHERE session_id = $1", "INC-C1-RETRY-0001:2")) == 2


def test_adk_llm_calls_limit_error_is_the_budget_signal_even_when_wrapped():
    from google.adk.agents.invocation_context import LlmCallsLimitExceededError

    record = AgentRunRecord("I", 1, "I:1", "shadow", "m", 8, 100)
    try:
        try:
            raise LlmCallsLimitExceededError("Max number of llm calls limit of `8` exceeded")
        except LlmCallsLimitExceededError as inner:
            raise RuntimeError("Dynamic node investigation failed") from inner
    except RuntimeError as wrapped:
        assert classify_failure(wrapped, record) == OUTCOME_BUDGET
    assert classify_failure(RuntimeError("boom"), record) == "ERROR"
