"""C2.2 on PostgreSQL: scripts/export_golden_incident.py turns one investigated incident (its ADK
session, its committed revision, its recent same-source incidents) into a redacted EvalSet that ADK
loads, that carries no site address, host or incident id, and that the investigator runs VALID
against the scripted fake vLLM."""

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
import httpx
import pytest
import pytest_asyncio

pytest.importorskip("google.adk")

from google.adk.evaluation.eval_set import EvalSet  # noqa: E402
from google.adk.integrations.openai import OpenAILlm  # noqa: E402
from google.adk.sessions import DatabaseSessionService  # noqa: E402
from openai import AsyncOpenAI  # noqa: E402

from src.investigation.agent.evaluation import EVAL_FIXTURE_KEY, FixtureLoki  # noqa: E402
from src.investigation.agent.runtime import APP_NAME, USER_ID, AgentInvestigator, adk_session_db  # noqa: E402
from src.investigation.agent.tools import session_state_for  # noqa: E402
from src.investigation.schemas import IncidentPacket, WriterAssessment  # noqa: E402
from src.storage.database import Database  # noqa: E402
from tests.agent.agent_fixtures import make_packet  # noqa: E402
from tests.agent.scenario import settings_for  # noqa: E402
from tests.e2e import fake_endpoints  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "export_golden_incident.py"
TEST_PG_URL = os.getenv("TEST_DATABASE_URL", "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test")
# The repository's existing placeholder site addresses (config/assets.yaml VIP and the e2e internal
# host), standing in for real ones: the export must replace them.
SITE_SOURCE, SITE_TARGET = "10.0.1.50", "10.0.14.120"
INCIDENT, EARLIER, OLDER = "INC-EXPORT-TEST-1", "INC-EXPORT-TEST-0", "INC-EXPORT-TEST-OLD"

spec = importlib.util.spec_from_file_location("export_golden_incident", SCRIPT)
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


@pytest_asyncio.fixture
async def seeded():
    db = Database(TEST_PG_URL)
    await db.connect()  # migrations
    await db.close()
    packet = make_packet(INCIDENT, 2).model_copy(update={"source_ip": SITE_SOURCE, "target_ip": SITE_TARGET})
    state = session_state_for(packet)
    state["investigation_notes"] = f"notes about {SITE_TARGET}"  # written by the run; must not be exported
    state["assessment_json"] = {"summary": "the agent's answer"}
    url, kwargs = adk_session_db(settings_for(TEST_PG_URL))
    sessions = DatabaseSessionService(db_url=url, **kwargs)
    session_id = f"{INCIDENT}:2"
    if await sessions.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id):
        await sessions.delete_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id)
    await sessions.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id, state=state)
    await sessions.close()

    ev_id = packet.evidence_events[0]["id"]
    legacy = {
        "incident_id": INCIDENT, "incident_revision": 2, "visibility_scope": "FIREWALL_ONLY", "severity": "CRITICAL",
        "attack_category": "EXPLOITATION_ATTEMPT", "exploitation_assessment": "ATTEMPT_OBSERVED", "enforcement": packet.enforcement,
        "summary": f"Log4j attempt from {SITE_SOURCE} against {SITE_TARGET}.",
        "findings": [{"kind": "OBSERVATION", "statement": f"IPS detected the exploit against {SITE_TARGET}.", "evidence_ids": [ev_id]}],
        "cve_references": ["CVE-2021-44228"], "visibility_gaps": [], "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"],
        "analyst_follow_up": [], "model_reported_enforcement": None, "assessment_source": "MODEL_VALIDATED",
    }
    last_seen = datetime.fromtimestamp(state["window_end_ns"] / 1e9, tz=timezone.utc)
    conn = await asyncpg.connect(TEST_PG_URL)
    try:
        await conn.execute("DELETE FROM incident_revisions WHERE incident_id LIKE 'INC-EXPORT-TEST-%'")
        await conn.execute("DELETE FROM incidents WHERE id LIKE 'INC-EXPORT-TEST-%'")
        for inc_id, seen in ((INCIDENT, last_seen), (EARLIER, last_seen - timedelta(hours=3)), (OLDER, last_seen - timedelta(hours=30))):
            await conn.execute(
                "INSERT INTO incidents (id, severity, enforcement, source_ip, target_ip, first_seen, last_seen, deterministic_rule_ids) "
                "VALUES ($1, 'CRITICAL', 'ALLOWED_OR_DETECTED', $2, $3, $4, $4, $5)",
                inc_id, SITE_SOURCE, SITE_TARGET, seen, ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
            )
        await conn.execute(
            "INSERT INTO incident_revisions (incident_id, revision, severity, enforcement, assessment_json, assessment_source) "
            "VALUES ($1, 2, 'CRITICAL', 'ALLOWED_OR_DETECTED', $2::jsonb, 'MODEL_VALIDATED')",
            INCIDENT, json.dumps(legacy),
        )
    finally:
        await conn.close()
    yield packet
    conn = await asyncpg.connect(TEST_PG_URL)
    try:
        await conn.execute("DELETE FROM incident_revisions WHERE incident_id LIKE 'INC-EXPORT-TEST-%'")
        await conn.execute("DELETE FROM incidents WHERE id LIKE 'INC-EXPORT-TEST-%'")
        await conn.execute("DELETE FROM adk.sessions WHERE id = $1", session_id)
    finally:
        await conn.close()


def _export(*args):
    env = dict(os.environ, DATABASE_URL=TEST_PG_URL)
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)


async def test_export_is_a_redacted_evalset_that_runs_valid(seeded):
    out = _export(INCIDENT, "2", "--name", "lab_case")
    assert out.returncode == 0, out.stderr
    text = out.stdout
    eval_set = EvalSet.model_validate_json(text)
    case = eval_set.eval_cases[0]
    state = case.session_input.state

    # No site data: addresses, URL host, incident ids; nothing the run wrote into the session.
    assert export.leaks(text) == []
    for site in (SITE_SOURCE, SITE_TARGET, "victim.example", INCIDENT, EARLIER, "supersecret"):
        assert site not in text, site
    assert "investigation_notes" not in state and "assessment_json" not in state
    lab_id = export.lab_incident_id(INCIDENT)
    assert (state["incident_id"], state["source_ip"], state["target_ip"]) == (lab_id, "198.51.100.10", "192.0.2.10")
    packet = IncidentPacket.model_validate(state["packet"])
    assert (packet.incident_id, packet.source_ip, packet.target_ip) == (lab_id, "198.51.100.10", "192.0.2.10")
    assert packet.evidence_events[0]["url"].startswith("https://redacted.example/")

    # The fixture: the earlier same-source incident (pseudonymized), not the one older than 24 h.
    fixture = state[EVAL_FIXTURE_KEY]
    assert fixture["traffic_lines"] == []
    assert [(r["id"], r["source_ip"], r["target_ip"]) for r in fixture["recent_incidents"]] == [
        (export.lab_incident_id(EARLIER), "198.51.100.10", "192.0.2.10")
    ]

    # The reference is the committed assessment, pseudonymized, in the writer's schema.
    reference = WriterAssessment.model_validate_json(case.conversation[0].final_response.parts[0].text)
    assert reference.incident_id == lab_id and "198.51.100.10" in reference.summary and "192.0.2.10" in reference.summary
    assert [t.name for t in case.conversation[0].intermediate_data.tool_uses] == ["evidence_agent", "context_agent"]

    # And it is usable: the investigator runs it VALID against the scripted fake vLLM.
    transport = httpx.ASGITransport(app=fake_endpoints.app)
    client = AsyncOpenAI(base_url="http://fake-vllm.test/v1", api_key="EMPTY", max_retries=0,
                         http_client=httpx.AsyncClient(transport=transport, base_url="http://fake-vllm.test"))
    fake_endpoints.state.reset()
    db = Database(TEST_PG_URL)
    await db.connect()
    inv = AgentInvestigator(settings_for(TEST_PG_URL), db, FixtureLoki(fixture["traffic_lines"]),
                            model=OpenAILlm(model="scripted-fake", client=client))
    try:
        result = await inv.investigate(packet, "shadow")
    finally:
        await inv.close()
        await db.close()
    assert result.outcome == "VALID", result.reason_codes


def test_export_refuses_missing_sessions_and_reports_leaks(seeded):
    missing = _export("INC-EXPORT-TEST-NONE", "2")
    assert missing.returncode == 1 and "no ADK session" in missing.stderr and missing.stdout == ""
    assert export.leaks(f'{{"a": "{SITE_TARGET}", "b": "app.example.internal", "c": "203.0.113.9", "d": "2001:db8::1"}}') == [
        SITE_TARGET, "app.example.internal"
    ]
    pseudo = export.Pseudonymizer()
    assert pseudo.map(SITE_SOURCE, "source") == "198.51.100.10" and pseudo.map(SITE_TARGET, "target") == "192.0.2.10"
    # Whole addresses, wherever they stand (end of a sentence, after a letter); documentation
    # addresses stay; a longer dotted number is not an address and is not cut in two.
    assert pseudo.apply(f"to {SITE_TARGET}. v{SITE_SOURCE} 203.0.113.9 {SITE_TARGET}.7") == (
        f"to 192.0.2.10. v198.51.100.10 203.0.113.9 {SITE_TARGET}.7"
    )
