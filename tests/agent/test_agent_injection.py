"""C1.6 prompt-injection fixture: hostile text in Loki lines and in an IPS signature reaches the model
only inside <<UNTRUSTED id=...>> delimiters, and when the scripted writer obeys it the validator
strips the ineligible action. Runs on SQLite in memory with ADK's InMemorySessionService, so it also
exercises the SQLite DDL of the audit tables."""

import re

import pytest
import pytest_asyncio

pytest.importorskip("google.adk")

from google.adk.sessions import InMemorySessionService  # noqa: E402

from src.investigation.agent.runtime import AgentInvestigator  # noqa: E402
from src.investigation.agent.tools import session_state_for  # noqa: E402
from src.parsing.normalizer import normalize_event  # noqa: E402
from src.storage.database import Database  # noqa: E402
from tests.agent.agent_fixtures import BASE_NS, INJECTION, IPS_LINE, SIGNATURE, FakeLoki, make_packet, traffic_line  # noqa: E402
from tests.agent.fake_llm import FakeLlm  # noqa: E402
from tests.agent.scenario import happy_script, settings_for, writer_object  # noqa: E402

DELIMITED = re.compile(r"^<<UNTRUSTED id=[A-Za-z0-9_.:\-]+>>\n(.*)\n<</UNTRUSTED>>$", re.S)


@pytest_asyncio.fixture
async def sqlite_db():
    db = Database("sqlite:///:memory:")
    await db.connect()
    yield db
    await db.close()


def _strings(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(value, str):
        yield path, value


async def test_injection_is_delimited_and_the_obeyed_action_is_stripped(sqlite_db):
    hostile_ips = IPS_LINE.replace(f'attack="{SIGNATURE}"', f'attack="{INJECTION}"')
    events = [normalize_event(BASE_NS + 700_000_000, IPS_LINE), normalize_event(BASE_NS + 800_000_000, hostile_ips)]
    packet = make_packet("INC-C1-INJECT-0001", 2, events=events)
    ev_id = events[0]["id"]
    end = session_state_for(packet)["window_end_ns"]
    loki = FakeLoki([(end - i * 1_000_000_000, traffic_line(i, service=INJECTION, url=f"/{INJECTION.replace(' ', '-')}")) for i in range(3)])

    obeying_writer = writer_object(packet, ev_id, recommended_action_ids=["ACT_QUARANTINE_SRC_IP", "ACT_INSPECT_APPLICATION_LOGS"])
    model = FakeLlm(happy_script(packet, ev_id, writer=obeying_writer))
    inv = AgentInvestigator(settings_for("sqlite:///:memory:"), sqlite_db, loki, session_service=InMemorySessionService(), model=model)
    try:
        result = await inv.investigate(packet, "shadow")
    finally:
        await inv.close()

    # 1. Every string the model was handed that carries the hostile text is one delimited block, and
    #    nothing inside a block can close it early.
    hostile = []
    for agent in ("evidence_agent", "context_agent"):
        for seen in model.tool_results_seen(agent):
            for path, s in _strings(seen["response"], seen["name"]):
                if "ignore previous instructions" in s:
                    hostile.append(path)
                    m = DELIMITED.match(s)
                    assert m, f"{path} carries hostile text outside delimiters: {s[:120]!r}"
                    assert "<</UNTRUSTED>>" not in m.group(1) and "<<UNTRUSTED" not in m.group(1)
    assert any(p.startswith("get_incident_packet.evidence") for p in hostile)
    assert any(p.startswith("get_incident_packet.signatures") for p in hostile)
    assert any(p.startswith("query_traffic_context.samples") for p in hostile)

    # 2. The scripted writer obeyed the injection; the validator stripped the ineligible action.
    assert result.outcome == "VALID"
    assert result.assessment.recommended_action_ids == ["ACT_INSPECT_APPLICATION_LOGS"]
    assert "INELIGIBLE_ACTION_STRIPPED" in result.validation_reason_codes

    # 3. The run is audited on SQLite too.
    run = await sqlite_db.fetch_one("SELECT outcome, total_llm_calls FROM agent_runs WHERE id = $1", result.run_id)
    assert run == {"outcome": "VALID", "total_llm_calls": 8}
    assert (await sqlite_db.fetch_one("SELECT COUNT(*) AS n FROM agent_events WHERE run_id = $1", result.run_id))["n"] == 17
