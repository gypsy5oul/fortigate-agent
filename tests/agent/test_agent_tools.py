"""C1.2 tool contracts, without a model: bounds, refusals, identity binding, redaction, read-only.

Each tool is called directly with a ToolContext stand-in whose state is what the runtime puts in an
ADK session. The read-only check runs every tool against PostgreSQL through a spy that records each
statement, and asserts no INSERT, UPDATE or DELETE (or any other write) was issued.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

pytest.importorskip("google.adk")

from src.investigation.agent import tools  # noqa: E402
from src.investigation.agent.tools import (  # noqa: E402
    ToolDeps,
    configure_tools,
    get_action_catalog,
    get_incident_packet,
    lookup_asset,
    lookup_signature,
    query_traffic_context,
    recent_incidents_for_source,
    session_state_for,
)
from src.storage.database import Database  # noqa: E402
from src.storage.repository import Repository  # noqa: E402
from tests.agent.agent_fixtures import (  # noqa: E402
    INJECTION,
    OTHER_IP,
    SIGNATURE,
    SOURCE_IP,
    TARGET_IP,
    DatabaseSpy,
    FakeLoki,
    FakeToolContext,
    make_packet,
    traffic_line,
)

TEST_PG_URL = os.getenv("TEST_DATABASE_URL", "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test")


@pytest.fixture
def state():
    return session_state_for(make_packet())


@pytest.fixture(autouse=True)
def reset_deps():
    yield
    configure_tools(ToolDeps())


def ctx(state, agent="evidence_agent"):
    return FakeToolContext(state=state, agent_name=agent)


def staged_traffic(state, n, **kw):
    """n traffic lines inside the incident window, newest last."""
    end = state["window_end_ns"]
    return [(end - (n - i) * 1_000_000_000, traffic_line(i, **kw)) for i in range(n)]


# ---------------------------------------------------------------------------------------------
# get_incident_packet
# ---------------------------------------------------------------------------------------------


def test_packet_identity_comes_from_session_state_and_evidence_is_redacted(state):
    state["packet"]["incident_id"] = "INC-SPOOFED"  # a packet field never overrides the bound identity
    out = get_incident_packet(ctx(state))
    assert out["status"] == "success"
    assert (out["incident_id"], out["revision"], out["source_ip"], out["target_ip"]) == ("INC-C1-TEST-0001", 2, SOURCE_IP, TARGET_IP)
    assert out["deterministic_rule_ids"] == ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"]
    assert out["deterministic_severity_floor"] == "CRITICAL"
    assert out["enforcement_counts"] == {"ALLOWED_OR_DETECTED": 1}
    assert out["evidence_ids"] and out["evidence_ids"][0] == out["evidence"][0]["id"]
    blob = json.dumps(out)
    assert "raw_message" not in blob and "supersecret" not in blob  # raw line dropped, URL query value redacted
    assert "token=<redacted>" in blob


def test_packet_tool_reports_missing_identity_instead_of_raising():
    out = get_incident_packet(ctx({"packet": {}}))
    assert out == {"status": "error", "reason": "incident identity missing from session state"}


# ---------------------------------------------------------------------------------------------
# query_traffic_context
# ---------------------------------------------------------------------------------------------


async def test_traffic_context_uses_the_profile_and_only_the_incidents_ips(state):
    loki = FakeLoki(staged_traffic(state, 5) + staged_traffic(state, 3, src=OTHER_IP, dst=OTHER_IP))
    configure_tools(ToolDeps(loki=loki, selector='{service_name="forticlient"}'))

    to_target = await query_traffic_context("to_target", 10, ctx(state))
    from_source = await query_traffic_context("from_source", 10, ctx(state))

    assert [c["query"] for c in loki.calls] == [
        f'{{service_name="forticlient"}} |= "type=\\"traffic\\"" |= "dstip={TARGET_IP}"',
        f'{{service_name="forticlient"}} |= "type=\\"traffic\\"" |= "srcip={SOURCE_IP}"',
    ]
    assert all(c["limit"] == 200 for c in loki.calls)
    assert to_target["status"] == from_source["status"] == "success"
    assert to_target["events_parsed"] == 5 and to_target["counts_by_action"] == {"BLOCKED": 5}
    assert sum(to_target["counts_by_dstport"].values()) == 5
    assert to_target["first_seen"] < to_target["last_seen"]
    assert to_target["query_profile"] == "traffic_context@v1"


@pytest.mark.parametrize("minutes, expected", [(0, 1), (-5, 1), (7, 7), (30, 30), (999, 30)])
async def test_traffic_context_clamps_minutes_before(state, minutes, expected):
    loki = FakeLoki([])
    configure_tools(ToolDeps(loki=loki))
    out = await query_traffic_context("to_target", minutes, ctx(state))
    assert out["minutes_before"] == expected
    call = loki.calls[0]
    assert call["end_ns"] == state["window_end_ns"]
    assert state["window_start_ns"] - call["start_ns"] == expected * 60 * 1_000_000_000


async def test_traffic_context_keeps_only_the_exact_incident_ip(state):
    """LogQL |= is a substring match (a filter on dstip=192.0.2.15 also returns dstip=192.0.2.150 lines), so
    lines Loki returns can belong to another host. They are parsed but not counted."""
    near_miss = TARGET_IP[:-1]  # 192.0.2.15, a different host whose address is a prefix of the target's
    lines = staged_traffic(state, 2) + staged_traffic(state, 3, dst=near_miss)
    # The fake Loki is told the near-miss lines match the filter, as real Loki would for a prefix of the address.
    loki = FakeLoki([(ts, line.replace(f"dstip={near_miss} ", f"dstip={near_miss} x=dstip={TARGET_IP} ")) for ts, line in lines])
    configure_tools(ToolDeps(loki=loki))
    out = await query_traffic_context("to_target", 5, ctx(state))
    assert out["lines_returned"] == 5 and out["events_parsed"] == 2


async def test_traffic_context_refuses_an_unknown_direction_without_querying(state):
    loki = FakeLoki([])
    configure_tools(ToolDeps(loki=loki))
    out = await query_traffic_context("any_ip", 5, ctx(state))
    assert out["status"] == "refused" and not loki.calls


async def test_traffic_context_caps_lines_and_samples_and_redacts(state):
    url = "https://victim.example/login?password=hunter2&user=bob"
    loki = FakeLoki(staged_traffic(state, 300, url=url))
    configure_tools(ToolDeps(loki=loki))
    out = await query_traffic_context("to_target", 30, ctx(state))
    assert out["lines_returned"] == 200 and out["events_parsed"] == 200
    assert len(out["samples"]) == 20
    blob = json.dumps(out)
    assert "hunter2" not in blob and "raw_message" not in blob
    assert all(s["id"].startswith("TC-") for s in out["samples"])


async def test_traffic_context_reports_loki_failure_without_raising(state):
    configure_tools(ToolDeps(loki=FakeLoki(fail=True)))
    out = await query_traffic_context("from_source", 5, ctx(state))
    assert out == {"status": "error", "reason": "traffic context query failed (RuntimeError)"}


# ---------------------------------------------------------------------------------------------
# lookup_asset, lookup_signature, get_action_catalog
# ---------------------------------------------------------------------------------------------


def test_lookup_asset_answers_only_for_the_incidents_ips(state):
    target = lookup_asset(TARGET_IP, ctx(state, "context_agent"))
    source = lookup_asset(SOURCE_IP, ctx(state, "context_agent"))
    other = lookup_asset(OTHER_IP, ctx(state, "context_agent"))
    assert target["status"] == "success" and target["role"] == "target"
    assert target["target_asset"]["provenance"].startswith("config/assets.yaml")
    assert source["role"] == "source" and source["source_context"]["provenance"] == "Public unicast endpoint"
    assert other == {"status": "refused", "reason": "ip is not part of this incident"}


def test_lookup_signature_answers_only_for_the_packets_signatures(state):
    ok = lookup_signature(SIGNATURE, ctx(state, "context_agent"))
    assert ok["status"] == "success" and ok["cve_ids"] == ["CVE-2021-44228"] and ok["reviewed"] is True
    assert ok["provenance"] and ok["reviewed_at"]
    no = lookup_signature("OpenSSL.Heartbleed.Information.Disclosure", ctx(state, "context_agent"))
    assert no["status"] == "refused"


def test_action_catalog_is_the_deterministically_eligible_set(state):
    out = get_action_catalog(ctx(state, "context_agent"))
    ids = [a["id"] for a in out["eligible_actions"]]
    assert out["status"] == "success" and ids
    # No FortiOS build is configured, so the perimeter block actions are not eligible (B2).
    assert "ACT_QUARANTINE_SRC_IP" not in ids and "ACT_ADD_FIREWALL_BLOCKLIST" not in ids
    assert all(set(a) == {"id", "name", "risk", "requires_approval"} for a in out["eligible_actions"])


# ---------------------------------------------------------------------------------------------
# recent_incidents_for_source and the read-only guarantee (PostgreSQL)
# ---------------------------------------------------------------------------------------------


@pytest_asyncio.fixture
async def pg():
    db = Database(TEST_PG_URL)
    await db.connect()
    async with db._pg_pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE incidents, incident_revisions, jobs, notification_outbox CASCADE")
    yield db
    await db.close()


async def _seed_incident(repo, inc_id, src, last_seen):
    await repo.record_incident_transition(incident={
        "id": inc_id, "current_revision": 1, "status": "ACTIVE", "severity": "MEDIUM", "enforcement": "BLOCKED",
        "source_ip": src, "target_ip": TARGET_IP, "first_seen": last_seen, "last_seen": last_seen, "event_count": 1,
        "summary": "seed", "deterministic_rule_ids": ["RULE_PORT_SCAN_MULTI_SERVICE"],
    })


async def test_recent_incidents_same_source_last_24h_excluding_current(pg, state):
    repo = Repository(pg)
    anchor = datetime.fromtimestamp(state["window_end_ns"] / 1e9, tz=timezone.utc)
    await _seed_incident(repo, state["incident_id"], SOURCE_IP, anchor)  # the current incident
    for i in range(12):
        await _seed_incident(repo, f"INC-C1-RECENT-{i:02d}", SOURCE_IP, anchor - timedelta(hours=1, minutes=i))
    await _seed_incident(repo, "INC-C1-OLD", SOURCE_IP, anchor - timedelta(hours=30))
    await _seed_incident(repo, "INC-C1-OTHER-SRC", OTHER_IP, anchor - timedelta(hours=1))
    configure_tools(ToolDeps(db=pg))

    out = await recent_incidents_for_source(ctx(state, "context_agent"))
    ids = [r["id"] for r in out["incidents"]]
    assert out["status"] == "success" and len(ids) == 10
    assert ids == [f"INC-C1-RECENT-{i:02d}" for i in range(10)]  # newest first
    assert state["incident_id"] not in ids and "INC-C1-OLD" not in ids and "INC-C1-OTHER-SRC" not in ids
    assert out["incidents"][0]["rule_ids"] == ["RULE_PORT_SCAN_MULTI_SERVICE"]


async def test_no_tool_issues_a_write(pg, state):
    """The repository spy: every statement any tool sends is recorded; none may write."""
    repo = Repository(pg)
    anchor = datetime.fromtimestamp(state["window_end_ns"] / 1e9, tz=timezone.utc)
    await _seed_incident(repo, "INC-C1-SPY-PRIOR", SOURCE_IP, anchor - timedelta(hours=2))
    spy = DatabaseSpy(pg)
    configure_tools(ToolDeps(db=spy, loki=FakeLoki(staged_traffic(state, 4))))
    c = ctx(state, "context_agent")

    results = [
        get_incident_packet(c),
        await query_traffic_context("to_target", 5, c),
        await query_traffic_context("from_source", 5, c),
        lookup_asset(TARGET_IP, c),
        lookup_asset(OTHER_IP, c),
        lookup_signature(SIGNATURE, c),
        await recent_incidents_for_source(c),
        get_action_catalog(c),
    ]
    assert all(r["status"] in ("success", "refused") for r in results)
    assert spy.statements, "recent_incidents_for_source must have read through the spy"
    assert spy.writes() == []
    assert all(s.lstrip().upper().startswith("SELECT") for s in spy.statements)


async def test_select_guard_refuses_anything_but_select(pg):
    spy = DatabaseSpy(pg)
    with pytest.raises(PermissionError):
        await tools._select(spy, "DELETE FROM incidents")
    with pytest.raises(PermissionError):
        await tools._select(spy, "  update incidents set severity = 'LOW'")
    assert spy.statements == []


async def test_injection_text_from_loki_reaches_the_tool_result_as_data_only(state):
    """The raw tool result carries the hostile text; the after_tool_callback delimits it (see callbacks tests)."""
    configure_tools(ToolDeps(loki=FakeLoki(staged_traffic(state, 2, service=INJECTION))))
    out = await query_traffic_context("to_target", 5, ctx(state))
    assert out["samples"][0]["service"] == INJECTION
