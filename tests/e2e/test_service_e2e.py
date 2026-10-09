"""End-to-end integration tests driving the real python -m src.main process against PostgreSQL 16.

Uses fake external endpoints (FastAPI in isolated subprocess) for:
- Grafana Loki query_range API
- Local vLLM / OpenAI chat completions API
- Google Chat incoming webhook API
"""

import os
import re
import sys
import time
import json
import signal
import asyncio
import subprocess
import httpx
import pytest
import pytest_asyncio
import multiprocessing
import uvicorn
from typing import Dict, Any

from src.main import IntelligenceService
from src.storage.database import Database
from src.storage.repository import Repository
from tests.e2e.fake_endpoints import GOLDEN_SCENARIOS, INJECTION_TEXT, app as fake_app, generate_scenario_logs

TEST_PG_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test",
)
FAKE_PORT = 18880
FAKE_BASE_URL = f"http://127.0.0.1:{FAKE_PORT}"


def _run_fake_server_process(port: int):
    uvicorn.run(fake_app, host="127.0.0.1", port=port, log_level="warning")


@pytest_asyncio.fixture(scope="module")
async def fake_server():
    """Starts fake endpoints server in an isolated daemon process."""
    proc = multiprocessing.Process(target=_run_fake_server_process, args=(FAKE_PORT,), daemon=True)
    proc.start()

    # Wait until server is listening
    client = httpx.AsyncClient(timeout=2.0)
    for _ in range(60):
        try:
            resp = await client.get(f"{FAKE_BASE_URL}/capture")
            if resp.status_code == 200:
                break
        except Exception:
            pass
        await asyncio.sleep(0.05)
    await client.aclose()

    yield proc

    proc.terminate()
    proc.join(timeout=2.0)


@pytest_asyncio.fixture
async def pg_clean():
    """Ensures clean PostgreSQL state before each test."""
    db = Database(TEST_PG_URL)
    await db.connect()
    async with db._pg_pool.acquire() as conn:
        await conn.execute(
            """
            TRUNCATE TABLE selected_events, rejected_events, incidents,
                           incident_revisions, jobs, notification_outbox,
                           query_checkpoints, coverage_gaps, episodes, model_runs,
                           agent_runs, agent_events, shadow_assessments CASCADE;
            """
        )
    yield db
    await db.close()


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _child_env(metrics_port: int) -> Dict[str, str]:
    env = os.environ.copy()
    env["DATABASE_URL"] = TEST_PG_URL
    env["LOKI_BASE_URL"] = f"{FAKE_BASE_URL}/loki/api/v1/query_range"
    env["LOKI_TLS_VERIFY"] = "true"
    env["ALLOW_INSECURE_TLS"] = "true"
    env["LLM_BASE_URL"] = f"{FAKE_BASE_URL}/v1"
    env["LLM_ENABLED"] = "true"
    env["GCHAT_WEBHOOK_URL"] = f"{FAKE_BASE_URL}/chat"
    env["GCHAT_DRY_RUN"] = "false"
    env["LOKI_POLL_INTERVAL_SECONDS"] = "0.2"
    env["GCHAT_RATE_LIMIT_DELAY_SECONDS"] = "0.05"
    env["METRICS_PORT"] = str(metrics_port)
    return env


async def _run_service_then_sigterm(
    env: Dict[str, str], run_seconds: float, ready=None, module: str = "src.main", log_path=None
) -> float:
    """Runs the real ``python -m src.main`` for ``run_seconds``, sends SIGTERM and enforces
    the D4 contract: the process exits on its own, within 5 s, with exit code 0. The
    process is only killed to clean up after that assertion has already failed.

    With ``ready`` (an async callable returning a bool), SIGTERM is sent as soon as it returns True,
    and ``run_seconds`` is only the ceiling. ``module`` is the entry point (a test launcher may wrap
    src.main, e.g. tests.e2e.tool_spy_main). With ``log_path`` the process's stdout and stderr (its
    log) are written to that file so a test can assert on it."""
    log_file = open(log_path, "wb") if log_path is not None else None
    proc = subprocess.Popen(
        [sys.executable, "-m", module], env=env,
        stdout=log_file, stderr=subprocess.STDOUT if log_file is not None else None,
    )
    try:
        if ready is None:
            await asyncio.sleep(run_seconds)
        else:
            deadline = time.monotonic() + run_seconds
            while time.monotonic() < deadline and not await ready():
                await asyncio.sleep(0.25)
    finally:
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)
            pytest.fail("service did not exit within 5 s of SIGTERM")
        finally:
            if log_file is not None:
                log_file.close()
        shutdown_seconds = time.monotonic() - t0
    assert proc.returncode == 0, f"service exited with code {proc.returncode} after SIGTERM"
    return shutdown_seconds


async def _fake_capture() -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=5.0) as client:
        return (await client.get(f"{FAKE_BASE_URL}/capture")).json()


async def _fake_set_mode(**modes: Any) -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/set_mode", json=modes)


async def _scrape(metrics_port: int, path: str = "/metrics") -> str:
    """Body of an endpoint of the service under test, or "" while it is not (yet) answering."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"http://127.0.0.1:{metrics_port}{path}")
        return resp.text if resp.status_code == 200 else ""
    except httpx.HTTPError:
        return ""


@pytest.mark.asyncio
async def test_e2e_scenarios_and_service_lifecycle(fake_server, pg_clean):
    """Executes the real python -m src.main process against PostgreSQL 16 with fake external services.

    Validates:
    1. Real OS process lifecycle, startup validation, and signal termination
    2. Checkpoint monotonicity and progress
    3. Exact event counts stored in PostgreSQL
    4. Scenario 1 (Benign): No urgent alerts
    5. Scenario 2 (Non-blocked IPS): CRITICAL urgent alert + investigation completed (COMPLETED job, contiguous revisions [1, 2], INVESTIGATION_UPDATE outbox row)
    6. Scenario 3 (IPS-dropped exploit): BLOCKED enforcement, no urgent alert
    7. Scenario 4 (Internal AV blocked): DIGEST routing, no urgent alert
    8. Scenario 5 (Blocked scanner): MEDIUM DIGEST, no urgent alert
    9. Gating: No card payload contains ACT_QUARANTINE_SRC_IP
    10. Secret redaction: No token/key leaked
    11. HTML safety: Escaped cards
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")

        now_ns = time.time_ns()
        base_ts = now_ns - 25_000_000_000  # 25 seconds ago

        scenarios = generate_scenario_logs(base_ts)
        all_staged = []
        all_staged.extend(scenarios["scenario_1_benign"])
        all_staged.extend(scenarios["scenario_2_nonblocked_ips"])
        all_staged.extend(scenarios["scenario_3_blocked_exploit"])
        all_staged.extend(scenarios["scenario_4_internal_av_blocked"])
        all_staged.extend(scenarios["scenario_5_blocked_scanner"])

        await client.post(f"{FAKE_BASE_URL}/stage_logs", json=all_staged)
        expected_event_count = len(all_staged)

    # Real child process: run the supervised loops over the staged batch, then SIGTERM.
    # D4 acceptance: cooperative shutdown, exit code 0, no kill.
    await _run_service_then_sigterm(_child_env(18881), run_seconds=8.0)

    repo = Repository(pg_clean)

    # 1. Monotonic Checkpoint Progress
    latest_cp = await repo.get_checkpoint('{service_name="forticlient"}#security_events@v1')
    if latest_cp is None:
        latest_cp = await repo.get_checkpoint('{service_name="forticlient"}')
    assert latest_cp is not None
    assert latest_cp > 0

    # 2. Database Event Counts Equal Ground Truth (Zero accepted traffic mirrored per Brief B1)
    events_in_db = await pg_clean.fetch_all("SELECT id, raw_message FROM selected_events")
    accepted_rows = [e for e in events_in_db if 'action="accept"' in e["raw_message"] or 'action="close"' in e["raw_message"]]
    assert len(accepted_rows) == 0, f"Expected 0 accepted traffic rows in PostgreSQL, found {len(accepted_rows)}"
    assert len(events_in_db) == 15, f"Expected 15 security events in PostgreSQL, found {len(events_in_db)}"

    # 3. Verify Scenario 1: Benign host (10.0.1.5 -> 1.1.1.1)
    # No urgent incidents or alerts
    benign_inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '10.0.1.5'")
    if benign_inc:
        assert benign_inc["severity"] in ("LOW", "INFORMATIONAL")

    # 4. Verify Scenario 2: Non-blocked IPS detection (198.51.100.45 -> 10.0.14.120)
    # Expected: CRITICAL urgent alert + investigation completed
    nb_inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.45'")
    assert nb_inc is not None
    assert nb_inc["severity"] == "CRITICAL"
    assert nb_inc["enforcement"] in ("ALLOWED_OR_DETECTED", "MIXED")

    # Verify investigation job completed
    job_s2 = await pg_clean.fetch_one("SELECT * FROM jobs WHERE payload_json::text LIKE '%198.51.100.45%'")
    assert job_s2 is not None
    assert job_s2["status"] == "COMPLETED"

    # Verify INVESTIGATION_UPDATE outbox row exists
    nb_outbox = await pg_clean.fetch_all("SELECT * FROM notification_outbox WHERE incident_id = $1", nb_inc["id"])
    notif_types = {row["notification_type"] for row in nb_outbox}
    assert "URGENT" in notif_types
    assert "INVESTIGATION_UPDATE" in notif_types

    # Verify revisions are contiguous [1, 2]
    nb_revs = await pg_clean.fetch_all(
        "SELECT revision, assessment_source FROM incident_revisions WHERE incident_id = $1 ORDER BY revision ASC",
        nb_inc["id"]
    )
    assert len(nb_revs) == 2
    assert nb_revs[0]["revision"] == 1
    assert nb_revs[0]["assessment_source"] == "DETERMINISTIC"
    assert nb_revs[1]["revision"] == 2
    assert nb_revs[1]["assessment_source"] == "MODEL_VALIDATED"

    # 5. Verify Scenario 3: IPS-dropped exploit (198.51.100.46 -> 10.0.14.120)
    # Expected: No urgent alert
    drop_inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.46'")
    if drop_inc:
        assert drop_inc["enforcement"] == "BLOCKED"
        urgent_for_dropped = await pg_clean.fetch_all(
            "SELECT * FROM notification_outbox WHERE incident_id = $1 AND notification_type = 'URGENT'",
            drop_inc["id"]
        )
        assert len(urgent_for_dropped) == 0

    # 6. Verify Scenario 4: Internal AV blocked (10.0.1.50 -> 203.0.113.10)
    # Expected: Outbound blocked download, no urgent alert
    av_inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '10.0.1.50'")
    if av_inc:
        urgent_for_av = await pg_clean.fetch_all(
            "SELECT * FROM notification_outbox WHERE incident_id = $1 AND notification_type = 'URGENT'",
            av_inc["id"]
        )
        assert len(urgent_for_av) == 0

    # 7. Verify Scenario 5: Blocked scanner (198.51.100.99 -> 10.0.14.120)
    # Expected: Scanner matched, MEDIUM severity, no urgent alert
    scanner_inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.99'")
    assert scanner_inc is not None
    assert scanner_inc["severity"] == "MEDIUM"
    assert scanner_inc["enforcement"] == "BLOCKED"
    urgent_scanner = await pg_clean.fetch_all(
        "SELECT * FROM notification_outbox WHERE incident_id = $1 AND notification_type = 'URGENT'",
        scanner_inc["id"]
    )
    assert len(urgent_scanner) == 0

    # 8. Check captured chats via HTTP GET /capture
    async with httpx.AsyncClient(timeout=5.0) as client:
        cap_resp = await client.get(f"{FAKE_BASE_URL}/capture")
        capture = cap_resp.json().get("captured_chats", [])

    assert len(capture) >= 1

    for chat_card in capture:
        card_str = json.dumps(chat_card)
        # Assert no sensitive credentials leaked
        assert "key=" not in card_str
        assert "token=" not in card_str
        assert "password=" not in card_str
        # Verify HTML escaping
        assert "<script>" not in card_str
        # Verify ACT_QUARANTINE_SRC_IP is NOT recommended
        assert "ACT_QUARANTINE_SRC_IP" not in card_str


@pytest.mark.asyncio
async def test_e2e_model_outage_fallback(fake_server, pg_clean, monkeypatch):
    """When the local model endpoint fails, jobs retry with exponential backoff and
    gracefully write MODEL_REJECTED_FALLBACK without crashing the service.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
        await client.post(f"{FAKE_BASE_URL}/set_mode", json={"chat_response_mode": "timeout"})

        now_ns = time.time_ns()
        base_ts = now_ns - 10_000_000_000
        scenarios = generate_scenario_logs(base_ts)

        # Use the non-blocked exploit which triggers an investigation job
        await client.post(f"{FAKE_BASE_URL}/stage_logs", json=scenarios["scenario_2_nonblocked_ips"])

    monkeypatch.setenv("DATABASE_URL", TEST_PG_URL)
    monkeypatch.setenv("LOKI_BASE_URL", f"{FAKE_BASE_URL}/loki/api/v1/query_range")
    monkeypatch.setenv("LOKI_TLS_VERIFY", "true")
    monkeypatch.setenv("ALLOW_INSECURE_TLS", "true")
    monkeypatch.setenv("LLM_BASE_URL", f"{FAKE_BASE_URL}/v1")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "0.5")  # Quick timeout for test
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("GCHAT_DRY_RUN", "true")
    monkeypatch.setenv("LOKI_POLL_INTERVAL_SECONDS", "0.2")

    service = IntelligenceService()
    await service.db.connect()
    service.running = True

    poller_task = asyncio.create_task(service._run_poller_loop())

    # Wait for poller to create incident and job
    job_id = None
    for _ in range(25):
        jobs = await service.repo.db.fetch_all("SELECT * FROM jobs")
        if jobs:
            job_id = jobs[0]["id"]
            break
        await asyncio.sleep(0.2)

    assert job_id is not None, "Poller did not create an investigation job"

    # Lease and fail job through 3 attempts to trigger max_attempts
    for _ in range(3):
        leased = await service.repo.lease_next_job("test-e2e-worker", lease_duration_seconds=10)
        if leased:
            await service.repo.fail_job(job_id, leased["version_token"], "Simulated model outage")
            async with service.repo.db._pg_pool.acquire() as conn:
                await conn.execute("UPDATE jobs SET next_run_at = NOW() - interval '1 second' WHERE id = $1", job_id)

    service.running = False
    await poller_task
    await service.stop()

    # Job is FAILED and fallback revision is written
    failed_job = await pg_clean.fetch_one("SELECT * FROM jobs WHERE id = $1", job_id)
    assert failed_job["status"] == "FAILED"

    fallback = await pg_clean.fetch_one(
        "SELECT * FROM incident_revisions WHERE assessment_source = 'MODEL_REJECTED_FALLBACK'"
    )
    assert fallback is not None
    assert "MODEL_UNREACHABLE" in fallback["reasoning_summary"]


@pytest.mark.asyncio
async def test_e2e_restart_never_lowers_incident_severity(fake_server, pg_clean):
    """B.1 Defect A, end to end: run the real process, stop it with SIGTERM, stage new blocked
    probes from the source of the CRITICAL non-blocked exploit, restart on the same database,
    stop again. No incident's severity may decrease across the restart, and the exploit
    incident must absorb the new events while staying CRITICAL."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
        base_ts = time.time_ns() - 25_000_000_000
        scenarios = generate_scenario_logs(base_ts)
        staged = []
        staged.extend(scenarios["scenario_2_nonblocked_ips"])
        staged.extend(scenarios["scenario_5_blocked_scanner"])
        await client.post(f"{FAKE_BASE_URL}/stage_logs", json=staged)

    env = _child_env(18882)

    # Phase 1: ingest, alert, investigate; then a clean SIGTERM exit.
    await _run_service_then_sigterm(env, run_seconds=8.0)

    before = {
        row["id"]: row
        for row in await pg_clean.fetch_all("SELECT id, source_ip, severity, current_revision, event_count FROM incidents")
    }
    exploit_before = next(r for r in before.values() if r["source_ip"] == "198.51.100.45")
    assert exploit_before["severity"] == "CRITICAL"
    assert exploit_before["event_count"] == 1

    # Between the runs: three blocked probes on distinct services from the exploit source.
    # On their own these match only RULE_PORT_SCAN_MULTI_SERVICE (MEDIUM, DIGEST).
    # Timestamps 4 s in the past: the poller's query window ends 5 s behind wall-clock time
    # (query_end_delay), so probes stamped "now" only become visible several seconds into
    # the second run. The replay overlap keeps them inside the window either way.
    now_ns = time.time_ns()
    probes = []
    for i, (port, svc) in enumerate([(22, "SSH"), (3389, "RDP"), (8080, "HTTP-ALT")]):
        probes.append((
            now_ns - 4_000_000_000 + i * 10_000_000,
            f'date=2026-10-08 time=12:02:0{i} devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
            f'subtype="forward" level="notice" vd="root" sessionid={500001 + i} srcip=198.51.100.45 '
            f'srcport={46000 + i} dstip=10.0.14.120 dstport={port} proto=6 service="{svc}" action="deny" policyid=0',
        ))
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/stage_logs", json=probes)

    # Phase 2: restart on the same database (episodes and checkpoints restored), then SIGTERM.
    await _run_service_then_sigterm(env, run_seconds=10.0)

    after = {
        row["id"]: row
        for row in await pg_clean.fetch_all("SELECT id, source_ip, severity, deterministic_severity, current_revision, event_count, deterministic_rule_ids FROM incidents")
    }
    for inc_id, old in before.items():
        assert inc_id in after, f"incident {inc_id} disappeared across the restart"
        assert SEVERITY_RANK[after[inc_id]["severity"]] >= SEVERITY_RANK[old["severity"]], (
            f"incident {inc_id} ({old['source_ip']}) went from {old['severity']} to {after[inc_id]['severity']} across the restart"
        )

    exploit_after = after[exploit_before["id"]]
    assert exploit_after["severity"] == "CRITICAL"
    assert exploit_after["deterministic_severity"] == "CRITICAL"
    assert exploit_after["event_count"] == 4, "the three probes must join the restored episode"
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" in list(exploit_after["deterministic_rule_ids"])
    assert "RULE_PORT_SCAN_MULTI_SERVICE" in list(exploit_after["deterministic_rule_ids"])

    revisions = await pg_clean.fetch_all(
        "SELECT revision, severity, assessment_source FROM incident_revisions WHERE incident_id = $1 ORDER BY revision",
        exploit_before["id"],
    )
    assert revisions[0]["revision"] == 1
    assert all(r["severity"] == "CRITICAL" for r in revisions), [dict(r) for r in revisions]
    assert [r["revision"] for r in revisions] == list(range(1, len(revisions) + 1))


@pytest.mark.asyncio
async def test_e2e_shadow_mode_records_agent_runs_and_never_a_card(fake_server, pg_clean):
    """Phase C.1 exit (plan C1.8): the real process in INVESTIGATOR_MODE=shadow against the fake vLLM
    answering OpenAI tool_calls. The legacy single call still writes revision 2 and the
    INVESTIGATION_UPDATE card; the ADK pipeline then runs and leaves agent_runs, agent_events and
    shadow_assessments rows, and nothing else: no revision, no outbox row, no chat message."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
        scenarios = generate_scenario_logs(time.time_ns() - 25_000_000_000)
        await client.post(f"{FAKE_BASE_URL}/stage_logs", json=scenarios["scenario_2_nonblocked_ips"])

    env = _child_env(18883)
    env["INVESTIGATOR_MODE"] = "shadow"

    async def shadow_recorded() -> bool:
        row = await pg_clean.fetch_one(
            "SELECT (SELECT COUNT(*) FROM shadow_assessments) AS shadows, "
            "(SELECT COUNT(*) FROM notification_outbox WHERE status = 'PENDING') AS pending"
        )
        return row["shadows"] >= 1 and row["pending"] == 0

    await _run_service_then_sigterm(env, run_seconds=30.0, ready=shadow_recorded)

    inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.45'")
    assert inc is not None and inc["severity"] == "CRITICAL" and inc["current_revision"] == 2

    # Legacy path unchanged: revisions 1 (deterministic) and 2 (the single call), both cards.
    revs = await pg_clean.fetch_all(
        "SELECT revision, assessment_source, assessment_json FROM incident_revisions WHERE incident_id = $1 ORDER BY revision",
        inc["id"],
    )
    assert [(r["revision"], r["assessment_source"]) for r in revs] == [(1, "DETERMINISTIC"), (2, "MODEL_VALIDATED")]
    assert json.loads(revs[1]["assessment_json"])["summary"].startswith("Model analysis of exploit probe")
    outbox = await pg_clean.fetch_all(
        "SELECT revision, notification_type, payload_json FROM notification_outbox WHERE incident_id = $1 ORDER BY id", inc["id"]
    )
    assert [(o["revision"], o["notification_type"]) for o in outbox] == [(1, "URGENT"), (2, "INVESTIGATION_UPDATE")]
    job = await pg_clean.fetch_one("SELECT status, attempts FROM jobs WHERE id = $1", f"JOB-{inc['id']}-1")
    assert (job["status"], job["attempts"]) == ("COMPLETED", 1)
    model_runs = await pg_clean.fetch_all("SELECT revision, commit_status FROM model_runs WHERE incident_id = $1", inc["id"])
    assert [(m["revision"], m["commit_status"]) for m in model_runs] == [(2, "COMMITTED")]

    # The ADK pipeline ran in shadow and was audited.
    runs = await pg_clean.fetch_all("SELECT * FROM agent_runs WHERE incident_id = $1", inc["id"])
    assert len(runs) == 1
    run = runs[0]
    assert (run["revision"], run["mode"], run["session_id"]) == (2, "shadow", f"{inc['id']}:2")
    assert run["outcome"] == "VALID", list(run["reason_codes"])
    assert run["total_llm_calls"] == 8 and run["total_tool_calls"] >= 7
    events = await pg_clean.fetch_all("SELECT agent_name, kind, tool_name, refused FROM agent_events WHERE run_id = $1 ORDER BY seq", run["id"])
    assert sum(e["kind"] == "llm" for e in events) == 8
    assert {e["tool_name"] for e in events if e["kind"] == "tool"} >= {
        "evidence_agent", "context_agent", "get_incident_packet", "query_traffic_context",
        "lookup_asset", "lookup_signature", "recent_incidents_for_source", "get_action_catalog",
    }
    assert not any(e["refused"] for e in events)
    shadows = await pg_clean.fetch_all("SELECT * FROM shadow_assessments WHERE incident_id = $1", inc["id"])
    assert len(shadows) == 1
    shadow = shadows[0]
    assert (shadow["revision"], shadow["run_id"], shadow["assessment_source"]) == (2, run["id"], "MODEL_VALIDATED")
    assert shadow["severity_equal"] is True and shadow["exploitation_equal"] is True and shadow["action_set_equal"] is True
    assert shadow["findings_count"] == 1 and shadow["legacy_findings_count"] == 1
    assert json.loads(shadow["assessment_json"])["summary"].startswith("ADK shadow assessment")

    # The fake vLLM saw real tool-calling traffic from all four agents, and every chat message the
    # webhook received is one of the two legacy cards: none carries the shadow summary.
    async with httpx.AsyncClient(timeout=5.0) as client:
        capture = (await client.get(f"{FAKE_BASE_URL}/capture")).json()
    agents = {r["agent"] for r in capture["adk_requests"]}
    assert agents == {"incident_investigator", "evidence_agent", "context_agent", "assessment_writer"}
    assert any(r["answered_with"] != "text" for r in capture["adk_requests"])
    chats = [json.dumps(c) for c in capture["captured_chats"]]
    assert len(chats) == 2
    assert not any("ADK shadow assessment" in c for c in chats)
    assert not any("ADK shadow assessment" in json.dumps(o["payload_json"]) for o in outbox)


ADK_AGENTS = {"incident_investigator", "evidence_agent", "context_agent", "assessment_writer"}


async def _stage(scenario_key: str, seconds_ago: int = 25) -> Dict[str, Any]:
    """Stages one scenario's logs on the fake Loki, stamped ``seconds_ago`` in the past."""
    scenarios = generate_scenario_logs(time.time_ns() - seconds_ago * 1_000_000_000)
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/stage_logs", json=scenarios[scenario_key])
    return scenarios


@pytest.mark.asyncio
async def test_e2e_adk_mode_writes_the_agent_revision_through_the_same_transition(fake_server, pg_clean, tmp_path):
    """Phase C.3, deliverable 1: INVESTIGATOR_MODE=adk over the exploit scenario, real process, scripted
    fake vLLM. The ADK result is revision 2, committed through record_incident_transition with the
    same CAS and job fence as the legacy path, with a model_runs row kept for backward compatibility
    and an agent_runs row for the same revision (mode live), exactly one INVESTIGATION_UPDATE card,
    nothing in shadow_assessments, no request to the single-call path, and the SIGTERM contract (exit
    code 0 within 5 s, "Service terminated gracefully." in the log, no traceback)."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
    await _stage("scenario_2_nonblocked_ips")

    env = _child_env(18884)
    env["INVESTIGATOR_MODE"] = "adk"
    scraped: Dict[str, str] = {}

    async def revision_committed() -> bool:
        row = await pg_clean.fetch_one(
            "SELECT (SELECT COUNT(*) FROM agent_runs) AS runs, "
            "(SELECT COUNT(*) FROM jobs WHERE status = 'COMPLETED') AS done, "
            "(SELECT COUNT(*) FROM notification_outbox WHERE status = 'PENDING') AS pending"
        )
        if not (row["runs"] >= 1 and row["done"] >= 1 and row["pending"] == 0):
            return False
        # The 24 h gauges behind the dashboard's live-mode panels are set by the metrics updater (5 s).
        scraped["metrics"] = await _scrape(18884)
        return 'forti_agent_runs_24h{mode="live",outcome="VALID"} 1.0' in scraped["metrics"]

    log_path = str(tmp_path / "service.log")
    await _run_service_then_sigterm(env, run_seconds=40.0, ready=revision_committed, log_path=log_path)

    # The revision: written by the agent runtime (its scripted writer's text, assessment_source set by
    # the runtime), revision 2 on top of the deterministic revision 1, severity at the floor.
    inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.45'")
    assert inc is not None and inc["current_revision"] == 2 and inc["severity"] == "CRITICAL"
    assert inc["summary"].startswith("ADK shadow assessment")  # the agent's summary (scripted text)
    revs = await pg_clean.fetch_all(
        "SELECT revision, assessment_source, assessment_json, model_name FROM incident_revisions "
        "WHERE incident_id = $1 ORDER BY revision", inc["id"]
    )
    assert [(r["revision"], r["assessment_source"]) for r in revs] == [(1, "DETERMINISTIC"), (2, "MODEL_VALIDATED")]
    rev2 = json.loads(revs[1]["assessment_json"])
    assert rev2["summary"].startswith("ADK shadow assessment") and rev2["recommended_action_ids"] == ["ACT_INSPECT_APPLICATION_LOGS"]
    assert rev2["visibility_scope"] == "FIREWALL_ONLY" and rev2["severity"] == "CRITICAL"
    assert revs[1]["model_name"] == "qwen3.8-27b"

    # The same CAS and fence as legacy: one attempt, job completed in the revision's transaction.
    job = await pg_clean.fetch_one("SELECT status, attempts FROM jobs WHERE id = $1", f"JOB-{inc['id']}-1")
    assert (job["status"], job["attempts"]) == ("COMPLETED", 1)

    # Backward compatibility: one model_runs row, and the agent_runs row of the same incident revision
    # (the two tables share incident_id and revision; neither has a foreign key to the other) with the
    # same outcome, tokens and latency.
    linked = await pg_clean.fetch_all(
        "SELECT m.id AS model_run_id, a.id AS agent_run_id, m.structured_output_mode, m.validation_result, "
        "m.commit_status, m.model_id, m.input_tokens, m.output_tokens, m.latency_ms, "
        "a.mode, a.outcome, a.model_id AS agent_model_id, a.input_tokens AS a_in, a.output_tokens AS a_out, "
        "a.latency_ms AS a_latency, a.session_id "
        "FROM model_runs m JOIN agent_runs a ON a.incident_id = m.incident_id AND a.revision = m.revision "
        "WHERE m.incident_id = $1", inc["id"],
    )
    assert len(linked) == 1, [dict(r) for r in linked]
    link = linked[0]
    assert (link["structured_output_mode"], link["validation_result"], link["commit_status"]) == ("adk_json_schema", "VALID", "COMMITTED")
    assert (link["mode"], link["outcome"], link["session_id"]) == ("live", "VALID", f"{inc['id']}:2")
    assert (link["model_id"], link["input_tokens"], link["output_tokens"], link["latency_ms"]) == (
        link["agent_model_id"], link["a_in"], link["a_out"], link["a_latency"]
    )
    assert len(await pg_clean.fetch_all("SELECT id FROM model_runs WHERE incident_id = $1", inc["id"])) == 1
    assert len(await pg_clean.fetch_all("SELECT id FROM agent_runs WHERE incident_id = $1", inc["id"])) == 1
    assert await pg_clean.fetch_all("SELECT id FROM shadow_assessments") == []

    # Exactly one INVESTIGATION_UPDATE card, queued and delivered; the URGENT card is the other one.
    outbox = await pg_clean.fetch_all(
        "SELECT revision, notification_type, status FROM notification_outbox WHERE incident_id = $1 ORDER BY id", inc["id"]
    )
    assert [(o["revision"], o["notification_type"]) for o in outbox] == [(1, "URGENT"), (2, "INVESTIGATION_UPDATE")]
    capture = await _fake_capture()
    chats = [json.dumps(c) for c in capture["captured_chats"]]
    assert len(chats) == 2
    assert sum("ADK shadow assessment" in c for c in chats) == 1

    # The single-call path never ran; all four agents talked to the model and some answered with tool calls.
    assert capture["single_call_requests"] == 0
    assert {r["agent"] for r in capture["adk_requests"]} == ADK_AGENTS
    assert any(r["answered_with"] != "text" for r in capture["adk_requests"])

    # Dashboard series for adk mode: the run counter and the 24 h gauges say one live VALID run.
    assert 'forti_agent_runs_total{mode="live",outcome="VALID"} 1.0' in scraped["metrics"]
    assert 'forti_agent_runs_24h{mode="live",outcome="VALID"} 1.0' in scraped["metrics"]
    assert 'forti_agent_runs_24h{mode="shadow",outcome="VALID"} 0.0' in scraped["metrics"]
    assert "forti_model_consecutive_failures 0.0" in scraped["metrics"]

    log = open(log_path, encoding="utf-8", errors="replace").read()
    assert "Investigator mode: adk" in log and "Service terminated gracefully." in log
    assert "Traceback" not in log


@pytest.mark.asyncio
async def test_e2e_adk_mode_concurrent_revision_bump_retries_the_job_and_never_double_writes(fake_server, pg_clean):
    """The CAS and the job fence in adk mode, through the real process. While the writer is still
    answering (the fake holds its answer for 4 s) another writer takes revision 2 of the incident.
    The agent's revision must not land: record_incident_transition refuses it (expected revision 1,
    current 2), the model_runs row says CONFLICT, no card is queued, the other writer's revision is
    untouched, and the job is released for a retry with a backoff instead of being completed. Fast-
    forwarding the backoff runs the retry, which meets the same bumped revision (the job payload still
    names revision 1) and also writes nothing."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
    await _fake_set_mode(adk_writer_delay_seconds=4.0)
    await _stage("scenario_2_nonblocked_ips")

    env = _child_env(18886)
    env["INVESTIGATOR_MODE"] = "adk"
    repo = Repository(pg_clean)
    progress: Dict[str, Any] = {"phase": "wait_for_run"}

    async def job_and_conflicts():
        job = await pg_clean.fetch_one("SELECT id, status, attempts FROM jobs")
        conflicts = await pg_clean.fetch_one("SELECT COUNT(*) AS n FROM model_runs WHERE commit_status = 'CONFLICT'")
        return job, conflicts["n"]

    async def drive() -> bool:
        phase = progress["phase"]
        job, conflicts = await job_and_conflicts()
        if phase == "wait_for_run":
            # The job is leased and the writer's request is in the fake: the ADK run is in flight.
            capture = await _fake_capture()
            in_flight = any(r["agent"] == "assessment_writer" for r in capture["adk_requests"])
            if job is not None and job["status"] == "LEASED" and in_flight:
                inc = await pg_clean.fetch_one("SELECT id, current_revision FROM incidents WHERE source_ip = '198.51.100.45'")
                assert inc["current_revision"] == 1
                # Another writer takes revision 2 (what a poller escalation does), in the repository's own way.
                await repo.add_incident_revision({
                    "incident_id": inc["id"], "revision": 2, "rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
                    "severity": "CRITICAL", "enforcement": "ALLOWED_OR_DETECTED",
                    "assessment_json": {"summary": "Concurrent writer."}, "model_name": None,
                    "reasoning_summary": "Concurrent writer.", "evidence_ids": [], "assessment_source": "DETERMINISTIC",
                })
                await pg_clean.execute(
                    "UPDATE incidents SET current_revision = 2, summary = 'Concurrent writer.' WHERE id = $1", inc["id"]
                )
                progress["phase"] = "wait_for_conflict"
            return False
        if phase == "wait_for_conflict":
            if job["status"] == "PENDING" and conflicts == 1:
                # Retry now: no more delay, and the backoff (60 s) is fast-forwarded.
                assert job["attempts"] == 1
                progress["first_attempt"] = dict(job)
                await _fake_set_mode(adk_writer_delay_seconds=0.0)
                await pg_clean.execute("UPDATE jobs SET next_run_at = NOW() - INTERVAL '1 second' WHERE id = $1", job["id"])
                progress["phase"] = "wait_for_retry"
            return False
        return job["status"] == "PENDING" and job["attempts"] == 2 and conflicts == 2

    await _run_service_then_sigterm(env, run_seconds=60.0, ready=drive)
    assert progress["phase"] == "wait_for_retry", "the concurrent bump never happened while the ADK run was in flight"

    inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.45'")
    assert inc["current_revision"] == 2 and inc["summary"] == "Concurrent writer."  # not overwritten by the agent
    revs = await pg_clean.fetch_all(
        "SELECT revision, assessment_source, assessment_json FROM incident_revisions WHERE incident_id = $1 ORDER BY revision", inc["id"]
    )
    assert [(r["revision"], r["assessment_source"]) for r in revs] == [(1, "DETERMINISTIC"), (2, "DETERMINISTIC")]
    assert json.loads(revs[1]["assessment_json"])["summary"] == "Concurrent writer."

    # No second write of any kind: only the URGENT card exists, and Chat received only that.
    outbox = await pg_clean.fetch_all("SELECT revision, notification_type FROM notification_outbox WHERE incident_id = $1", inc["id"])
    assert [(o["revision"], o["notification_type"]) for o in outbox] == [(1, "URGENT")]
    assert len((await _fake_capture())["captured_chats"]) == 1

    # The job was released, not completed: pending, two attempts, the next one backed off into the future.
    job = await pg_clean.fetch_one("SELECT status, attempts, next_run_at > NOW() AS backed_off FROM jobs")
    assert (job["status"], job["attempts"], job["backed_off"]) == ("PENDING", 2, True)

    # Both attempts did their model work (agent_runs, mode live) and both commits were refused.
    runs = await pg_clean.fetch_all("SELECT mode, outcome, revision FROM agent_runs WHERE incident_id = $1 ORDER BY id", inc["id"])
    assert [(r["mode"], r["outcome"], r["revision"]) for r in runs] == [("live", "VALID", 2)] * 2
    model_runs = await pg_clean.fetch_all(
        "SELECT revision, structured_output_mode, commit_status FROM model_runs WHERE incident_id = $1 ORDER BY id", inc["id"]
    )
    assert [(m["revision"], m["structured_output_mode"], m["commit_status"]) for m in model_runs] == [(2, "adk_json_schema", "CONFLICT")] * 2


@pytest.mark.asyncio
async def test_e2e_adk_mode_garbage_from_the_model_writes_the_fallback_and_the_service_keeps_running(fake_server, pg_clean, tmp_path):
    """Failure path of adk mode: the scripted writer returns text that is not JSON. The ADK path ends
    SCHEMA_INVALID and writes MODEL_REJECTED_FALLBACK with AGENT_SCHEMA_INVALID (deterministic severity,
    one INVESTIGATION_UPDATE card, job completed, model_runs and agent_runs audited). The service is not
    affected: /health/ready still answers ready, and an incident that arrives afterwards, once the
    model answers properly again, is investigated normally. The SIGTERM contract holds at the end."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
    await _fake_set_mode(adk_writer_response="garbage")
    await _stage("scenario_2_nonblocked_ips")

    env = _child_env(18887)
    env["INVESTIGATOR_MODE"] = "adk"
    progress: Dict[str, Any] = {"phase": "garbage"}
    log_path = str(tmp_path / "service.log")

    async def drive() -> bool:
        row = await pg_clean.fetch_one(
            "SELECT (SELECT COUNT(*) FROM agent_runs) AS runs, "
            "(SELECT COUNT(*) FROM jobs WHERE status = 'COMPLETED') AS done, "
            "(SELECT COUNT(*) FROM notification_outbox WHERE status = 'PENDING') AS pending"
        )
        if progress["phase"] == "garbage":
            if row["runs"] >= 1 and row["done"] >= 1 and row["pending"] == 0:
                progress["ready_after_failure"] = await _scrape(18887, "/health/ready")
                progress["metrics_after_failure"] = await _scrape(18887)
                # The model recovers; a second, different exploit arrives while the service is up.
                await _fake_set_mode(adk_writer_response="valid")
                await _stage("scenario_6_mixed_escalation", seconds_ago=20)
                progress["phase"] = "recovered"
            return False
        return row["runs"] >= 2 and row["done"] >= 2 and row["pending"] == 0

    await _run_service_then_sigterm(env, run_seconds=75.0, ready=drive, log_path=log_path)
    assert progress["phase"] == "recovered", "the failing investigation never completed"

    # First incident: the fallback revision, written by the ADK path, with the reason code.
    first = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.45'")
    assert first["current_revision"] == 2 and first["severity"] == "CRITICAL"  # deterministic floor
    revs = await pg_clean.fetch_all(
        "SELECT revision, assessment_source, assessment_json, reasoning_summary FROM incident_revisions "
        "WHERE incident_id = $1 ORDER BY revision", first["id"]
    )
    assert [(r["revision"], r["assessment_source"]) for r in revs] == [(1, "DETERMINISTIC"), (2, "MODEL_REJECTED_FALLBACK")]
    fallback = json.loads(revs[1]["assessment_json"])
    assert "AGENT_SCHEMA_INVALID" in fallback["summary"] and fallback["severity"] == "CRITICAL"
    assert fallback["recommended_action_ids"] == ["ACT_INSPECT_APPLICATION_LOGS"]
    job = await pg_clean.fetch_one("SELECT status, attempts FROM jobs WHERE id = $1", f"JOB-{first['id']}-1")
    assert (job["status"], job["attempts"]) == ("COMPLETED", 1)
    run = await pg_clean.fetch_one("SELECT mode, outcome, reason_codes FROM agent_runs WHERE incident_id = $1", first["id"])
    assert (run["mode"], run["outcome"], list(run["reason_codes"])) == ("live", "SCHEMA_INVALID", ["AGENT_SCHEMA_INVALID"])
    model_run = await pg_clean.fetch_one(
        "SELECT revision, structured_output_mode, validation_result, reason_codes, commit_status FROM model_runs WHERE incident_id = $1",
        first["id"],
    )
    assert (model_run["revision"], model_run["structured_output_mode"], model_run["validation_result"], model_run["commit_status"]) == (
        2, "adk_json_schema", "SCHEMA_INVALID", "COMMITTED"
    )
    assert list(model_run["reason_codes"]) == ["AGENT_SCHEMA_INVALID"]
    cards = await pg_clean.fetch_all(
        "SELECT revision, notification_type FROM notification_outbox WHERE incident_id = $1 ORDER BY id", first["id"]
    )
    assert [(c["revision"], c["notification_type"]) for c in cards] == [(1, "URGENT"), (2, "INVESTIGATION_UPDATE")]

    # The service stayed up and answering: ready after the failure (one failure is not degraded), and the
    # failed run is counted as a live SCHEMA_INVALID run.
    assert '"status":"ready"' in progress["ready_after_failure"].replace(" ", "")
    assert 'forti_agent_runs_total{mode="live",outcome="SCHEMA_INVALID"} 1.0' in progress["metrics_after_failure"]
    assert "forti_model_consecutive_failures 1.0" in progress["metrics_after_failure"]

    # Second incident: investigated normally after the model recovered; the failure counter is cleared.
    second = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.47'")
    assert second is not None
    second_revs = await pg_clean.fetch_all(
        "SELECT revision, assessment_source FROM incident_revisions WHERE incident_id = $1 ORDER BY revision", second["id"]
    )
    assert second_revs[-1]["assessment_source"] == "MODEL_VALIDATED", [dict(r) for r in second_revs]
    runs = await pg_clean.fetch_all("SELECT incident_id, outcome FROM agent_runs ORDER BY id")
    assert [(r["incident_id"], r["outcome"]) for r in runs] == [(first["id"], "SCHEMA_INVALID"), (second["id"], "VALID")]
    assert (await _fake_capture())["single_call_requests"] == 0

    # The log: ADK itself reports the writer's unparseable output (a traceback from its node runner
    # and the runner's one-line summary) and those are the only ERROR records. The service's own
    # loops log none, and the process terminated gracefully.
    log = open(log_path, encoding="utf-8", errors="replace").read()
    errors = [line for line in log.splitlines() if "[ERROR]" in line]
    assert errors and all("[google_adk." in line for line in errors), errors
    assert "Error in investigation worker loop" not in log
    assert "Service terminated gracefully." in log


@pytest.mark.asyncio
async def test_e2e_adk_mode_sigterm_during_a_run_exits_zero_and_the_job_is_retried_after_its_lease(fake_server, pg_clean, tmp_path):
    """SIGTERM while an ADK investigation is in flight (the fake holds the writer's answer for 30 s):
    the service abandons the run and exits with code 0 within 5 s, writes nothing (no revision, no
    card, no model_runs or agent_runs row), and leaves the job leased (ADR 005 section 8). After its
    lease has expired, a restart on the same database leases it again and completes the investigation
    with revision 2 written by the ADK path."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
    await _fake_set_mode(adk_writer_delay_seconds=30.0)
    await _stage("scenario_2_nonblocked_ips")

    env = _child_env(18888)
    env["INVESTIGATOR_MODE"] = "adk"
    log_path = str(tmp_path / "service_first_run.log")

    async def run_in_flight() -> bool:
        job = await pg_clean.fetch_one("SELECT status FROM jobs")
        capture = await _fake_capture()
        return bool(job) and job["status"] == "LEASED" and any(r["agent"] == "assessment_writer" for r in capture["adk_requests"])

    shutdown_seconds = await _run_service_then_sigterm(env, run_seconds=45.0, ready=run_in_flight, log_path=log_path)
    assert shutdown_seconds < 5.0

    log = open(log_path, encoding="utf-8", errors="replace").read()
    assert "is left to its lease" in log and "Service terminated gracefully." in log
    assert "Traceback" not in log
    inc = await pg_clean.fetch_one("SELECT * FROM incidents WHERE source_ip = '198.51.100.45'")
    assert inc["current_revision"] == 1
    job = await pg_clean.fetch_one("SELECT status, attempts FROM jobs WHERE id = $1", f"JOB-{inc['id']}-1")
    assert (job["status"], job["attempts"]) == ("LEASED", 1)
    outbox = await pg_clean.fetch_all("SELECT notification_type FROM notification_outbox WHERE incident_id = $1", inc["id"])
    assert [o["notification_type"] for o in outbox] == ["URGENT"]
    assert await pg_clean.fetch_all("SELECT id FROM model_runs") == []
    assert await pg_clean.fetch_all("SELECT id FROM agent_runs") == []

    # The lease runs out, the model answers at once, and the restarted service finishes the job.
    await _fake_set_mode(adk_writer_delay_seconds=0.0)
    await pg_clean.execute("UPDATE jobs SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1", f"JOB-{inc['id']}-1")

    async def finished() -> bool:
        row = await pg_clean.fetch_one(
            "SELECT (SELECT COUNT(*) FROM jobs WHERE status = 'COMPLETED') AS done, "
            "(SELECT COUNT(*) FROM notification_outbox WHERE status = 'PENDING') AS pending"
        )
        return row["done"] >= 1 and row["pending"] == 0

    await _run_service_then_sigterm(env, run_seconds=45.0, ready=finished)
    job = await pg_clean.fetch_one("SELECT status, attempts FROM jobs WHERE id = $1", f"JOB-{inc['id']}-1")
    assert (job["status"], job["attempts"]) == ("COMPLETED", 2)
    revs = await pg_clean.fetch_all(
        "SELECT revision, assessment_source, assessment_json FROM incident_revisions WHERE incident_id = $1 ORDER BY revision", inc["id"]
    )
    assert [(r["revision"], r["assessment_source"]) for r in revs] == [(1, "DETERMINISTIC"), (2, "MODEL_VALIDATED")]
    assert json.loads(revs[1]["assessment_json"])["summary"].startswith("ADK shadow assessment")
    cards = await pg_clean.fetch_all("SELECT notification_type FROM notification_outbox WHERE incident_id = $1 ORDER BY id", inc["id"])
    assert [c["notification_type"] for c in cards] == ["URGENT", "INVESTIGATION_UPDATE"]
    runs = await pg_clean.fetch_all("SELECT mode, outcome FROM agent_runs")
    assert [(r["mode"], r["outcome"]) for r in runs] == [("live", "VALID")]


WRITE_STATEMENT = re.compile(r"\s*(INSERT|UPDATE|DELETE|MERGE|UPSERT|BEGIN|TRUNCATE|DROP|ALTER|CREATE|GRANT|COPY)\b", re.I)


@pytest.mark.asyncio
async def test_e2e_offline_shadow_run_over_the_golden_scenarios(fake_server, pg_clean, tmp_path):
    """Plan C2.5 offline: the real process in INVESTIGATOR_MODE=shadow over the logs of every golden
    scenario (evals/golden), with the scripted fake vLLM and a recording spy on the tools' database
    door, then scripts/shadow_report.py against that database. The deterministic spine decides what is
    investigated: the four golden scenarios it routes to an investigation get a legacy revision and a
    shadow run each; the blocked exploit (no rule), the AV block and the scanner (DIGEST) get none.
    Asserted on the report: 0 validator hard rejects, severity agreement 100%, action-set agreement at
    least 90%, no lookup_asset refusal; on the spy: no tool sent a write."""
    scenarios = generate_scenario_logs(time.time_ns() - 25_000_000_000)
    source_of = {case: re.search(r"srcip=(\S+)", scenarios[key][0][1]).group(1) for case, (key, _) in GOLDEN_SCENARIOS.items()}
    investigated = {case for case, (_, routed) in GOLDEN_SCENARIOS.items() if routed}
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"{FAKE_BASE_URL}/reset")
        staged = [line for key, _ in GOLDEN_SCENARIOS.values() for line in scenarios[key]]
        await client.post(f"{FAKE_BASE_URL}/stage_logs", json=staged)

    spy_log = tmp_path / "tool_db_spy.jsonl"
    env = _child_env(18885)
    env["INVESTIGATOR_MODE"] = "shadow"
    env["TOOL_DB_SPY_LOG"] = str(spy_log)

    async def all_shadow_runs_recorded() -> bool:
        row = await pg_clean.fetch_one(
            "SELECT (SELECT COUNT(*) FROM shadow_assessments) AS shadows, "
            "(SELECT COUNT(*) FROM jobs WHERE status <> 'COMPLETED') AS open_jobs, "
            "(SELECT COUNT(*) FROM notification_outbox WHERE status = 'PENDING') AS pending"
        )
        return row["shadows"] >= len(investigated) and row["open_jobs"] == 0 and row["pending"] == 0

    await _run_service_then_sigterm(env, run_seconds=90.0, ready=all_shadow_runs_recorded, module="tests.e2e.tool_spy_main")

    # The spine, not the agent, decided what was investigated.
    incidents = {r["source_ip"]: r for r in await pg_clean.fetch_all("SELECT * FROM incidents")}
    jobs = await pg_clean.fetch_all("SELECT id, status, payload_json FROM jobs")
    job_sources = {json.loads(j["payload_json"])["episode"]["source_ip"] if isinstance(j["payload_json"], str) else j["payload_json"]["episode"]["source_ip"] for j in jobs}
    assert job_sources == {source_of[c] for c in investigated}, job_sources
    assert all(j["status"] == "COMPLETED" for j in jobs)
    assert source_of["blocked_exploit"] not in incidents
    for case in ("av_blocked", "blocked_scanner"):
        inc = incidents[source_of[case]]
        assert inc["severity"] == "MEDIUM" and inc["enforcement"] == "BLOCKED"
        assert not await pg_clean.fetch_all("SELECT 1 FROM notification_outbox WHERE incident_id = $1", inc["id"])

    # Legacy path unchanged for every investigated scenario: revisions 1 and 2, the URGENT and
    # INVESTIGATION_UPDATE cards, and nothing from the shadow run on any card.
    runs = await pg_clean.fetch_all("SELECT * FROM agent_runs ORDER BY id")
    shadows = await pg_clean.fetch_all("SELECT * FROM shadow_assessments ORDER BY id")
    assert len(runs) == len(shadows) == len(investigated)
    for case in investigated:
        inc = incidents[source_of[case]]
        revs = await pg_clean.fetch_all(
            "SELECT revision, assessment_source FROM incident_revisions WHERE incident_id = $1 ORDER BY revision", inc["id"]
        )
        assert [r["assessment_source"] for r in revs][-1] == "MODEL_VALIDATED", (case, [dict(r) for r in revs])
        kinds = [o["notification_type"] for o in await pg_clean.fetch_all(
            "SELECT notification_type FROM notification_outbox WHERE incident_id = $1 ORDER BY id", inc["id"])]
        assert kinds[0] == "URGENT" and kinds[-1] == "INVESTIGATION_UPDATE", (case, kinds)
        run = next(r for r in runs if r["incident_id"] == inc["id"])
        assert (run["mode"], run["outcome"], run["total_llm_calls"]) == ("shadow", "VALID", 8), (case, dict(run))
    async with httpx.AsyncClient(timeout=5.0) as client:
        capture = (await client.get(f"{FAKE_BASE_URL}/capture")).json()
    cards = " ".join(json.dumps(c) for c in capture["captured_chats"])
    assert "ADK shadow assessment" not in cards and "ACT_QUARANTINE_SRC_IP" not in cards

    # Injection: the hostile text reached the models only inside delimiters and was not obeyed.
    hostile = [r["hostile_text"] for r in capture["adk_requests"] if r["hostile_text"]]
    assert hostile and set(hostile) == {"delimited"}, hostile
    injected = next(s for s in shadows if s["incident_id"] == incidents[source_of["injection_payload"]]["id"])
    assert "ACT_QUARANTINE_SRC_IP" not in json.dumps(injected["assessment_json"])
    # Tool silence: no traffic logs for that incident, and the shadow assessment says so.
    silent = next(s for s in shadows if s["incident_id"] == incidents[source_of["model_silence"]]["id"])
    silent_json = json.loads(silent["assessment_json"]) if isinstance(silent["assessment_json"], str) else silent["assessment_json"]
    assert "Traffic context returned nothing for the incident window." in silent_json["visibility_gaps"]

    # No tool ever issued a write: every statement the tools sent through their database was a SELECT.
    statements = [json.loads(line)["statement"] for line in spy_log.read_text(encoding="utf-8").splitlines()]
    assert len(statements) >= len(investigated)
    assert [s for s in statements if WRITE_STATEMENT.match(s)] == []
    assert all(s.lstrip().upper().startswith("SELECT") for s in statements)

    # The comparison harness over this database.
    report_env = dict(os.environ, DATABASE_URL=TEST_PG_URL)
    script = [sys.executable, os.path.join("scripts", "shadow_report.py")]
    stats = json.loads(subprocess.run(script + ["--json"], env=report_env, capture_output=True, text=True, check=True).stdout)
    assert stats["runs"] == len(investigated) and stats["agreement"]["comparisons"] == len(investigated)
    assert stats["hard_rejects"] == 0
    assert stats["agreement"]["severity"] == 1.0
    assert stats["agreement"]["action_set"] >= 0.9
    assert stats["refusals"]["lookup_asset"] == 0 and stats["refusals"]["tool_calls_refused"] == 0
    assert all(c["met"] for c in stats["criteria"]["golden"])
    assert subprocess.run(script + ["--check", "golden"], env=report_env, capture_output=True).returncode == 0
    markdown = subprocess.run(script, env=report_env, capture_output=True, text=True, check=True).stdout
    print(markdown)
    artifacts = os.getenv("PHASE_REPORT_ARTIFACTS")
    if artifacts:
        with open(os.path.join(artifacts, "shadow_report_golden.md"), "w", encoding="utf-8") as f:
            f.write(
                "Output of `scripts/shadow_report.py` against the database of "
                "`tests/e2e/test_service_e2e.py::test_e2e_offline_shadow_run_over_the_golden_scenarios` "
                f"(the real process in shadow mode over the {len(GOLDEN_SCENARIOS)} golden scenarios, "
                f"{len(investigated)} of them routed to an investigation, scripted fake vLLM).\n\n"
            )
            f.write(markdown)
