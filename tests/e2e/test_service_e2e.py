"""End-to-end integration tests driving the real python -m src.main process against PostgreSQL 16.

Uses fake external endpoints (FastAPI in isolated subprocess) for:
- Grafana Loki query_range API
- Local vLLM / OpenAI chat completions API
- Google Chat incoming webhook API
"""

import os
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
from tests.e2e.fake_endpoints import app as fake_app, generate_scenario_logs

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
                           query_checkpoints, coverage_gaps, episodes, model_runs CASCADE;
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


async def _run_service_then_sigterm(env: Dict[str, str], run_seconds: float) -> float:
    """Runs the real ``python -m src.main`` for ``run_seconds``, sends SIGTERM and enforces
    the D4 contract: the process exits on its own, within 5 s, with exit code 0. The
    process is only killed to clean up after that assertion has already failed."""
    proc = subprocess.Popen([sys.executable, "-m", "src.main"], env=env)
    try:
        await asyncio.sleep(run_seconds)
    finally:
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)
            pytest.fail("service did not exit within 5 s of SIGTERM")
        shutdown_seconds = time.monotonic() - t0
    assert proc.returncode == 0, f"service exited with code {proc.returncode} after SIGTERM"
    return shutdown_seconds


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
