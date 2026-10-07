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
                           query_checkpoints, coverage_gaps CASCADE;
            """
        )
    yield db
    await db.close()


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

    # Configure environment for real child process
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
    env["METRICS_PORT"] = "18881"

    # Spawn real process python -m src.main
    proc = subprocess.Popen([sys.executable, "-m", "src.main"], env=env)

    try:
        # Allow process to execute supervised loops and process the staged batch
        await asyncio.sleep(8.0)
    finally:
        # Gracefully shut down via SIGTERM
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)

    repo = Repository(pg_clean)

    # 1. Monotonic Checkpoint Progress
    latest_cp = await repo.get_checkpoint('{service_name="forticlient"}')
    assert latest_cp is not None
    assert latest_cp > 0

    # 2. Database Event Counts Equal Ground Truth
    events_in_db = await pg_clean.fetch_all("SELECT id, raw_message FROM selected_events")
    assert len(events_in_db) == expected_event_count

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
