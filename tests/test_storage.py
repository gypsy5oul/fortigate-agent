"""Unit tests for storage, checkpoints, leased job queue, and outbox."""

import pytest
import pytest_asyncio
from src.storage.database import Database
from src.storage.repository import Repository
from src.parsing.normalizer import normalize_event
from tests.fixtures.fortios_logs import SAMPLE_TRAFFIC_DENY


@pytest_asyncio.fixture
async def repo():
    db = Database("sqlite:///:memory:")
    await db.connect()
    repository = Repository(db)
    yield repository
    await db.close()


@pytest.mark.asyncio
async def test_checkpoints_and_gaps(repo):
    # Save checkpoint
    await repo.save_checkpoint("test_stream", 1791271900000000000)
    cp = await repo.get_checkpoint("test_stream")
    assert cp == 1791271900000000000

    # Advance checkpoint
    await repo.save_checkpoint("test_stream", 1791271950000000000)
    cp2 = await repo.get_checkpoint("test_stream")
    assert cp2 == 1791271950000000000

    # Record coverage gap
    await repo.record_coverage_gap("test_stream", 100, 200, "Buffer overflow test")
    gap = await repo.db.fetch_one("SELECT * FROM coverage_gaps WHERE stream_name = 'test_stream'")
    assert gap is not None
    assert gap["reason"] == "Buffer overflow test"


@pytest.mark.asyncio
async def test_event_deduplication(repo):
    ev = normalize_event(1791271940000000000, SAMPLE_TRAFFIC_DENY)
    assert ev is not None

    # First insert
    saved1 = await repo.save_events([ev])
    assert saved1 == 1

    # Second insert with identical fingerprint
    saved2 = await repo.save_events([ev])
    assert saved2 == 0
    # Total count in database must remain 1
    total = await repo.db.fetch_one("SELECT COUNT(*) as cnt FROM selected_events")
    assert total["cnt"] == 1


@pytest.mark.asyncio
async def test_leased_job_queue(repo):
    job_id = "JOB-001"
    payload = {"incident_id": "INC-001", "details": "test"}

    # Enqueue job
    await repo.enqueue_job(job_id, "INVESTIGATE_INCIDENT", payload, priority=20)

    # Worker 1 leases job
    leased = await repo.lease_next_job("worker-1", lease_duration_seconds=30)
    assert leased is not None
    assert leased["id"] == job_id
    assert leased["lease_owner"] == "worker-1"
    v_token = leased["version_token"]

    # Concurrent Worker 2 tries to lease; must get None since it is currently leased
    leased2 = await repo.lease_next_job("worker-2", lease_duration_seconds=30)
    assert leased2 is None

    # Worker 1 completes job with version token
    await repo.complete_job(job_id, v_token)
    job_row = await repo.db.fetch_one("SELECT * FROM jobs WHERE id = $1", job_id)
    assert job_row["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_notification_outbox(repo):
    payload = {"text": "Test alert message"}
    await repo.enqueue_notification("INC-001", 1, "URGENT", payload)

    pending = await repo.fetch_pending_notifications(limit=5)
    assert len(pending) == 1
    assert pending[0]["incident_id"] == "INC-001"
    outbox_id = pending[0]["id"]

    await repo.mark_notification_sent(outbox_id)
    pending_after = await repo.fetch_pending_notifications(limit=5)
    assert len(pending_after) == 0
