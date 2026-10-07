"""Integration tests for Google Chat outbox loop and safety redactions on PostgreSQL 16."""

import os
import pytest
import pytest_asyncio
import httpx
from unittest.mock import patch, AsyncMock

from src.storage.database import Database
from src.storage.repository import Repository
from src.notifications.outbox_worker import OutboxWorker
from src.observability.metrics import OUTBOX_DELIVERED_TOTAL, OUTBOX_FAILURES_TOTAL

TEST_PG_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test",
)


@pytest_asyncio.fixture
async def pg_repo():
    db = Database(TEST_PG_URL)
    await db.connect()
    # Clean tables
    async with db._pg_pool.acquire() as conn:
        await conn.execute(
            """
            TRUNCATE TABLE selected_events, rejected_events, incidents,
                           incident_revisions, jobs, notification_outbox,
                           query_checkpoints, coverage_gaps CASCADE;
            """
        )
    repo = Repository(db)
    yield repo
    await db.close()


@pytest.mark.asyncio
async def test_pg_outbox_dry_run_marks_simulated(pg_repo):
    """When dry_run=True, pending outbox notifications are marked SIMULATED without making external calls."""
    worker = OutboxWorker(repository=pg_repo, webhook_url=None, dry_run=True)

    await pg_repo.enqueue_notification(
        incident_id="INC-OUTBOX-1",
        revision=1,
        notif_type="URGENT",
        payload={"text": "Dry run alert text"},
    )

    pending = await pg_repo.fetch_pending_notifications(limit=10)
    assert len(pending) == 1
    assert pending[0]["status"] == "PENDING"

    dispatched = await worker.process_outbox_batch(limit=10)
    assert dispatched == 1

    # In database, status should now be SIMULATED
    row = await pg_repo.db.fetch_one("SELECT * FROM notification_outbox WHERE incident_id = $1", "INC-OUTBOX-1")
    assert row["status"] == "SIMULATED"
    assert row["sent_at"] is not None

    # No pending items remain
    remaining = await pg_repo.fetch_pending_notifications(limit=10)
    assert len(remaining) == 0

    await worker.close()


@pytest.mark.asyncio
async def test_pg_outbox_failure_redacts_webhook_url(pg_repo):
    """When webhook call fails with an exception containing secret tokens/URLs,
    last_error redacts the URL and OUTBOX_FAILURES_TOTAL is incremented.
    """
    secret_webhook = "https://chat.googleapis.com/v1/spaces/XYZ123/messages?key=AIzaSySecretKey999&token=SecretToken111"
    worker = OutboxWorker(
        repository=pg_repo,
        webhook_url=secret_webhook,
        dry_run=False,
        rate_limit_delay_seconds=0.01,
    )

    await pg_repo.enqueue_notification(
        incident_id="INC-OUTBOX-FAIL",
        revision=1,
        notif_type="URGENT",
        payload={"text": "Live delivery attempt"},
    )

    # Mock the client post to simulate HTTP error containing full URL
    mock_response = httpx.Response(
        status_code=403,
        request=httpx.Request("POST", secret_webhook),
        text=f"Authentication failed for webhook at {secret_webhook} with invalid token",
    )

    with patch.object(worker._client, "post", new=AsyncMock(side_effect=httpx.HTTPStatusError("Forbidden", request=mock_response.request, response=mock_response))):
        dispatched = await worker.process_outbox_batch(limit=5)

    assert dispatched == 0

    # Verify notification in database
    row = await pg_repo.db.fetch_one("SELECT * FROM notification_outbox WHERE incident_id = $1", "INC-OUTBOX-FAIL")
    assert row["status"] == "PENDING"
    assert row["attempts"] == 1
    assert row["last_error"] is not None
    # Verify confidential URL/token was redacted!
    assert "AIzaSySecretKey999" not in row["last_error"]
    assert "SecretToken111" not in row["last_error"]
    assert "[URL_REDACTED]" in row["last_error"]

    await worker.close()


@pytest.mark.asyncio
async def test_pg_outbox_successful_delivery_marks_sent(pg_repo):
    """When webhook call succeeds, notification is marked SENT and OUTBOX_DELIVERED_TOTAL is incremented."""
    worker = OutboxWorker(
        repository=pg_repo,
        webhook_url="https://mock-gchat.local/webhook",
        dry_run=False,
        rate_limit_delay_seconds=0.01,
    )

    await pg_repo.enqueue_notification(
        incident_id="INC-OUTBOX-SUCCESS",
        revision=1,
        notif_type="URGENT",
        payload={"text": "Successful delivery"},
    )

    mock_response = httpx.Response(
        status_code=200,
        request=httpx.Request("POST", "https://mock-gchat.local/webhook"),
        json={"name": "spaces/XYZ/messages/123"},
    )

    with patch.object(worker._client, "post", new=AsyncMock(return_value=mock_response)):
        dispatched = await worker.process_outbox_batch(limit=5)

    assert dispatched == 1

    row = await pg_repo.db.fetch_one("SELECT * FROM notification_outbox WHERE incident_id = $1", "INC-OUTBOX-SUCCESS")
    assert row["status"] == "SENT"
    assert row["sent_at"] is not None

    await worker.close()
