"""Integration tests for poller loop, durable inbox, and robust event storage on PostgreSQL 16."""

import os
import pytest
import pytest_asyncio
import asyncio
from datetime import datetime, timezone

from src.storage.database import Database
from src.storage.repository import Repository
from src.parsing.normalizer import normalize_event
from src.observability.metrics import PARSER_ERRORS_TOTAL

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
async def test_pg_long_msg_and_text_columns(pg_repo):
    """Batch of rows containing very long (>3000 chars) signature/msg persists successfully without truncation error."""
    events = []
    base_ts = 1791271940000000000
    long_msg = "A" * 3500

    for i in range(10):
        raw_line = (
            f'date=2026-10-06 time=12:00:00 devname="FGT" devid="FGT1" logid="0000000013" '
            f'type="utm" subtype="ips" level="alert" vd="root" srcip=198.51.100.{i+1} dstip=10.0.14.120 '
            f'action="dropped" attack="Exploit.Long.Signature.{long_msg}" sessionid={1000 + i}'
        )
        ev = normalize_event(base_ts + i * 1_000_000, raw_line)
        assert ev is not None
        assert ev["signature_truncated"] is True  # Signature truncated to 512
        events.append(ev)

    inserted = await pg_repo.save_events(events)
    assert inserted == 10

    # Verify rows in PostgreSQL
    pending = await pg_repo.fetch_pending_events(limit=20)
    assert len(pending) == 10
    for p in pending:
        assert p["signature_truncated"] is True
        assert len(p["signature"]) <= 512
        assert len(p["raw_message"]) > 3500


@pytest.mark.asyncio
async def test_pg_batch_insert_rejection_fallback(pg_repo):
    """If a batch contains an invalid row (violating NOT NULL constraint), 
    the batch falls back to row-by-row, valid rows are saved, invalid row is recorded in rejected_events,
    and PARSER_ERRORS_TOTAL is incremented without halting ingestion.
    """
    valid_events = []
    base_ts = 1791271940000000000
    for i in range(5):
        raw_line = (
            f'date=2026-10-06 time=12:00:00 devname="FGT" devid="FGT1" logid="0000000013" '
            f'type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.1.{i+1} dstip=10.0.2.10 '
            f'action="accept" sessionid={2000 + i}'
        )
        ev = normalize_event(base_ts + i * 1_000_000, raw_line)
        valid_events.append(ev)

    # Poisoned event: None for NOT NULL column (e.g. raw_message or action_normalized)
    bad_event = dict(valid_events[0])
    bad_event["id"] = "BAD-EVENT-NOT-NULL"
    bad_event["raw_message"] = None  # selected_events raw_message is NOT NULL

    batch = valid_events + [bad_event]

    errors_before = PARSER_ERRORS_TOTAL._value.get()
    inserted = await pg_repo.save_events(batch)

    # 5 valid rows inserted, 1 bad row rejected
    assert inserted == 5
    assert PARSER_ERRORS_TOTAL._value.get() == errors_before + 1

    # Check rejected_events table
    async with pg_repo.db._pg_pool.acquire() as conn:
        rej_rows = await conn.fetch("SELECT * FROM rejected_events WHERE id = 'BAD-EVENT-NOT-NULL'")
        assert len(rej_rows) == 1
        assert "null value in column" in rej_rows[0]["reason"].lower()


@pytest.mark.asyncio
async def test_pg_durable_inbox_ordered_draining(pg_repo):
    """Pending events are drained in strictly ascending chronological order and marked processed."""
    events = []
    base_ts = 1791271940000000000
    # Add out of order timestamps
    ts_offsets = [50, 10, 30, 20, 40]
    for idx, offset in enumerate(ts_offsets):
        raw_line = (
            f'date=2026-10-06 time=12:00:00 devname="FGT" devid="FGT1" logid="0000000013" '
            f'type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.1.{idx} dstip=10.0.2.10 '
            f'action="accept" sessionid={3000 + idx}'
        )
        ev = normalize_event(base_ts + offset * 1_000_000_000, raw_line)
        events.append(ev)

    await pg_repo.save_events(events)

    pending = await pg_repo.fetch_pending_events(limit=10)
    assert len(pending) == 5

    # Check strictly ascending order
    loki_timestamps = [p["loki_ts_ns"] for p in pending]
    assert loki_timestamps == sorted(loki_timestamps)
    assert loki_timestamps[0] == base_ts + 10 * 1_000_000_000
    assert loki_timestamps[-1] == base_ts + 50 * 1_000_000_000

    # Mark first 3 processed
    to_ack = [p["id"] for p in pending[:3]]
    await pg_repo.mark_events_processed(to_ack)

    # Remaining pending must be 2
    remaining = await pg_repo.fetch_pending_events(limit=10)
    assert len(remaining) == 2
    assert [r["id"] for r in remaining] == [p["id"] for p in pending[3:]]
