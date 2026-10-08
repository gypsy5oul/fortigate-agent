"""Integration tests for poller loop, durable inbox, and robust event storage on PostgreSQL 16."""

import os
import pytest
import pytest_asyncio
import asyncio
from datetime import datetime, timezone, timedelta

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
                           query_checkpoints, coverage_gaps, episodes, model_runs CASCADE;
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
            f'action="deny" sessionid={2000 + i}'
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
            f'action="deny" sessionid={3000 + idx}'
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


# ---------------------------------------------------------------------------
# B.1 Defect A: incident severity is monotonic across deterministic re-evaluation
# ---------------------------------------------------------------------------

_DENY_FROM_45 = (
    'date=2026-10-08 time=12:02:00 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
    'subtype="forward" level="notice" vd="root" sessionid=500001 srcip=198.51.100.45 srcport=46000 '
    'dstip=10.0.14.120 dstport=22 proto=6 service="SSH" action="deny" policyid=0'
)


async def _service_with_restored_critical_incident(monkeypatch, pg_repo):
    """A service whose aggregator holds a restored episode for an incident that is already
    CRITICAL at revision 1 (rule RULE_NONBLOCKED_EXPLOIT_ATTEMPT), plus one pending deny."""
    from unittest.mock import AsyncMock
    from src.main import IntelligenceService
    from src.parsing.normalizer import normalize_event

    monkeypatch.setenv("DATABASE_URL", TEST_PG_URL)
    monkeypatch.setenv("GCHAT_DRY_RUN", "true")
    monkeypatch.setenv("LLM_ENABLED", "true")

    service = IntelligenceService()
    await service.db.connect()
    service.poller.poll_once = AsyncMock(return_value=(0, 0))  # Loki is not involved

    now = datetime.now(timezone.utc)
    inc_id = "INC-PG-MONOTONIC-1"
    incident = {
        "id": inc_id,
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "CRITICAL",
        "enforcement": "MIXED",
        "exploitation_assessment": "ATTEMPT_OBSERVED",
        "vd": "root",
        "direction": "INBOUND",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "first_seen": now,
        "last_seen": now,
        "event_count": 13,
        "summary": "Non-blocked Log4j exploit",
        "rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        "deterministic_severity": "CRITICAL",
        "deterministic_enforcement": "MIXED",
        "deterministic_rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
    }
    revision = {
        "incident_id": inc_id,
        "revision": 1,
        "rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        "severity": "CRITICAL",
        "enforcement": "MIXED",
        "assessment_json": {"summary": "Non-blocked Log4j exploit"},
        "reasoning_summary": "Non-blocked Log4j exploit",
        "evidence_ids": ["EVID-1"],
        "assessment_source": "DETERMINISTIC",
    }
    await service.repo.record_incident_transition(incident=incident, revision=revision)

    service.aggregator.load_open_episodes([{
        "id": "EP-PG-MONOTONIC-1",
        "incident_id": inc_id,
        "vdom": "root",
        "direction": "INBOUND",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "service": "HTTPS",
        "first_seen": now,
        "last_seen": now,
        "last_event_ts_ns": int(now.timestamp() * 1e9),
        "event_count": 13,
        "enforcement": "MIXED",
        "enforcement_counts": {"BLOCKED": 12, "ALLOWED_OR_DETECTED": 1},
        "signatures": ["Apache.Log4j.Error.Log.Remote.Code.Execution"],
        "utm_subtypes": ["ips"],
        "evidence_ids": [],
    }])

    deny_ts_ns = int((now + timedelta(seconds=5)).timestamp() * 1e9)
    deny = normalize_event(deny_ts_ns, _DENY_FROM_45)
    assert deny is not None
    await service.repo.save_events([deny])
    return service, inc_id


async def _run_poller_until_inbox_drained(service):
    service.running = True
    task = asyncio.create_task(service._run_poller_loop())
    for _ in range(100):
        if not await service.repo.fetch_pending_events(limit=10):
            break
        await asyncio.sleep(0.05)
    service.running = False
    service.stop_event.set()
    await asyncio.wait_for(task, timeout=10)


@pytest.mark.asyncio
async def test_pg_poller_same_rules_lower_floor_writes_nothing(pg_repo, monkeypatch):
    """Evaluation returns the same rule set with a lower floor (MEDIUM): no revision is
    written and the incident stays CRITICAL at revision 1."""
    service, inc_id = await _service_with_restored_critical_incident(monkeypatch, pg_repo)
    try:
        service.rule_engine.evaluate_episode = lambda ep: {
            "matched_rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
            "severity_floor": "MEDIUM",
            "routing_outcome": "DIGEST",
            "reasons": ["re-evaluated on one new event"],
        }
        await _run_poller_until_inbox_drained(service)

        inc = await pg_repo.get_incident(inc_id)
        assert inc["severity"] == "CRITICAL"
        assert inc["deterministic_severity"] == "CRITICAL"
        assert inc["current_revision"] == 1
        assert inc["event_count"] == 14  # counts-only update still landed
        revs = await pg_repo.db.fetch_all(
            "SELECT revision, severity FROM incident_revisions WHERE incident_id = $1 ORDER BY revision", inc_id
        )
        assert [(r["revision"], r["severity"]) for r in revs] == [(1, "CRITICAL")]
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_pg_poller_new_lower_rule_keeps_severity_and_unions_rules(pg_repo, monkeypatch):
    """Evaluation returns a new, lower rule (port scan, MEDIUM): a revision is written for
    the new rule, but severity stays CRITICAL and the rule list is the union."""
    service, inc_id = await _service_with_restored_critical_incident(monkeypatch, pg_repo)
    try:
        service.rule_engine.evaluate_episode = lambda ep: {
            "matched_rule_ids": ["RULE_PORT_SCAN_MULTI_SERVICE"],
            "severity_floor": "MEDIUM",
            "routing_outcome": "DIGEST",
            "reasons": ["Source IP probed multiple distinct network services"],
        }
        await _run_poller_until_inbox_drained(service)

        inc = await pg_repo.get_incident(inc_id)
        assert inc["severity"] == "CRITICAL"
        assert inc["deterministic_severity"] == "CRITICAL"
        assert inc["current_revision"] == 2
        assert list(inc["deterministic_rule_ids"]) == ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT", "RULE_PORT_SCAN_MULTI_SERVICE"]
        revs = await pg_repo.db.fetch_all(
            "SELECT revision, severity, assessment_source FROM incident_revisions WHERE incident_id = $1 ORDER BY revision",
            inc_id,
        )
        assert [(r["revision"], r["severity"]) for r in revs] == [(1, "CRITICAL"), (2, "CRITICAL")]
        assert revs[1]["assessment_source"] == "DETERMINISTIC"
    finally:
        await service.stop()


# ---------------------------------------------------------------------------
# B.1 Finding 1 and 2: operational gauges are set from the real tables
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pg_operational_metrics_updater_sets_gauges(pg_repo, monkeypatch):
    from src.main import IntelligenceService
    from src.observability.metrics import (
        BACKLOG_PENDING_EVENTS,
        JOBS_OLDEST_PENDING_SECONDS,
        MODEL_CONSECUTIVE_FAILURES,
    )

    monkeypatch.setenv("DATABASE_URL", TEST_PG_URL)
    monkeypatch.setenv("GCHAT_DRY_RUN", "true")
    service = IntelligenceService()
    await service.db.connect()
    try:
        base_ts = 1791271940000000000
        events = []
        for i in range(2):
            raw_line = (
                f'date=2026-10-06 time=12:00:00 devname="FGT" devid="FGT1" logid="0000000013" '
                f'type="traffic" subtype="forward" level="notice" vd="root" srcip=198.51.100.{i+1} dstip=10.0.14.120 '
                f'action="deny" sessionid={7000 + i}'
            )
            events.append(normalize_event(base_ts + i * 1_000_000, raw_line))
        await service.repo.save_events(events)
        async with service.db._pg_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO jobs (id, job_type, payload_json, priority, status, created_at) "
                "VALUES ('JOB-METRICS-1', 'INVESTIGATE_INCIDENT', '{}'::jsonb, 10, 'PENDING', NOW() - interval '30 seconds')"
            )

        await service._update_operational_metrics()
        assert BACKLOG_PENDING_EVENTS._value.get() == 2
        assert JOBS_OLDEST_PENDING_SECONDS._value.get() >= 29.0

        await service.repo.mark_events_processed([e["id"] for e in events])
        async with service.db._pg_pool.acquire() as conn:
            await conn.execute("UPDATE jobs SET status = 'COMPLETED' WHERE id = 'JOB-METRICS-1'")
        await service._update_operational_metrics()
        assert BACKLOG_PENDING_EVENTS._value.get() == 0
        assert JOBS_OLDEST_PENDING_SECONDS._value.get() == 0.0

        # Consecutive-failure gauge drives the FortiGateModelDegraded alert
        service._note_model_success()
        assert MODEL_CONSECUTIVE_FAILURES._value.get() == 0
        for _ in range(3):
            service._note_model_failure()
        assert MODEL_CONSECUTIVE_FAILURES._value.get() == 3
        assert service.service_state["model_degraded"] is True
        service._note_model_success()
        assert MODEL_CONSECUTIVE_FAILURES._value.get() == 0
        assert service.service_state["model_degraded"] is False
    finally:
        await service.stop()
