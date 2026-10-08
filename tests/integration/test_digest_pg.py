"""Integration tests for periodic DIGEST aggregation on PostgreSQL 16 (M5, D7)."""

import os
import json
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta

from src.storage.database import Database
from src.storage.repository import Repository

TEST_PG_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test",
)


@pytest_asyncio.fixture
async def pg_repo():
    db = Database(TEST_PG_URL)
    await db.connect()
    async with db._pg_pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE notification_outbox, incident_revisions, incidents CASCADE;")
    repo = Repository(db)
    yield repo
    await db.close()


@pytest.mark.asyncio
async def test_digest_filtering_and_counts_pg(pg_repo):
    """M5: get_digest_summary selects DIGEST and RETAIN_* incidents, excludes URGENT, and reports distinct event vs incident counts."""
    now = datetime.now(timezone.utc)
    since_dt = now - timedelta(minutes=15)

    # 1. Digest incident (e.g. port scan / scanner, 10 events)
    inc_digest = {
        "id": "INC-DIGEST-01",
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "source_ip": "198.51.100.5",
        "target_ip": "10.0.14.120",
        "first_seen": (now - timedelta(minutes=5)).isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 10,
        "summary": "Port scanner",
        "deterministic_severity": "MEDIUM",
        "deterministic_enforcement": "BLOCKED",
        "deterministic_rule_ids": ["RULE_HIGH_FREQUENCY_SCANNER"],
    }
    rev_digest = {
        "incident_id": "INC-DIGEST-01",
        "revision": 1,
        "rule_ids": ["RULE_HIGH_FREQUENCY_SCANNER"],
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "assessment_json": {"routing": "DIGEST", "severity": "MEDIUM"},
        "assessment_source": "DETERMINISTIC",
    }
    await pg_repo.record_incident_transition(inc_digest, rev_digest)

    # 2. Retain incident (e.g. unknown action mapping, 4 events)
    inc_retain = {
        "id": "INC-RETAIN-02",
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "LOW",
        "enforcement": "UNKNOWN",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.14.120",
        "first_seen": (now - timedelta(minutes=2)).isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 4,
        "summary": "Unknown action mapping",
        "deterministic_severity": "LOW",
        "deterministic_enforcement": "UNKNOWN",
        "deterministic_rule_ids": ["RULE_UNKNOWN_ACTION_MAPPING"],
    }
    rev_retain = {
        "incident_id": "INC-RETAIN-02",
        "revision": 1,
        "rule_ids": ["RULE_UNKNOWN_ACTION_MAPPING"],
        "severity": "LOW",
        "enforcement": "UNKNOWN",
        "assessment_json": {"routing": "RETAIN_WITH_VISIBILITY_GAP", "severity": "LOW"},
        "assessment_source": "DETERMINISTIC",
    }
    await pg_repo.record_incident_transition(inc_retain, rev_retain)

    # 3. Urgent incident with URGENT card in outbox (e.g. nonblocked exploit, 3 events) -> must be excluded!
    inc_urgent = {
        "id": "INC-URGENT-03",
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "CRITICAL",
        "enforcement": "ALLOWED_OR_DETECTED",
        "source_ip": "203.0.113.88",
        "target_ip": "10.0.14.120",
        "first_seen": (now - timedelta(minutes=1)).isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 3,
        "summary": "Exploit probe",
        "deterministic_severity": "CRITICAL",
        "deterministic_enforcement": "ALLOWED_OR_DETECTED",
        "deterministic_rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        "last_urgent_at": now,
    }
    rev_urgent = {
        "incident_id": "INC-URGENT-03",
        "revision": 1,
        "rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        "severity": "CRITICAL",
        "enforcement": "ALLOWED_OR_DETECTED",
        "assessment_json": {"routing": "URGENT_ALERT_AND_INVESTIGATE", "severity": "CRITICAL"},
        "assessment_source": "DETERMINISTIC",
    }
    notif_urgent = {
        "incident_id": "INC-URGENT-03",
        "revision": 1,
        "notification_type": "URGENT",
        "payload": {"text": "URGENT ALERT"},
    }
    await pg_repo.record_incident_transition(inc_urgent, rev_urgent, notification=notif_urgent)

    # Query digest summary
    summary = await pg_repo.get_digest_summary(since_dt)

    # Asserts:
    # 1. Urgent incident must be excluded
    # 2. total_incidents = 2 (DIGEST-01 and RETAIN-02)
    assert summary["total_incidents"] == 2
    # 3. total_events = 14 (10 from DIGEST-01 + 4 from RETAIN-02)
    assert summary["total_events"] == 14
    # 4. Correct counts by source
    assert summary["counts_by_source"].get("198.51.100.5") == 10
    assert summary["counts_by_source"].get("198.51.100.99") == 4
    assert "203.0.113.88" not in summary["counts_by_source"]
    # 5. Counts by rule
    assert summary["counts_by_rule"].get("RULE_HIGH_FREQUENCY_SCANNER") == 1
    assert summary["counts_by_rule"].get("RULE_UNKNOWN_ACTION_MAPPING") == 1
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" not in summary["counts_by_rule"]
