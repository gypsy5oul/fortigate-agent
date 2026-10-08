"""Integration tests for episode persistence, closing, and restore on PostgreSQL 16 (D5)."""

import os
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
        await conn.execute("TRUNCATE TABLE episodes, incidents, incident_revisions CASCADE;")
    repo = Repository(db)
    yield repo
    await db.close()


@pytest.mark.asyncio
async def test_episode_save_and_restore_pg(pg_repo):
    """Episodes save enforcement_counts (JSONB) and signatures (TEXT[]) and restore accurately."""
    now = datetime.now(timezone.utc)
    episode = {
        "id": "EP-PG-001",
        "incident_id": "INC-PG-001",
        "vdom": "root",
        "direction": "INBOUND",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "first_seen": (now - timedelta(seconds=60)).isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 5,
        "enforcement": "MIXED",
        "enforcement_counts": {"BLOCKED": 3, "ALLOWED_OR_DETECTED": 2},
        "signatures": ["Apache.Log4j.Error.Log.Remote.Code.Execution", "CVE-2021-44228"],
        "status": "OPEN",
    }

    await pg_repo.save_episodes([episode])

    # Restore
    restored = await pg_repo.load_open_episodes(idle_timeout_seconds=300)
    assert len(restored) == 1
    ep = restored[0]
    assert ep["id"] == "EP-PG-001"
    assert ep["incident_id"] == "INC-PG-001"
    assert ep["enforcement"] == "MIXED"
    assert ep["enforcement_counts"] == {"BLOCKED": 3, "ALLOWED_OR_DETECTED": 2}
    assert "Apache.Log4j.Error.Log.Remote.Code.Execution" in ep["signatures"]
    assert "CVE-2021-44228" in ep["signatures"]


@pytest.mark.asyncio
async def test_episode_prune_closes_rows_pg(pg_repo):
    """Closing episodes marks their database status as CLOSED so they are no longer restored."""
    now = datetime.now(timezone.utc)
    episode = {
        "id": "EP-PG-CLOSE-001",
        "incident_id": "INC-PG-CLOSE-001",
        "vdom": "root",
        "direction": "INBOUND",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.14.120",
        "first_seen": now.isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 1,
        "enforcement": "BLOCKED",
        "enforcement_counts": {"BLOCKED": 1},
        "signatures": [],
        "status": "OPEN",
    }
    await pg_repo.save_episodes([episode])

    # Close the episode
    await pg_repo.close_episodes(["EP-PG-CLOSE-001"])

    # Verify status in database
    row = await pg_repo.db.fetch_one("SELECT status FROM episodes WHERE id = 'EP-PG-CLOSE-001'")
    assert row is not None
    assert row["status"] == "CLOSED"

    # Verify load_open_episodes excludes it
    restored = await pg_repo.load_open_episodes(idle_timeout_seconds=300)
    assert len(restored) == 0


@pytest.mark.asyncio
async def test_restore_skips_and_closes_stale_rows_pg(pg_repo):
    """load_open_episodes automatically closes episodes older than idle_timeout relative to newest row."""
    now = datetime.now(timezone.utc)
    stale_ep = {
        "id": "EP-PG-STALE",
        "incident_id": "INC-PG-STALE",
        "vdom": "root",
        "direction": "INBOUND",
        "source_ip": "198.51.100.10",
        "target_ip": "10.0.14.120",
        "first_seen": (now - timedelta(seconds=500)).isoformat(),
        "last_seen": (now - timedelta(seconds=400)).isoformat(),
        "event_count": 2,
        "enforcement": "BLOCKED",
        "enforcement_counts": {"BLOCKED": 2},
        "signatures": [],
        "status": "OPEN",
    }
    fresh_ep = {
        "id": "EP-PG-FRESH",
        "incident_id": "INC-PG-FRESH",
        "vdom": "root",
        "direction": "INBOUND",
        "source_ip": "198.51.100.20",
        "target_ip": "10.0.14.120",
        "first_seen": (now - timedelta(seconds=10)).isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 3,
        "enforcement": "BLOCKED",
        "enforcement_counts": {"BLOCKED": 3},
        "signatures": [],
        "status": "OPEN",
    }
    await pg_repo.save_episodes([stale_ep, fresh_ep])

    # idle_timeout_seconds = 120 (stale_ep is 400s older than fresh_ep)
    restored = await pg_repo.load_open_episodes(idle_timeout_seconds=120)

    # Only fresh episode restored
    assert len(restored) == 1
    assert restored[0]["id"] == "EP-PG-FRESH"

    # Stale episode row was closed in database
    stale_row = await pg_repo.db.fetch_one("SELECT status FROM episodes WHERE id = 'EP-PG-STALE'")
    assert stale_row["status"] == "CLOSED"


@pytest.mark.asyncio
async def test_restored_episode_plus_new_deny_still_matches_exploit_rule_pg(pg_repo):
    """B.1 Defect A, PostgreSQL round trip: persist a CRITICAL MIXED episode, restore it into a
    fresh aggregator, add one blocked probe, evaluate. The exploit rule must still match and
    the floor must still be CRITICAL."""
    from src.correlator.session_aggregator import SessionAggregator
    from src.rules.engine import RuleEngine
    from src.parsing.normalizer import normalize_event

    now = datetime.now(timezone.utc)
    episode = {
        "id": "EP-PG-RESTART-001",
        "incident_id": "INC-PG-RESTART-001",
        "vdom": "root",
        "direction": "INBOUND",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "service": "HTTPS",
        "first_seen": (now - timedelta(seconds=60)).isoformat(),
        "last_seen": now.isoformat(),
        "last_event_ts_ns": int(now.timestamp() * 1e9),
        "event_count": 13,
        "enforcement": "MIXED",
        "enforcement_counts": {"BLOCKED": 12, "ALLOWED_OR_DETECTED": 1},
        "signatures": ["Apache.Log4j.Error.Log.Remote.Code.Execution", "CVE-2021-44228"],
        "utm_subtypes": ["ips"],
        "status": "OPEN",
    }
    await pg_repo.save_episodes([episode])

    records = await pg_repo.load_open_episodes(idle_timeout_seconds=300)
    assert len(records) == 1
    assert list(records[0]["utm_subtypes"]) == ["ips"]

    aggregator = SessionAggregator(idle_timeout_seconds=120, max_episode_seconds=600)
    aggregator.load_open_episodes(records)

    deny_ts_ns = int((now + timedelta(seconds=5)).timestamp() * 1e9)
    deny = normalize_event(
        deny_ts_ns,
        'date=2026-10-08 time=12:02:00 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
        'subtype="forward" level="notice" vd="root" sessionid=500001 srcip=198.51.100.45 srcport=46000 '
        'dstip=10.0.14.120 dstport=22 proto=6 service="SSH" action="deny" policyid=0',
    )
    assert deny is not None
    deny["id"] = "EVID-RESTART-DENY-1"
    deny["loki_ts_ns"] = deny_ts_ns

    touched = aggregator.process_events([deny])
    assert len(touched) == 1
    ep = touched[0]
    assert ep["incident_id"] == "INC-PG-RESTART-001"
    assert ep["restored"] is True
    assert ep["event_count"] == 14
    assert len(ep["events"]) == 1  # only the new event is in memory

    result = RuleEngine().evaluate_episode(ep)
    assert "RULE_NONBLOCKED_EXPLOIT_ATTEMPT" in result["matched_rule_ids"]
    assert result["severity_floor"] == "CRITICAL"
