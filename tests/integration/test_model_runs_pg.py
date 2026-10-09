"""Integration tests for audited model_runs persistence and commit_status tracking on PostgreSQL 16 (M4, D7)."""

import os
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from src.storage.database import Database
from src.storage.repository import Repository, RevisionConflict

TEST_PG_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test",
)


@pytest_asyncio.fixture
async def pg_repo():
    db = Database(TEST_PG_URL)
    await db.connect()
    async with db._pg_pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE model_runs, incident_revisions, incidents CASCADE;")
    repo = Repository(db)
    yield repo
    await db.close()


@pytest.mark.asyncio
async def test_model_run_committed_on_successful_transition_pg(pg_repo):
    """M4: A successful incident transition writes a model_runs row with commit_status='COMMITTED'."""
    now = datetime.now(timezone.utc)
    inc_data = {
        "id": "INC-MRUN-001",
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "CRITICAL",
        "enforcement": "ALLOWED_OR_DETECTED",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "first_seen": now.isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 2,
        "summary": "Log4j probe",
    }
    rev_data = {
        "incident_id": "INC-MRUN-001",
        "revision": 1,
        "rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        "severity": "CRITICAL",
        "enforcement": "ALLOWED_OR_DETECTED",
        "assessment_json": {"severity": "CRITICAL"},
        "assessment_source": "MODEL_VALIDATED",
    }
    mrun_data = {
        "incident_id": "INC-MRUN-001",
        "revision": 1,
        "model_id": "qwen3.8-27b",
        "server_reported_model": "qwen3.8-27b",
        "prompt_version": "1.0.0",
        "schema_version": "1.0.0",
        "input_hash": "a" * 64,
        "input_tokens": 150,
        "output_tokens": 40,
        "latency_ms": 350,
        "structured_output_mode": "json_schema",
        "validation_result": "VALID",
        "reason_codes": [],
    }

    await pg_repo.record_incident_transition(
        incident=inc_data,
        revision=rev_data,
        model_run=mrun_data,
        expected_revision=None,
    )

    row = await pg_repo.db.fetch_one("SELECT * FROM model_runs WHERE incident_id = 'INC-MRUN-001'")
    assert row is not None
    assert row["commit_status"] == "COMMITTED"
    assert row["revision"] == 1
    assert row["model_id"] == "qwen3.8-27b"
    assert row["validation_result"] == "VALID"
    assert row["input_tokens"] == 150


@pytest.mark.asyncio
async def test_model_run_conflict_preserved_on_revision_conflict_pg(pg_repo):
    """M4: A forced RevisionConflict still preserves the model_runs row with commit_status='CONFLICT'."""
    now = datetime.now(timezone.utc)
    # 1. Seed incident at revision 2
    inc_data = {
        "id": "INC-MRUN-CONFLICT",
        "current_revision": 2,
        "status": "ACTIVE",
        "severity": "HIGH",
        "enforcement": "BLOCKED",
        "source_ip": "198.51.100.99",
        "target_ip": "10.0.14.120",
        "first_seen": now.isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 5,
        "summary": "Port probe",
    }
    await pg_repo.upsert_incident(inc_data)

    # 2. Attempt transition expecting revision 1 (stale)
    mrun_data = {
        "incident_id": "INC-MRUN-CONFLICT",
        "revision": 2,
        "model_id": "qwen3.8-27b",
        "server_reported_model": "qwen3.8-27b",
        "prompt_version": "1.0.0",
        "schema_version": "1.0.0",
        "input_hash": "b" * 64,
        "input_tokens": 200,
        "output_tokens": 50,
        "latency_ms": 400,
        "structured_output_mode": "json_schema",
        "validation_result": "VALID",
        "reason_codes": [],
    }

    with pytest.raises(RevisionConflict):
        await pg_repo.record_incident_transition(
            incident=inc_data,
            revision={
                "incident_id": "INC-MRUN-CONFLICT",
                "revision": 2,
                "rule_ids": ["RULE_PORT_SCAN_MULTI_SERVICE"],
                "severity": "HIGH",
                "enforcement": "BLOCKED",
                "assessment_json": {"severity": "HIGH"},
                "assessment_source": "MODEL_VALIDATED",
            },
            model_run=mrun_data,
            expected_revision=1,  # Intentional conflict (current is 2)
        )

    # 3. Verify model_runs row was NOT rolled back, and status was updated to CONFLICT
    row = await pg_repo.db.fetch_one("SELECT * FROM model_runs WHERE incident_id = 'INC-MRUN-CONFLICT'")
    assert row is not None
    assert row["commit_status"] == "CONFLICT"
    assert row["input_tokens"] == 200
    assert row["model_id"] == "qwen3.8-27b"
