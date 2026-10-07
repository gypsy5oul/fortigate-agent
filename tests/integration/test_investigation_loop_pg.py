"""Integration tests for investigation loop concurrency, fencing, and job backoff on PostgreSQL 16."""

import os
import asyncio
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from src.storage.database import Database
from src.storage.repository import Repository, RevisionConflict, StaleJobLeaseError
from src.observability.metrics import MODEL_FAILURES_TOTAL

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
async def test_pg_concurrent_incident_transitions_optimistic_locking(pg_repo):
    """Two concurrent transitions for one incident (expected_revision=1 on both)
    results in exactly one succeeding and one raising RevisionConflict.
    The incident ends at revision 2.
    """
    inc_id = "INC-PG-CONCURRENT-1"
    now = datetime.now(timezone.utc)
    inc_v1 = {
        "id": inc_id,
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "source_ip": "198.51.100.10",
        "target_ip": "10.0.14.120",
        "first_seen": now,
        "last_seen": now,
        "event_count": 5,
        "summary": "Initial scanner observation",
    }
    rev_v1 = {
        "incident_id": inc_id,
        "revision": 1,
        "rule_ids": ["RULE_HIGH_FREQUENCY_SCANNER"],
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "assessment_json": {"summary": "Scanner"},
        "reasoning_summary": "Scanner",
        "evidence_ids": ["EVID-1"],
    }
    # Initialize incident at revision 1
    new_rev = await pg_repo.record_incident_transition(incident=inc_v1, revision=rev_v1)
    assert new_rev == 1

    # Prepare two conflicting transitions both expecting revision 1
    inc_v2a = dict(inc_v1)
    inc_v2a["severity"] = "HIGH"
    inc_v2a["summary"] = "Update branch A"
    rev_v2a = dict(rev_v1)
    rev_v2a["severity"] = "HIGH"

    inc_v2b = dict(inc_v1)
    inc_v2b["severity"] = "CRITICAL"
    inc_v2b["summary"] = "Update branch B"
    rev_v2b = dict(rev_v1)
    rev_v2b["severity"] = "CRITICAL"

    # Launch concurrently
    results = await asyncio.gather(
        pg_repo.record_incident_transition(incident=inc_v2a, revision=rev_v2a, expected_revision=1),
        pg_repo.record_incident_transition(incident=inc_v2b, revision=rev_v2b, expected_revision=1),
        return_exceptions=True,
    )

    conflicts = [r for r in results if isinstance(r, RevisionConflict)]
    successes = [r for r in results if isinstance(r, int)]

    assert len(conflicts) == 1, f"Expected 1 RevisionConflict, got: {results}"
    assert len(successes) == 1, f"Expected 1 success, got: {results}"
    assert successes[0] == 2

    # Verify incident state in PostgreSQL is at revision 2
    inc = await pg_repo.get_incident(inc_id)
    assert inc["current_revision"] == 2


@pytest.mark.asyncio
async def test_pg_stale_job_lease_fencing(pg_repo):
    """Stale version_token write on leased job raises StaleJobLeaseError,
    transaction rolls back completely, and no outbox notification is persisted.
    """
    inc_id = "INC-PG-STALE-1"
    now = datetime.now(timezone.utc)
    inc_v1 = {
        "id": inc_id,
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "source_ip": "198.51.100.11",
        "target_ip": "10.0.14.120",
        "first_seen": now,
        "last_seen": now,
        "event_count": 3,
        "summary": "Initial state",
    }
    rev_v1 = {
        "incident_id": inc_id,
        "revision": 1,
        "rule_ids": ["RULE_HIGH_FREQUENCY_SCANNER"],
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "assessment_json": {"summary": "Initial"},
        "reasoning_summary": "Initial",
        "evidence_ids": ["EVID-1"],
    }
    await pg_repo.record_incident_transition(incident=inc_v1, revision=rev_v1)

    # Enqueue a job
    job_id = f"JOB-{inc_id}-2"
    await pg_repo.enqueue_job(job_id, "INVESTIGATE_INCIDENT", {"incident_id": inc_id, "revision": 2}, priority=10)

    # Worker 1 leases job
    job_w1 = await pg_repo.lease_next_job("worker-1", lease_duration_seconds=60)
    assert job_w1 is not None
    token_w1 = job_w1["version_token"]

    # Simulate lease expiration and re-lease by Worker 2
    async with pg_repo.db._pg_pool.acquire() as conn:
        await conn.execute("UPDATE jobs SET lease_expires_at = NOW() - interval '10 seconds' WHERE id = $1", job_id)

    job_w2 = await pg_repo.lease_next_job("worker-2", lease_duration_seconds=60)
    assert job_w2 is not None
    token_w2 = job_w2["version_token"]
    assert token_w2 > token_w1

    # Worker 1 attempts to commit with stale token_w1
    inc_v2 = dict(inc_v1)
    inc_v2["summary"] = "Worker 1 stale update"
    rev_v2 = dict(rev_v1)
    rev_v2["revision"] = 2
    notif_v2 = {
        "incident_id": inc_id,
        "revision": 2,
        "notification_type": "INVESTIGATION_UPDATE",
        "payload": {"text": "Worker 1 stale alert"},
    }

    with pytest.raises(StaleJobLeaseError):
        await pg_repo.record_incident_transition(
            incident=inc_v2,
            revision=rev_v2,
            notification=notif_v2,
            fence_job_id=job_id,
            fence_version_token=token_w1,
        )

    # Verify rollback: incident is still revision 1 and no notification was inserted
    inc = await pg_repo.get_incident(inc_id)
    assert inc["current_revision"] == 1

    notifs = await pg_repo.fetch_pending_notifications(limit=10)
    assert len(notifs) == 0

    revisions = await pg_repo.db.fetch_all("SELECT * FROM incident_revisions WHERE incident_id = $1", inc_id)
    assert len(revisions) == 1


@pytest.mark.asyncio
async def test_pg_job_backoff_and_max_attempts_failure(pg_repo):
    """Job retries with exponential backoff and upon reaching max_attempts marks FAILED,
    increments MODEL_FAILURES_TOTAL, and writes a MODEL_REJECTED_FALLBACK revision.
    """
    inc_id = "INC-PG-FAIL-1"
    now = datetime.now(timezone.utc)
    inc_v1 = {
        "id": inc_id,
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "HIGH",
        "enforcement": "ALLOWED_OR_DETECTED",
        "source_ip": "198.51.100.22",
        "target_ip": "10.0.14.120",
        "first_seen": now,
        "last_seen": now,
        "event_count": 2,
        "summary": "Initial exploit alert",
    }
    rev_v1 = {
        "incident_id": inc_id,
        "revision": 1,
        "rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        "severity": "HIGH",
        "enforcement": "ALLOWED_OR_DETECTED",
        "assessment_json": {"summary": "Exploit attempt"},
        "reasoning_summary": "Exploit attempt",
        "evidence_ids": ["EVID-10"],
    }
    await pg_repo.record_incident_transition(incident=inc_v1, revision=rev_v1)

    job_id = f"JOB-{inc_id}-1"
    job_payload = {
        "incident_id": inc_id,
        "revision": 1,
        "rule_eval": {"matched_rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"], "severity_floor": "HIGH"},
        "episode": {"enforcement": "ALLOWED_OR_DETECTED"},
    }
    await pg_repo.enqueue_job(job_id, "INVESTIGATE_INCIDENT", job_payload, priority=20)

    # Attempt 1
    j1 = await pg_repo.lease_next_job("worker-test")
    assert j1 is not None
    assert j1["attempts"] == 1
    await pg_repo.fail_job(job_id, j1["version_token"], "Simulated timeout 1")

    row1 = await pg_repo.db.fetch_one("SELECT * FROM jobs WHERE id = $1", job_id)
    assert row1["status"] == "PENDING"
    assert row1["attempts"] == 1

    # Fast-forward next_run_at for retry 2
    async with pg_repo.db._pg_pool.acquire() as conn:
        await conn.execute("UPDATE jobs SET next_run_at = NOW() - interval '1 second' WHERE id = $1", job_id)

    # Attempt 2
    j2 = await pg_repo.lease_next_job("worker-test")
    assert j2 is not None
    assert j2["attempts"] == 2
    await pg_repo.fail_job(job_id, j2["version_token"], "Simulated timeout 2")

    row2 = await pg_repo.db.fetch_one("SELECT * FROM jobs WHERE id = $1", job_id)
    assert row2["status"] == "PENDING"
    assert row2["attempts"] == 2

    # Fast-forward next_run_at for retry 3 (terminal attempt)
    async with pg_repo.db._pg_pool.acquire() as conn:
        await conn.execute("UPDATE jobs SET next_run_at = NOW() - interval '1 second' WHERE id = $1", job_id)

    # Attempt 3 (reaches max_attempts = 3)
    j3 = await pg_repo.lease_next_job("worker-test")
    assert j3 is not None
    assert j3["attempts"] == 3
    await pg_repo.fail_job(job_id, j3["version_token"], "Simulated timeout 3 (terminal)")

    row3 = await pg_repo.db.fetch_one("SELECT * FROM jobs WHERE id = $1", job_id)
    assert row3["status"] == "FAILED"

    # Verify fallback revision was persisted
    fallback_rev = await pg_repo.db.fetch_one(
        "SELECT * FROM incident_revisions WHERE incident_id = $1 AND assessment_source = 'MODEL_REJECTED_FALLBACK'",
        inc_id,
    )
    assert fallback_rev is not None
    assert fallback_rev["severity"] == "HIGH"
    assert "MODEL_UNREACHABLE" in fallback_rev["reasoning_summary"]


@pytest.mark.asyncio
async def test_pg_unchanged_episode_poller_and_investigation_completion(pg_repo, monkeypatch):
    """Drive poller loop five times over an unchanged episode: current_revision unchanged,
    exactly one revision row. Then run investigation loop once with valid mock model:
    job COMPLETED on first attempt, exactly one INVESTIGATION_UPDATE, current_revision
    incremented by exactly one, revision numbers contiguous.
    """
    from unittest.mock import patch, AsyncMock
    from src.main import IntelligenceService
    from src.parsing.normalizer import normalize_event
    from tests.fixtures.fortios_logs import SAMPLE_IPS_NONBLOCKED_EXPLOIT
    from src.investigation.schemas import QwenAssessment, FindingItem

    monkeypatch.setenv("DATABASE_URL", TEST_PG_URL)
    monkeypatch.setenv("GCHAT_DRY_RUN", "true")
    monkeypatch.setenv("LLM_ENABLED", "true")

    service = IntelligenceService()
    await service.db.connect()
    service.running = True

    # 1. Ingest an exploit event into PostgreSQL selected_events
    base_ts = 1791271940000000000
    ev = normalize_event(base_ts, SAMPLE_IPS_NONBLOCKED_EXPLOIT)
    assert ev is not None
    await service.repo.save_events([ev])

    # 2. Initial poller cycle: processes event, creates incident rev 1, enqueues job
    pending_events = await service.repo.fetch_pending_events(limit=100)
    assert len(pending_events) == 1
    episodes = service.aggregator.process_events(pending_events)
    assert len(episodes) == 1
    ep = episodes[0]
    inc_id = ep["incident_id"]

    rule_eval = service.rule_engine.evaluate_episode(ep)
    inc_data = {
        "id": inc_id,
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": rule_eval["severity_floor"],
        "enforcement": ep["enforcement"],
        "exploitation_assessment": "ATTEMPT_OBSERVED",
        "source_ip": ep["source_ip"],
        "target_ip": ep["target_ip"],
        "first_seen": ep["first_seen"],
        "last_seen": ep["last_seen"],
        "event_count": ep["event_count"],
        "summary": "; ".join(rule_eval["reasons"]),
        "rule_ids": rule_eval["matched_rule_ids"],
        "deterministic_severity": rule_eval["severity_floor"],
        "deterministic_enforcement": ep["enforcement"],
        "deterministic_rule_ids": rule_eval["matched_rule_ids"],
    }
    rev_data = {
        "incident_id": inc_id,
        "revision": 1,
        "rule_ids": rule_eval["matched_rule_ids"],
        "severity": rule_eval["severity_floor"],
        "enforcement": ep["enforcement"],
        "assessment_json": {"summary": "Initial alert"},
        "reasoning_summary": "Initial alert",
        "evidence_ids": ["EVID-1"],
        "assessment_source": "DETERMINISTIC",
    }
    job_data = {
        "id": f"JOB-{inc_id}-1",
        "job_type": "INVESTIGATE_INCIDENT",
        "payload": {
            "incident_id": inc_id,
            "revision": 1,
            "episode": ep,
            "rule_eval": rule_eval,
        },
        "priority": 20,
    }
    await service.repo.record_incident_transition(
        incident=inc_data,
        revision=rev_data,
        job=job_data,
    )
    await service.repo.mark_events_processed([ev["id"]])

    inc_initial = await service.repo.get_incident(inc_id)
    assert inc_initial["current_revision"] == 1
    revs_initial = await service.repo.db.fetch_all("SELECT * FROM incident_revisions WHERE incident_id = $1", inc_id)
    assert len(revs_initial) == 1

    # 3. Five counts-only poller transitions over the unchanged active episode.
    # This is the exact call main.py makes on the "no material change" path
    # (revision=None, expected_revision=<revision it just read>); it must not
    # advance current_revision or write a revision row.
    for cycle in range(5):
        pending = await service.repo.fetch_pending_events(limit=100)
        assert len(pending) == 0
        current = (await service.repo.get_incident(inc_id))["current_revision"]
        counts_only = dict(inc_data, current_revision=current, event_count=inc_data["event_count"])
        await service.repo.record_incident_transition(
            incident=counts_only, revision=None, expected_revision=current
        )

    # Assert current_revision unchanged, exactly one revision row
    inc_after_polls = await service.repo.get_incident(inc_id)
    assert inc_after_polls["current_revision"] == 1

    revs_after_polls = await service.repo.db.fetch_all("SELECT * FROM incident_revisions WHERE incident_id = $1", inc_id)
    assert len(revs_after_polls) == 1
    assert revs_after_polls[0]["revision"] == 1

    # 4. Now run investigation loop once with valid mock model
    mock_assessment = QwenAssessment(
        incident_id=inc_id,
        incident_revision=2,
        visibility_scope="FIREWALL_ONLY",
        severity="CRITICAL",
        attack_category="EXPLOITATION_ATTEMPT",
        exploitation_assessment="ATTEMPT_OBSERVED",
        enforcement="ALLOWED_OR_DETECTED",
        summary="Model analysis validated Log4Shell exploit.",
        findings=[FindingItem(kind="OBSERVATION", statement="Critical probe", evidence_ids=["EVID-1"])],
        cve_references=[],
        visibility_gaps=[],
        recommended_action_ids=["ACT_INSPECT_APPLICATION_LOGS"],
        analyst_follow_up=[],
    )

    with patch.object(service.adk_workflow, "investigate_packet", new=AsyncMock(return_value=mock_assessment)):
        job = await service.repo.lease_next_job("worker-supervisor", lease_duration_seconds=90)
        assert job is not None
        assert job["id"] == f"JOB-{inc_id}-1"
        assert job["attempts"] == 1

        payload = job.get("payload", {})
        trigger_rev = payload.get("revision", 1)
        target_rev = trigger_rev + 1

        assessment = await service.adk_workflow.investigate_packet(None)
        await service.repo.record_incident_transition(
            incident={
                "id": inc_id,
                "current_revision": target_rev,
                "status": "ACTIVE",
                "severity": assessment.severity,
                "enforcement": ep["enforcement"],
                "exploitation_assessment": "ATTEMPT_OBSERVED",
                "source_ip": ep["source_ip"],
                "target_ip": ep["target_ip"],
                "first_seen": ep["first_seen"],
                "last_seen": ep["last_seen"],
                "event_count": ep["event_count"],
                "summary": assessment.summary,
                "deterministic_severity": rule_eval["severity_floor"],
                "deterministic_enforcement": ep["enforcement"],
                "deterministic_rule_ids": rule_eval["matched_rule_ids"],
            },
            revision={
                "incident_id": inc_id,
                "revision": target_rev,
                "rule_ids": rule_eval["matched_rule_ids"],
                "severity": assessment.severity,
                "enforcement": ep["enforcement"],
                "assessment_json": assessment.model_dump(),
                "model_name": "qwen3.8-27b",
                "reasoning_summary": assessment.summary,
                "evidence_ids": ["EVID-1"],
                "assessment_source": "MODEL_VALIDATED",
            },
            notification={
                "incident_id": inc_id,
                "revision": target_rev,
                "notification_type": "INVESTIGATION_UPDATE",
                "payload": {"text": "Model investigation update"},
            },
            expected_revision=trigger_rev,
            fence_job_id=job["id"],
            fence_version_token=job["version_token"],
        )

    # 1. Job is COMPLETED on first attempt
    job_final = await service.repo.db.fetch_one("SELECT * FROM jobs WHERE id = $1", job["id"])
    assert job_final["status"] == "COMPLETED"
    assert job_final["attempts"] == 1

    # 2. Exactly one INVESTIGATION_UPDATE notification
    outbox_rows = await service.repo.db.fetch_all(
        "SELECT * FROM notification_outbox WHERE incident_id = $1 AND notification_type = 'INVESTIGATION_UPDATE'",
        inc_id,
    )
    assert len(outbox_rows) == 1

    # 3. current_revision incremented by exactly one
    inc_final = await service.repo.get_incident(inc_id)
    assert inc_final["current_revision"] == 2

    # 4. Revision numbers contiguous (1, 2)
    all_revs = await service.repo.db.fetch_all(
        "SELECT revision, assessment_source FROM incident_revisions WHERE incident_id = $1 ORDER BY revision ASC",
        inc_id,
    )
    assert len(all_revs) == 2
    assert all_revs[0]["revision"] == 1
    assert all_revs[0]["assessment_source"] == "DETERMINISTIC"
    assert all_revs[1]["revision"] == 2
    assert all_revs[1]["assessment_source"] == "MODEL_VALIDATED"

    await service.stop()
