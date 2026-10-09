"""C1.7 mode plumbing in src/main.py: legacy never loads ADK, and a failing shadow run never fails the
job or the legacy write (PostgreSQL)."""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

pytest.importorskip("google.adk")

from src.investigation.schemas import FindingItem, QwenAssessment  # noqa: E402
from src.storage.database import Database  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TEST_PG_URL = os.getenv("TEST_DATABASE_URL", "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test")


def test_legacy_mode_does_not_import_adk():
    code = (
        "import sys\n"
        "from src.main import IntelligenceService\n"
        "s = IntelligenceService()\n"
        "assert s.settings.investigator_mode == 'legacy'\n"
        "assert s.agent_investigator is None\n"
        "loaded = sorted(m for m in sys.modules if m.startswith(('google.adk', 'src.investigation.agent', 'openai')))\n"
        "assert not loaded, loaded\n"
        "print('legacy-ok')\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "INVESTIGATOR_MODE"}
    env.update(DATABASE_URL="sqlite:///:memory:", GCHAT_DRY_RUN="true")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    assert "legacy-ok" in out.stdout


@pytest_asyncio.fixture
async def pg():
    db = Database(TEST_PG_URL)
    await db.connect()
    async with db._pg_pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE TABLE selected_events, incidents, incident_revisions, jobs, notification_outbox, "
            "model_runs, agent_runs, agent_events, shadow_assessments CASCADE"
        )
    yield db
    await db.close()


async def test_shadow_failure_never_fails_the_job_or_the_legacy_write(pg, monkeypatch):
    from src.main import IntelligenceService
    from src.parsing.normalizer import normalize_event
    from tests.fixtures.fortios_logs import SAMPLE_IPS_NONBLOCKED_EXPLOIT

    monkeypatch.setenv("DATABASE_URL", TEST_PG_URL)
    monkeypatch.setenv("GCHAT_DRY_RUN", "true")
    monkeypatch.setenv("INVESTIGATOR_MODE", "shadow")
    service = IntelligenceService()
    assert service.agent_investigator is not None
    await service.db.connect()
    service.running = True

    ev = normalize_event(1791271940000000000, SAMPLE_IPS_NONBLOCKED_EXPLOIT)
    episode = service.aggregator.process_events([dict(ev, id=ev["id"])])[0]
    rule_eval = service.rule_engine.evaluate_episode(episode)
    inc_id = episode["incident_id"]
    await service.repo.record_incident_transition(
        incident={
            "id": inc_id, "current_revision": 1, "status": "ACTIVE", "severity": "CRITICAL",
            "enforcement": episode["enforcement"], "source_ip": episode["source_ip"], "target_ip": episode["target_ip"],
            "first_seen": episode["first_seen"], "last_seen": episode["last_seen"], "event_count": 1, "summary": "seed",
            "deterministic_severity": "CRITICAL", "deterministic_enforcement": episode["enforcement"],
            "deterministic_rule_ids": rule_eval["matched_rule_ids"],
        },
        revision={
            "incident_id": inc_id, "revision": 1, "rule_ids": rule_eval["matched_rule_ids"], "severity": "CRITICAL",
            "enforcement": episode["enforcement"], "assessment_json": {"summary": "seed"}, "reasoning_summary": "seed",
            "evidence_ids": [ev["id"]], "assessment_source": "DETERMINISTIC",
        },
        job={
            "id": f"JOB-{inc_id}-1", "job_type": "INVESTIGATE_INCIDENT", "priority": 20,
            "payload": {"incident_id": inc_id, "revision": 1, "episode": episode, "rule_eval": rule_eval},
        },
    )
    legacy = QwenAssessment(
        incident_id=inc_id, incident_revision=2, severity="CRITICAL", attack_category="EXPLOITATION_ATTEMPT",
        exploitation_assessment="ATTEMPT_OBSERVED", enforcement=episode["enforcement"], summary="Legacy assessment.",
        findings=[FindingItem(kind="OBSERVATION", statement="IPS match", evidence_ids=[ev["id"]])],
        recommended_action_ids=["ACT_INSPECT_APPLICATION_LOGS"], assessment_source="MODEL_VALIDATED",
    )
    service.investigation_workflow.investigate_packet = AsyncMock(return_value=legacy)
    service.agent_investigator.investigate = AsyncMock(side_effect=RuntimeError("shadow pipeline exploded"))

    loop_task = asyncio.create_task(service._run_investigation_loop())
    try:
        for _ in range(100):
            job = await pg.fetch_one("SELECT status FROM jobs WHERE id = $1", f"JOB-{inc_id}-1")
            if job["status"] != "PENDING" and service.agent_investigator.investigate.await_count:
                break
            await asyncio.sleep(0.05)
    finally:
        service.running = False
        service.stop_event.set()
        await asyncio.wait_for(loop_task, timeout=10)
        await service.stop()

    assert service.agent_investigator.investigate.await_count == 1  # the shadow run was attempted
    job = await pg.fetch_one("SELECT status, attempts FROM jobs WHERE id = $1", f"JOB-{inc_id}-1")
    assert (job["status"], job["attempts"]) == ("COMPLETED", 1)
    revs = await pg.fetch_all("SELECT revision, assessment_source FROM incident_revisions WHERE incident_id = $1 ORDER BY revision", inc_id)
    assert [(r["revision"], r["assessment_source"]) for r in revs] == [(1, "DETERMINISTIC"), (2, "MODEL_VALIDATED")]
    outbox = await pg.fetch_all("SELECT notification_type FROM notification_outbox WHERE incident_id = $1", inc_id)
    assert [o["notification_type"] for o in outbox] == ["INVESTIGATION_UPDATE"]
    assert await pg.fetch_all("SELECT id FROM shadow_assessments") == []


def test_broken_agent_setup_disables_shadow_but_is_fatal_in_adk_mode(monkeypatch):
    import src.investigation.agent.runtime as runtime
    from src.main import IntelligenceService

    def broken(*args, **kwargs):
        raise RuntimeError("no session store")

    monkeypatch.setattr(runtime, "AgentInvestigator", broken)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("GCHAT_DRY_RUN", "true")
    monkeypatch.setenv("INVESTIGATOR_MODE", "shadow")
    assert IntelligenceService().agent_investigator is None
    monkeypatch.setenv("INVESTIGATOR_MODE", "adk")
    with pytest.raises(RuntimeError, match="no session store"):
        IntelligenceService()
