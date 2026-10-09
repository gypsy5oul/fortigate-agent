"""Plan C2.4 on PostgreSQL: the operational metrics updater sets the 24 h agent gauges from
agent_runs and shadow_assessments on every cycle, whatever the outcomes, and back to zero when the
window is empty (never left stale)."""

import os
from datetime import datetime, timedelta, timezone

from src.main import IntelligenceService
from src.observability.metrics import AGENT_RUNS_24H, AGENT_SHADOW_AGREEING_24H, AGENT_SHADOW_COMPARISONS_24H

TEST_PG_URL = os.getenv("TEST_DATABASE_URL", "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test")


def _runs(mode, outcome):
    return AGENT_RUNS_24H.labels(mode=mode, outcome=outcome)._value.get()


async def test_pg_updater_sets_agent_window_gauges_every_cycle(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", TEST_PG_URL)
    monkeypatch.setenv("GCHAT_DRY_RUN", "true")
    service = IntelligenceService()
    await service.db.connect()
    try:
        async with service.db._pg_pool.acquire() as conn:
            await conn.execute("TRUNCATE TABLE agent_runs, agent_events, shadow_assessments CASCADE")
            now = datetime.now(timezone.utc)
            seed = [("shadow", "VALID", now)] * 3 + [("shadow", "REJECTED", now), ("live", "BUDGET_EXHAUSTED", now),
                                                     ("shadow", "REJECTED", now - timedelta(hours=30))]
            for i, (mode, outcome, created) in enumerate(seed):
                run_id = await conn.fetchval(
                    "INSERT INTO agent_runs (incident_id, revision, session_id, mode, adk_version, model_id, outcome, created_at) "
                    "VALUES ($1, 2, $2, $3, '2.11.0', 'm', $4, $5) RETURNING id",
                    f"INC-G-{i}", f"INC-G-{i}:2", mode, outcome, created,
                )
                if mode == "shadow":
                    await conn.execute(
                        "INSERT INTO shadow_assessments (incident_id, revision, run_id, assessment_json, assessment_source, "
                        "severity_equal, action_set_equal, exploitation_equal, findings_count, legacy_findings_count, created_at) "
                        "VALUES ($1, 2, $2, '{}', 'MODEL_VALIDATED', true, $3, true, 1, 1, $4)",
                        f"INC-G-{i}", run_id, outcome == "VALID", created,
                    )

        await service._update_operational_metrics()
        assert (_runs("shadow", "VALID"), _runs("shadow", "REJECTED"), _runs("live", "BUDGET_EXHAUSTED")) == (3, 1, 1)
        assert _runs("shadow", "TIMEOUT") == 0 and _runs("live", "VALID") == 0
        assert AGENT_SHADOW_COMPARISONS_24H._value.get() == 4  # the 30 h old row is outside the window
        assert [AGENT_SHADOW_AGREEING_24H.labels(field=f)._value.get() for f in ("severity", "action_set", "exploitation")] == [4, 3, 4]

        async with service.db._pg_pool.acquire() as conn:
            await conn.execute("TRUNCATE TABLE agent_runs, agent_events, shadow_assessments CASCADE")
        await service._update_operational_metrics()
        assert _runs("shadow", "VALID") == 0 and _runs("shadow", "REJECTED") == 0 and _runs("live", "BUDGET_EXHAUSTED") == 0
        assert AGENT_SHADOW_COMPARISONS_24H._value.get() == 0
        assert AGENT_SHADOW_AGREEING_24H.labels(field="severity")._value.get() == 0
    finally:
        await service.stop()
