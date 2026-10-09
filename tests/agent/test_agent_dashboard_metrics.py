"""Every forti_agent_* series referenced by dashboards/agent_operations.json is exported once the
runtime has observed a run and the operational metrics updater has run once (plan rule 8: nothing on
a dashboard that the service never sets)."""

import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("google.adk")

from prometheus_client import generate_latest  # noqa: E402

from src.investigation.agent import runtime  # noqa: E402
from src.investigation.agent.audit import AgentRunRecord  # noqa: E402
from src.investigation.agent.runtime import AgentInvestigator  # noqa: E402
from src.main import IntelligenceService  # noqa: E402
from src.observability.metrics import AGENT_RUN_OUTCOMES  # noqa: E402
from src.storage.database import Database  # noqa: E402

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboards" / "agent_operations.json"


async def _updater_once_on_an_empty_database():
    db = Database("sqlite:///:memory:")
    await db.connect()
    try:
        await IntelligenceService._update_agent_window_gauges(SimpleNamespace(db=db))
    finally:
        await db.close()


def test_agent_dashboard_series_are_exported():
    record = AgentRunRecord("INC-DASH", 2, "INC-DASH:2", "shadow", "m", 8, 1000, input_tokens=10, output_tokens=5)
    record.add_event(agent_name="evidence_agent", kind="llm", tokens=15)
    record.add_event(agent_name="evidence_agent", kind="tool", tool_name="get_incident_packet", outcome="success")
    AgentInvestigator._observe(record, "BUDGET_EXHAUSTED", 1234)
    asyncio.run(_updater_once_on_an_empty_database())

    exported = generate_latest().decode()
    exprs = [t["expr"] for p in json.loads(DASHBOARD.read_text())["panels"] for t in p.get("targets", [])]
    referenced = {m for e in exprs for m in re.findall(r"\bforti_agent_[a-z0-9_]+", e)}
    assert {"forti_agent_runs_24h", "forti_agent_shadow_agreeing_24h", "forti_agent_shadow_comparisons_24h"} <= referenced
    missing = sorted(m for m in referenced if not re.search(rf"^{m}(\{{| )", exported, re.M))
    assert not missing, f"dashboard series never exported: {missing}"
    # With no runs the 24 h series exist and read zero, rather than being absent or stale.
    assert 'forti_agent_runs_24h{mode="shadow",outcome="REJECTED"} 0.0' in exported
    assert "forti_agent_shadow_comparisons_24h 0.0" in exported


def test_metric_outcomes_are_the_runtime_outcomes():
    outcomes = {getattr(runtime, n) for n in dir(runtime) if n.startswith("OUTCOME_")}
    assert set(AGENT_RUN_OUTCOMES) == outcomes
