"""Every forti_agent_* series referenced by dashboards/agent_operations.json is exported once the
runtime has observed a run (plan rule 8: nothing on a dashboard that the service never sets)."""

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("google.adk")

from prometheus_client import generate_latest  # noqa: E402

from src.investigation.agent.audit import AgentRunRecord  # noqa: E402
from src.investigation.agent.runtime import AgentInvestigator  # noqa: E402

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboards" / "agent_operations.json"


def test_agent_dashboard_series_are_exported():
    record = AgentRunRecord("INC-DASH", 2, "INC-DASH:2", "shadow", "m", 8, 1000, input_tokens=10, output_tokens=5)
    record.add_event(agent_name="evidence_agent", kind="llm", tokens=15)
    record.add_event(agent_name="evidence_agent", kind="tool", tool_name="get_incident_packet", outcome="success")
    AgentInvestigator._observe(record, "BUDGET_EXHAUSTED", 1234)

    exported = generate_latest().decode()
    exprs = [t["expr"] for p in json.loads(DASHBOARD.read_text())["panels"] for t in p.get("targets", [])]
    referenced = {m for e in exprs for m in re.findall(r"\bforti_agent_[a-z_]+", e)}
    assert referenced, "the dashboard has no agent panels"
    missing = sorted(m for m in referenced if not re.search(rf"^{m}(\{{| )", exported, re.M))
    assert not missing, f"dashboard series never exported: {missing}"
