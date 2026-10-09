"""The ``adk eval`` / ``AgentEvaluator`` entry point (src/investigation/agent/evaluation.py, plan C2.2).

Both ADK loaders find the App through the package ``__init__``; the App wraps the same Workflow the
runtime builds; its plugin binds one run record and the case's tool fixture per evaluated session,
shares them with the specialists' AgentTool runs, and releases them afterwards, so cases never see
each other's data. No eval extras are needed for any of this.
"""

import asyncio
import subprocess
import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("google.adk")

from src.investigation.agent import audit  # noqa: E402
from src.investigation.agent.evaluation import (  # noqa: E402
    EVAL_FIXTURE_KEY,
    EvalRunPlugin,
    FixtureIncidents,
    FixtureLoki,
)
from tests.agent.scenario import settings_for  # noqa: E402

QUERY = '{service_name="forticlient"} |= "type=\\"traffic\\"" |= "dstip=192.0.2.150"'
LINE_A = 'type="traffic" srcip=198.51.100.1 dstip=192.0.2.150 action="deny"'
LINE_B = 'type="traffic" srcip=198.51.100.2 dstip=192.0.2.150 action="deny"'


def _ctx(invocation_id: str, state: dict):
    return SimpleNamespace(invocation_id=invocation_id, session=SimpleNamespace(id=f"s-{invocation_id}", state=state))


def test_package_import_builds_nothing_and_both_adk_loaders_find_the_app():
    """Importing the package must not build a model or an App (src.main imports it in shadow mode)."""
    code = (
        "import sys, asyncio\n"
        "import src.investigation.agent\n"
        "assert 'src.investigation.agent.evaluation' not in sys.modules\n"
        "from google.adk.cli.cli_eval import get_app_or_root_agent\n"
        "from google.adk.evaluation.agent_evaluator import AgentEvaluator\n"
        "app, root = asyncio.run(get_app_or_root_agent('src/investigation/agent'))\n"
        "agent, app2 = asyncio.run(AgentEvaluator._get_agent_for_eval('src.investigation.agent'))\n"
        "print(app.name, root.name, agent.name, app2.name, [p.name for p in app.plugins])\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.split("\n")[-2] == "forti_investigator investigation investigation forti_investigator ['forti_eval_run']"


def test_eval_app_root_is_the_runtime_topology():
    from google.adk.agents import LlmAgent

    from src.investigation.agent.evaluation import get_app

    root = get_app().root_agent
    chain = [node for edge in root.edges for node in edge if isinstance(node, LlmAgent)]
    assert root.name == "investigation" and [a.name for a in chain] == ["incident_investigator", "assessment_writer"]
    master = chain[0]
    assert [t.name for t in master.tools] == ["evidence_agent", "context_agent"]
    assert [[f.__name__ for f in t.agent.tools] for t in master.tools] == [
        ["get_incident_packet", "query_traffic_context"],
        ["lookup_asset", "lookup_signature", "recent_incidents_for_source", "get_action_catalog"],
    ]


async def test_plugin_binds_one_run_and_the_case_fixture_per_session_and_isolates_cases():
    plugin = EvalRunPlugin(settings_for("sqlite:///:memory:", agent_max_llm_calls=8))
    loki, incidents = FixtureLoki([[1, LINE_A]]), FixtureIncidents()
    case_a = {"incident_id": "INC-A", "revision": 2, EVAL_FIXTURE_KEY: {
        "traffic_lines": [[5, LINE_A]],
        "recent_incidents": [{"id": "INC-OLD", "source_ip": "198.51.100.1", "last_seen": "2026-10-06T00:00:00+00:00"}],
    }}
    case_b = {"incident_id": "INC-B", "revision": 2, EVAL_FIXTURE_KEY: {"traffic_lines": [[6, LINE_B]]}}

    assert audit.current_run() is None
    assert await loki.query_range(QUERY, 0, 10) == [(1, LINE_A)]  # outside a session: its own lines

    async def evaluate(case, outer_id):
        await plugin.before_run_callback(invocation_context=_ctx(outer_id, case))
        run = audit.current_run()
        # An AgentTool run inside the session carries the same plugin: it must not rebind.
        await plugin.before_run_callback(invocation_context=_ctx(outer_id + "-inner", {}))
        assert audit.current_run() is run
        await plugin.after_run_callback(invocation_context=_ctx(outer_id + "-inner", {}))
        assert audit.current_run() is run
        seen = (
            run.incident_id, run.mode, run.max_llm_calls,
            await loki.query_range(QUERY, 0, 10),
            await incidents.fetch_all("SELECT ...", "198.51.100.1", case["incident_id"]),
        )
        await plugin.after_run_callback(invocation_context=_ctx(outer_id, case))
        assert audit.current_run() is None
        return seen

    seen_a, seen_b = await asyncio.gather(
        asyncio.create_task(evaluate(case_a, "inv-a")), asyncio.create_task(evaluate(case_b, "inv-b"))
    )
    assert seen_a[:4] == ("INC-A", "eval", 8, [(5, LINE_A)])
    assert [r["id"] for r in seen_a[4]] == ["INC-OLD"]
    assert seen_b == ("INC-B", "eval", 8, [(6, LINE_B)], [])
