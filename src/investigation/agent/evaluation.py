"""ADK evaluation entry point of the investigator (plan C2.2).

``adk eval src/investigation/agent <evalset files>`` and ``AgentEvaluator`` load ``app`` from this
package's ``__init__``; the service never imports this module. ``app`` wraps the root agent the
runtime builds (``agents.build_root_agent``: same topology, instructions, callbacks and one model
from ``LLM_*`` settings) in an ADK ``App`` with one plugin, which does for each evaluated session what
the runtime wrapper does for a real run: bind an ``AgentRunRecord`` so the callbacks enforce the same
model-call ceiling, allowlist and per-tool caps. Nothing is written anywhere.

Tool data comes from the evalset, never from a live service: each case carries, under the session
state key ``eval_fixture``, the traffic lines ``query_traffic_context`` may see and the incidents
``recent_incidents_for_source`` may return. The plugin binds that fixture to the evaluated session
(a ContextVar, like the run record), so cases never see each other's data and a run depends only on
its case and the model.
"""

import functools
import re
from contextvars import ContextVar
from typing import Any, Dict, List, Optional, Tuple

from google.adk.apps import App
from google.adk.plugins.base_plugin import BasePlugin

from src.investigation.agent import audit
from src.investigation.agent.agents import build_model, build_root_agent
from src.investigation.agent.audit import AgentRunRecord
from src.investigation.agent.tools import ToolDeps, configure_tools

APP_NAME = "forti_investigator"
EVAL_FIXTURE_KEY = "eval_fixture"
_NEEDLES = re.compile(r'\|=\s*"((?:\\.|[^"\\])*)"')
_CASE_FIXTURE: ContextVar[Optional[Dict[str, Any]]] = ContextVar("forti_eval_fixture", default=None)


def _case_fixture(key: str) -> Optional[List[Any]]:
    fixture = _CASE_FIXTURE.get()
    return None if fixture is None else list(fixture.get(key) or [])


class FixtureLoki:
    """Stands in for LokiClient.query_range: the traffic lines of the case under evaluation, or, outside
    an evaluated session, the lines it was built with. Filters like Loki: every ``|=`` needle, the time
    range, the direction and the limit."""

    def __init__(self, lines: Optional[List[List[Any]]] = None) -> None:
        self.lines = [(int(ts), str(line)) for ts, line in lines or []]

    async def query_range(self, query: str, start_ns: int, end_ns: int, limit: int = 1000, direction: str = "forward"):
        case_lines = _case_fixture("traffic_lines")
        lines = self.lines if case_lines is None else [(int(ts), str(line)) for ts, line in case_lines]
        needles = [n.replace('\\"', '"') for n in _NEEDLES.findall(query)]
        hits = [(ts, line) for ts, line in lines if start_ns <= ts <= end_ns and all(n in line for n in needles)]
        hits.sort(key=lambda hit: hit[0], reverse=(direction == "backward"))
        return hits[:limit]


class FixtureIncidents:
    """Answers the one SELECT of recent_incidents_for_source from the case under evaluation."""

    is_sqlite = False

    async def fetch_all(self, query: str, source_ip: str, incident_id: str) -> List[Dict[str, Any]]:
        rows = [dict(r) for r in _case_fixture("recent_incidents") or []]
        rows = [r for r in rows if r.get("source_ip") == source_ip and r.get("id") != incident_id]
        return sorted(rows, key=lambda r: str(r.get("last_seen")), reverse=True)


class EvalRunPlugin(BasePlugin):
    """Binds one AgentRunRecord and the case's tool fixture per evaluated session; the specialists'
    AgentTool runs (inner runners that carry the same plugins) share both."""

    def __init__(self, settings) -> None:
        super().__init__(name="forti_eval_run")
        self.settings = settings
        self._tokens: Dict[str, Tuple[Any, Any]] = {}

    async def before_run_callback(self, *, invocation_context) -> Optional[Any]:
        if audit.current_run() is not None:  # an AgentTool run inside an evaluated session
            return None
        state = invocation_context.session.state
        record = AgentRunRecord(
            incident_id=str(state.get("incident_id", "")),
            revision=int(state.get("revision", 0) or 0),
            session_id=invocation_context.session.id,
            mode="eval",
            model_id=self.settings.llm_model,
            max_llm_calls=self.settings.agent_max_llm_calls,
            max_input_tokens=self.settings.llm_max_input_tokens,
        )
        fixture = dict(state.get(EVAL_FIXTURE_KEY) or {})
        self._tokens[invocation_context.invocation_id] = (audit.bind_run(record), _CASE_FIXTURE.set(fixture))
        return None

    async def after_run_callback(self, *, invocation_context) -> None:
        tokens = self._tokens.pop(invocation_context.invocation_id, None)
        if tokens is None:
            return
        run_token, fixture_token = tokens
        try:
            audit.unbind_run(run_token)
            _CASE_FIXTURE.reset(fixture_token)
        except ValueError:  # reset from another context: clear instead
            audit.bind_run(None)
            _CASE_FIXTURE.set(None)


@functools.lru_cache(maxsize=1)
def get_app() -> App:
    from config.settings import get_settings

    settings = get_settings()
    configure_tools(ToolDeps(loki=FixtureLoki(), selector=settings.loki_selector, db=FixtureIncidents()))
    model = build_model(
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        api_key=settings.llm_api_key,
        timeout_seconds=settings.llm_timeout_seconds,
    )
    return App(
        name=APP_NAME,
        root_agent=build_root_agent(model, settings.llm_max_output_tokens),
        plugins=[EvalRunPlugin(settings)],
    )
