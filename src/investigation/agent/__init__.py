"""ADK investigation agents (Phase C.1, ADR 005).

Read-only tools, enforcement callbacks, the four agents, the runtime wrapper and the audit writer.
Nothing in this package writes to the service's tables except ``audit.py``, which the runtime
wrapper calls after a run; no agent, tool or callback reaches it. ``src.main`` imports this package
only when ``INVESTIGATOR_MODE`` is ``shadow`` or ``adk``.

``adk eval src/investigation/agent ...`` and ``AgentEvaluator`` look up ``app`` (or ``root_agent``)
here; both are built lazily on first access (``evaluation.py``), never by an import of the package.
"""


def __getattr__(name: str):
    if name == "app":
        from src.investigation.agent.evaluation import get_app

        return get_app()
    if name == "root_agent":
        from src.investigation.agent.evaluation import get_app

        return get_app().root_agent
    raise AttributeError(name)
