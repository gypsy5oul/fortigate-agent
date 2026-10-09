"""ADK investigation agents (Phase C.1, ADR 005).

Read-only tools, enforcement callbacks, the four agents, the runtime wrapper and the audit writer.
Nothing in this package writes to the service's tables except ``audit.py``, which the runtime
wrapper calls after a run; no agent, tool or callback reaches it. ``src.main`` imports this package
only when ``INVESTIGATOR_MODE`` is ``shadow`` or ``adk``.
"""
