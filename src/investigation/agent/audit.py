"""Per-run audit record for the ADK investigator, and the writer for agent_runs, agent_events and
shadow_assessments (migration 006).

Callbacks only append to the in-memory ``AgentRunRecord`` bound to the current run; they never touch
the database. The runtime wrapper persists the record with ``write_run`` after the run ends, and
``src.main`` persists a shadow comparison with ``write_shadow_assessment``. Those two functions are
the only writers in the agent package.
"""

import json
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.investigation.schemas import QwenAssessment

TOOL_CALL_CAP = 3            # calls per tool per run; the fourth is refused (C1.3)
TOOL_RESPONSE_MAX_BYTES = 6144  # serialized tool response cap (C1.3)


class AgentBudgetExceeded(RuntimeError):
    """Raised by before_model_callback when a run exceeds AGENT_MAX_LLM_CALLS across all agents."""


@dataclass
class AgentRunRecord:
    """Everything one investigation run did, accumulated by the callbacks."""

    incident_id: str
    revision: int
    session_id: str
    mode: str                       # "shadow" or "live"
    model_id: str
    max_llm_calls: int
    max_input_tokens: int
    llm_calls: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    budget_exhausted: bool = False
    tool_counts: Dict[str, int] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    pending: Dict[Any, List[Any]] = field(default_factory=dict)

    def add_event(self, **fields: Any) -> Dict[str, Any]:
        fields["seq"] = len(self.events) + 1
        self.events.append(fields)
        return fields

    def start(self, key: Any, payload: Any = None) -> None:
        self.pending.setdefault(key, []).append((time.monotonic(), payload))

    def finish(self, key: Any) -> tuple:
        """Return (elapsed_ms, payload) for the oldest open start under ``key``."""
        queue = self.pending.get(key) or []
        if not queue:
            return 0, None
        started, payload = queue.pop(0)
        return int((time.monotonic() - started) * 1000), payload


_CURRENT_RUN: ContextVar[Optional[AgentRunRecord]] = ContextVar("forti_agent_run", default=None)


def bind_run(record: AgentRunRecord):
    """Make ``record`` the current run for this task and the tasks ADK starts from it."""
    return _CURRENT_RUN.set(record)


def unbind_run(token) -> None:
    _CURRENT_RUN.reset(token)


def current_run() -> Optional[AgentRunRecord]:
    return _CURRENT_RUN.get()


def _array(db, values: List[str]):
    return json.dumps(list(values)) if db.is_sqlite else list(values)


async def write_run(
    db,
    record: AgentRunRecord,
    *,
    outcome: str,
    reason_codes: List[str],
    latency_ms: int,
    adk_version: str,
    prompt_versions: Dict[str, str],
) -> Optional[int]:
    """Insert one agent_runs row and its agent_events rows in one transaction; return the run id."""
    async with db.transaction() as tx:
        run_query = """
        INSERT INTO agent_runs (
            incident_id, revision, session_id, mode, adk_version, model_id, prompt_versions,
            total_llm_calls, total_tool_calls, input_tokens, output_tokens, latency_ms, outcome, reason_codes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14)
        """
        args = (
            record.incident_id, record.revision, record.session_id, record.mode, adk_version, record.model_id,
            json.dumps(prompt_versions), record.llm_calls, record.tool_calls, record.input_tokens,
            record.output_tokens, latency_ms, outcome, _array(db, [str(c) for c in reason_codes]),
        )
        if db.is_sqlite:
            await tx.execute(run_query, *args)
            run_id = (await tx.fetch_one("SELECT last_insert_rowid() AS id"))["id"]
        else:
            run_id = (await tx.fetch_one(run_query + " RETURNING id", *args))["id"]

        rows = [
            (
                run_id, ev["seq"], ev["agent_name"], ev["kind"], ev.get("tool_name"),
                json.dumps(ev["args"], default=str) if ev.get("args") is not None else None,
                int(ev.get("response_bytes", 0)), bool(ev.get("refused", False)), int(ev.get("latency_ms", 0)),
                int(ev.get("tokens", 0)), ev.get("request_hash"),
            )
            for ev in record.events
        ]
        await tx.execute_many(
            """
            INSERT INTO agent_events (
                run_id, seq, agent_name, kind, tool_name, args_json, response_bytes, refused, latency_ms, tokens, request_hash
            ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11)
            """,
            rows,
        )
    return run_id


def agreement(adk: QwenAssessment, legacy: QwenAssessment) -> Dict[str, Any]:
    """The C1.7 agreement fields of a shadow run against the legacy assessment of the same revision."""
    return {
        "severity_equal": adk.severity == legacy.severity,
        "action_set_equal": set(adk.recommended_action_ids) == set(legacy.recommended_action_ids),
        "exploitation_equal": adk.exploitation_assessment == legacy.exploitation_assessment,
        "findings_count": len(adk.findings),
        "legacy_findings_count": len(legacy.findings),
    }


async def write_shadow_assessment(
    db,
    *,
    incident_id: str,
    revision: int,
    run_id: Optional[int],
    assessment: QwenAssessment,
    validation_reason_codes: List[str],
    legacy: QwenAssessment,
) -> None:
    agree = agreement(assessment, legacy)
    await db.execute(
        """
        INSERT INTO shadow_assessments (
            incident_id, revision, run_id, assessment_json, assessment_source, validation_reason_codes,
            severity_equal, action_set_equal, exploitation_equal, findings_count, legacy_findings_count
        ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11)
        """,
        incident_id, revision, run_id, json.dumps(assessment.model_dump(mode="json")),
        assessment.assessment_source or "UNKNOWN", _array(db, [str(c) for c in validation_reason_codes]),
        agree["severity_equal"], agree["action_set_equal"], agree["exploitation_equal"],
        agree["findings_count"], agree["legacy_findings_count"],
    )
