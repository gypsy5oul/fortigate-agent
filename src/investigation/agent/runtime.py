"""Runtime wrapper of the ADK investigator (plan C1.4, ADR 005).

``AgentInvestigator.investigate(packet, mode)`` runs the Workflow once for one incident revision:
session ``<incident_id>:<revision>`` for user ``system`` on app ``forti-investigator``, identity and the
redacted packet in session state, ``RunConfig(max_llm_calls)`` plus the callbacks' run-wide ceiling,
the whole run under ``asyncio.wait_for(AGENT_TIMEOUT_SECONDS)``. The writer's object is mapped to a
``QwenAssessment`` and passed through ``validate_assessment`` exactly as the legacy path does; any
failure yields the deterministic fallback (``MODEL_REJECTED_FALLBACK``) with an AGENT_* reason code.

The wrapper, not an agent, persists the run to agent_runs and agent_events (audit.write_run). It
never writes an incident revision, a card or an outbox row; ``src.main`` decides what to do with the
result.
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, List, Optional, Tuple

from google.adk.agents.invocation_context import LlmCallsLimitExceededError
from google.adk.agents.run_config import RunConfig
from google.adk.runners import Runner
from google.adk.sessions import DatabaseSessionService
from google.genai import types
from pydantic import ValidationError

from src.investigation.agent import audit
from src.investigation.agent.agents import PROMPT_VERSIONS, build_model, build_root_agent
from src.investigation.agent.audit import AgentBudgetExceeded, AgentRunRecord
from src.investigation.agent.tools import ToolDeps, configure_tools, session_state_for
from src.investigation.schemas import FindingItem, IncidentPacket, QwenAssessment, WriterAssessment
from src.investigation.validator import validate_assessment
from src.observability.metrics import (
    AGENT_BUDGET_EXHAUSTED_TOTAL,
    AGENT_LLM_CALLS_TOTAL,
    AGENT_RUN_DURATION,
    AGENT_RUNS_TOTAL,
    AGENT_TOKENS_TOTAL,
    AGENT_TOOL_CALLS_TOTAL,
)

logger = logging.getLogger(__name__)

APP_NAME = "forti-investigator"
USER_ID = "system"
KICKOFF = "Investigate the incident bound to this session."
ADK_SCHEMA = "adk"

# Run outcomes written to agent_runs.outcome, and the reason code each failure adds.
OUTCOME_VALID = "VALID"
OUTCOME_REJECTED = "REJECTED"
OUTCOME_BUDGET = "BUDGET_EXHAUSTED"
OUTCOME_TIMEOUT = "TIMEOUT"
OUTCOME_SCHEMA = "SCHEMA_INVALID"
OUTCOME_ERROR = "ERROR"
REASON = {
    OUTCOME_BUDGET: "AGENT_BUDGET_EXHAUSTED",
    OUTCOME_TIMEOUT: "AGENT_TIMEOUT",
    OUTCOME_SCHEMA: "AGENT_SCHEMA_INVALID",
    OUTCOME_ERROR: "AGENT_ERROR",
    OUTCOME_REJECTED: "AGENT_VALIDATION_REJECTED",
}


@dataclass
class AgentOutcome:
    assessment: QwenAssessment          # validated model assessment, or the deterministic fallback
    outcome: str
    reason_codes: List[str]
    run_id: Optional[int]
    record: AgentRunRecord
    latency_ms: int = 0
    validation_reason_codes: List[str] = field(default_factory=list)


def adk_session_db(settings) -> Tuple[str, dict]:
    """The async SQLAlchemy URL for ADK sessions and the engine options (schema ``adk`` on PostgreSQL)."""
    url = settings.adk_session_db_url
    if not url:
        dsn = settings.database_url
        if dsn.startswith(("postgresql://", "postgres://")):
            url = "postgresql+asyncpg://" + dsn.split("://", 1)[1]
        elif dsn.startswith("sqlite"):
            url = "sqlite+aiosqlite:///" + (dsn.split(":///", 1)[1] if ":///" in dsn else ":memory:")
        else:
            url = dsn
    kwargs = {"connect_args": {"server_settings": {"search_path": ADK_SCHEMA}}} if url.startswith("postgresql+asyncpg") else {}
    return url, kwargs


def fallback_assessment(packet: IncidentPacket, reason_code: str) -> QwenAssessment:
    """Deterministic assessment when the agent result cannot be used (same shape as the legacy fallback)."""
    evidence_ids = [str(e.get("id")) for e in packet.evidence_events if isinstance(e, dict) and e.get("id")][:5]
    high = packet.deterministic_severity_floor in ("CRITICAL", "HIGH")
    return QwenAssessment(
        incident_id=packet.incident_id,
        incident_revision=packet.incident_revision,
        visibility_scope="FIREWALL_ONLY",
        severity=packet.deterministic_severity_floor,
        attack_category="EXPLOITATION_ATTEMPT" if high else "ANOMALOUS_TRAFFIC",
        exploitation_assessment="ATTEMPT_OBSERVED" if packet.enforcement in ("ALLOWED_OR_DETECTED", "MIXED") else "INSUFFICIENT_EVIDENCE",
        enforcement=packet.enforcement,
        summary=f"Deterministic assessment only. Agent analysis unavailable (reason code: {reason_code}).",
        findings=[FindingItem(
            kind="OBSERVATION",
            statement=f"Observed {packet.event_count} firewall events from {packet.source_ip} to {packet.target_ip} with {packet.enforcement} enforcement.",
            evidence_ids=evidence_ids or ["FALLBACK"],
        )],
        visibility_gaps=["Agent investigation unavailable; evaluated using deterministic firewall rules."],
        recommended_action_ids=["ACT_INSPECT_APPLICATION_LOGS"] if high else ["ACT_MONITOR_AND_DIGEST"],
        analyst_follow_up=["Review backend web server access logs for anomalous response sizes or HTTP 200/500 codes."],
        model_reported_enforcement=None,
        assessment_source="MODEL_REJECTED_FALLBACK",
    )


def _in_chain(exc: BaseException, kinds) -> bool:
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, kinds):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


def classify_failure(exc: BaseException, record: AgentRunRecord) -> str:
    """Map whatever a run raised to an outcome. The budget flag and LlmCallsLimitExceededError win
    because ADK may surface them wrapped (DynamicNodeFailError) or after other errors."""
    if record.budget_exhausted or _in_chain(exc, (AgentBudgetExceeded, LlmCallsLimitExceededError)):
        return OUTCOME_BUDGET
    if _in_chain(exc, (asyncio.TimeoutError, TimeoutError)):
        return OUTCOME_TIMEOUT
    if _in_chain(exc, (ValidationError, json.JSONDecodeError)):
        return OUTCOME_SCHEMA
    return OUTCOME_ERROR


class AgentInvestigator:
    def __init__(self, settings, db, loki_client=None, *, session_service=None, model=None):
        self.settings = settings
        self.db = db
        self.model = model or build_model(
            base_url=settings.llm_base_url,
            model=settings.llm_model,
            api_key=settings.llm_api_key,
            timeout_seconds=settings.llm_timeout_seconds,
        )
        if session_service is None:
            url, kwargs = adk_session_db(settings)
            session_service = DatabaseSessionService(db_url=url, **kwargs)
        self.session_service = session_service
        self.runner = Runner(agent=build_root_agent(self.model, settings.llm_max_output_tokens), app_name=APP_NAME, session_service=session_service)
        configure_tools(ToolDeps(loki=loki_client, selector=settings.loki_selector, db=db))
        try:
            self.adk_version = metadata.version("google-adk")
        except metadata.PackageNotFoundError:  # pragma: no cover
            self.adk_version = "unknown"

    async def close(self) -> None:
        for closer in (self.runner.close, getattr(self.session_service, "close", None), getattr(getattr(self.model, "client", None), "close", None)):
            if closer is None:
                continue
            try:
                await closer()
            except Exception as exc:  # shutdown must not fail on a close error
                logger.warning("ADK investigator close step failed: %s", exc)

    async def _fresh_session(self, session_id: str, state: dict) -> None:
        # A retried job reuses <incident>:<revision>; the old session is working memory, the audit
        # trail is in agent_runs/agent_events, so it is replaced.
        if await self.session_service.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id):
            await self.session_service.delete_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id)
        await self.session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id, state=state)

    async def _drive(self, session_id: str) -> Optional[str]:
        """Run the Workflow; return the error code of the last error event, if any."""
        error_code = None
        message = types.Content(role="user", parts=[types.Part(text=KICKOFF)])
        async for event in self.runner.run_async(
            user_id=USER_ID,
            session_id=session_id,
            new_message=message,
            run_config=RunConfig(max_llm_calls=self.settings.agent_max_llm_calls),
        ):
            if getattr(event, "error_code", None):
                # A final-flagged error event is not an answer (C.0 finding); remember it and go on.
                error_code = str(event.error_code)
        return error_code

    def _validated(self, raw: Any, packet: IncidentPacket) -> Tuple[QwenAssessment, str, List[str]]:
        writer = WriterAssessment.model_validate_json(raw) if isinstance(raw, (str, bytes)) else WriterAssessment.model_validate(raw)
        candidate = QwenAssessment(
            **writer.model_dump(),
            visibility_scope="FIREWALL_ONLY",
            model_reported_enforcement=None,
            assessment_source="MODEL_VALIDATED",
        )
        eligible = {a["id"] for a in packet.action_catalog if isinstance(a, dict) and a.get("id")}
        report = validate_assessment(candidate, packet, eligible)
        if report.is_valid and report.assessment is not None:
            return report.assessment, OUTCOME_VALID, list(report.reason_codes)
        return fallback_assessment(packet, REASON[OUTCOME_REJECTED]), OUTCOME_REJECTED, [REASON[OUTCOME_REJECTED]] + list(report.reason_codes)

    async def investigate(self, packet: IncidentPacket, mode: str) -> AgentOutcome:
        """Run one investigation. ``mode`` is "shadow" or "live"; it is recorded, not acted on."""
        session_id = f"{packet.incident_id}:{packet.incident_revision}"
        record = AgentRunRecord(
            incident_id=packet.incident_id,
            revision=packet.incident_revision,
            session_id=session_id,
            mode=mode,
            model_id=self.settings.llm_model,
            max_llm_calls=self.settings.agent_max_llm_calls,
            max_input_tokens=self.settings.llm_max_input_tokens,
        )
        validation_codes: List[str] = []
        started = time.monotonic()
        token = audit.bind_run(record)
        try:
            await self._fresh_session(session_id, session_state_for(packet))
            error_code = await asyncio.wait_for(self._drive(session_id), timeout=self.settings.agent_timeout_seconds)
            session = await self.session_service.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id)
            raw = session.state.get("assessment_json") if session else None
            if raw is None:
                outcome = OUTCOME_BUDGET if (record.budget_exhausted or error_code == "LlmCallsLimitExceededError") else (OUTCOME_ERROR if error_code else OUTCOME_SCHEMA)
                reasons = [REASON[outcome]] + ([error_code] if error_code and outcome == OUTCOME_ERROR else [])
                assessment = fallback_assessment(packet, REASON[outcome])
            else:
                assessment, outcome, reasons = self._validated(raw, packet)
                validation_codes = [c for c in reasons if c != REASON[OUTCOME_REJECTED]]
        except Exception as exc:
            outcome = classify_failure(exc, record)
            reasons = [REASON[outcome]] + ([type(exc).__name__] if outcome == OUTCOME_ERROR else [])
            assessment = fallback_assessment(packet, REASON[outcome])
            logger.warning("ADK investigation %s ended %s: %s: %s", session_id, outcome, type(exc).__name__, str(exc)[:200])
        finally:
            audit.unbind_run(token)
        latency_ms = int((time.monotonic() - started) * 1000)

        run_id = None
        try:
            run_id = await audit.write_run(
                self.db, record, outcome=outcome, reason_codes=reasons, latency_ms=latency_ms,
                adk_version=self.adk_version, prompt_versions=PROMPT_VERSIONS,
            )
        except Exception as exc:
            logger.error("Failed to write agent_runs for %s: %s", session_id, exc)
        self._observe(record, outcome, latency_ms)

        assessment.model_run = {
            "incident_id": packet.incident_id,
            "revision": packet.incident_revision,
            "model_id": self.settings.llm_model,
            "server_reported_model": None,
            "prompt_version": PROMPT_VERSIONS["assessment_writer"],
            "schema_version": "1.0.0",
            "rule_pack_version": "1.0.0",
            "catalog_version": "1.0.0",
            "action_map_version": "1.0.0",
            "input_hash": hashlib.sha256(packet.model_dump_json().encode("utf-8")).hexdigest(),
            "input_tokens": record.input_tokens,
            "output_tokens": record.output_tokens,
            "latency_ms": latency_ms,
            "structured_output_mode": "adk_json_schema",
            "validation_result": outcome,
            "reason_codes": reasons,
        }
        return AgentOutcome(
            assessment=assessment, outcome=outcome, reason_codes=reasons, run_id=run_id, record=record,
            latency_ms=latency_ms, validation_reason_codes=validation_codes,
        )

    @staticmethod
    def _observe(record: AgentRunRecord, outcome: str, latency_ms: int) -> None:
        AGENT_RUNS_TOTAL.labels(mode=record.mode, outcome=outcome).inc()
        AGENT_RUN_DURATION.observe(latency_ms / 1000.0)
        AGENT_TOKENS_TOTAL.labels(direction="input").inc(record.input_tokens)
        AGENT_TOKENS_TOTAL.labels(direction="output").inc(record.output_tokens)
        if outcome == OUTCOME_BUDGET:
            AGENT_BUDGET_EXHAUSTED_TOTAL.inc()
        for ev in record.events:
            if ev["kind"] == "llm" and not ev.get("refused"):
                AGENT_LLM_CALLS_TOTAL.labels(agent=ev["agent_name"]).inc()
            elif ev["kind"] == "tool":
                AGENT_TOOL_CALLS_TOTAL.labels(tool=ev["tool_name"], outcome=ev.get("outcome", "success")).inc()
