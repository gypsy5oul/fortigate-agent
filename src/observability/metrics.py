"""Prometheus metrics and FastAPI health/readiness HTTP endpoints."""

import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI, Response, status
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    REGISTRY,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

logger = logging.getLogger(__name__)


def _metric(cls, name: str, documentation: str, *args, **kwargs):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return cls(name, documentation, *args, **kwargs)


# Prometheus metrics
POLLER_QUERY_DURATION = _metric(
    Histogram,
    "forti_poller_query_duration_seconds",
    "Time spent executing Loki query_range requests",
)
RAW_LINES_TOTAL = _metric(
    Counter,
    "forti_poller_raw_lines_total",
    "Total raw log lines fetched from Loki",
)
NORMALIZED_EVENTS_TOTAL = _metric(
    Counter,
    "forti_poller_normalized_events_total",
    "Total security events normalized and persisted",
)
PARSER_ERRORS_TOTAL = _metric(
    Counter,
    "forti_parser_errors_total",
    "Total log parsing errors encountered",
)
COVERAGE_GAPS_TOTAL = _metric(
    Counter,
    "forti_coverage_gaps_total",
    "Total coverage gaps recorded due to saturation or errors",
)
INCIDENTS_ACTIVE = _metric(
    Gauge,
    "forti_incidents_active_count",
    "Current active attack episodes in memory",
)
MODEL_INFERENCE_DURATION = _metric(
    Histogram,
    "forti_model_inference_duration_seconds",
    "Time spent in the bounded single-call local model investigation",
)
MODEL_FAILURES_TOTAL = _metric(
    Counter,
    "forti_model_failures_total",
    "Failures during local model investigation",
)
OUTBOX_DELIVERED_TOTAL = _metric(
    Counter,
    "forti_outbox_delivered_total",
    "Alerts successfully dispatched to Google Chat",
)
OUTBOX_FAILURES_TOTAL = _metric(
    Counter,
    "forti_outbox_failures_total",
    "Failures while dispatching alerts to Google Chat",
)
OUTBOX_DEAD_LETTER_TOTAL = _metric(
    Counter,
    "forti_outbox_dead_letter_total",
    "Alerts moved to permanent dead letter queue due to non-retryable errors",
)
UNKNOWN_ACTIONS_TOTAL = _metric(
    Counter,
    "forti_unknown_actions_total",
    "Total unmapped log action values encountered",
    ["type", "subtype"],
)
INVESTIGATIONS_RATE_LIMITED_TOTAL = _metric(
    Counter,
    "forti_investigations_rate_limited_total",
    "Total incident investigations suppressed by per-source or per-target rate limits",
)
LOKI_LAST_SUCCESS_AGE_SECONDS = _metric(
    Gauge,
    "forti_loki_last_success_age_seconds",
    "Seconds since last successful Loki poll",
)
MODEL_LAST_SUCCESS_AGE_SECONDS = _metric(
    Gauge,
    "forti_model_last_success_age_seconds",
    "Seconds since last successful model inference",
)
CHAT_LAST_SUCCESS_AGE_SECONDS = _metric(
    Gauge,
    "forti_chat_last_success_age_seconds",
    "Seconds since last successful Chat alert delivery",
)
BACKLOG_PENDING_EVENTS = _metric(
    Gauge,
    "forti_backlog_pending_events",
    "Pending unprocessed events in durable inbox",
)
JOBS_OLDEST_PENDING_SECONDS = _metric(
    Gauge,
    "forti_jobs_oldest_pending_seconds",
    "Age of oldest pending investigation job in seconds",
)
MODEL_CONSECUTIVE_FAILURES = _metric(
    Gauge,
    "forti_model_consecutive_failures",
    "Consecutive failed or rejected model investigations; readiness reports degraded at 3",
)

# ADK investigator (plan C2.4, added in C.1). Incremented by the runtime wrapper after each run.
AGENT_RUNS_TOTAL = _metric(
    Counter,
    "forti_agent_runs_total",
    "ADK investigation runs by mode (shadow, live) and outcome",
    ["mode", "outcome"],
)
AGENT_LLM_CALLS_TOTAL = _metric(
    Counter,
    "forti_agent_llm_calls_total",
    "Model calls made by the ADK investigator, by agent",
    ["agent"],
)
AGENT_TOOL_CALLS_TOTAL = _metric(
    Counter,
    "forti_agent_tool_calls_total",
    "Tool calls made by the ADK investigator, by tool and outcome (success, refused, error)",
    ["tool", "outcome"],
)
AGENT_RUN_DURATION = _metric(
    Histogram,
    "forti_agent_run_duration_seconds",
    "Wall-clock duration of one ADK investigation run",
    buckets=(1, 2.5, 5, 10, 20, 30, 45, 60, 90, 120, 180),
)
AGENT_TOKENS_TOTAL = _metric(
    Counter,
    "forti_agent_tokens_total",
    "Tokens reported by the model endpoint for ADK investigator calls, by direction (input, output)",
    ["direction"],
)
AGENT_BUDGET_EXHAUSTED_TOTAL = _metric(
    Counter,
    "forti_agent_budget_exhausted_total",
    "ADK investigation runs stopped by the AGENT_MAX_LLM_CALLS ceiling",
)

# ADK investigator over the last 24 h, read from the audit tables (plan C2.4). Set by the operational
# metrics updater every cycle, in every mode and whatever the runs' outcome (zero when there were
# none), so the shadow-comparison panels and the agent alert rules never read a stale value.
AGENT_RUN_MODES = ("shadow", "live")
AGENT_RUN_OUTCOMES = ("VALID", "REJECTED", "BUDGET_EXHAUSTED", "TIMEOUT", "SCHEMA_INVALID", "ERROR")
AGENT_AGREEMENT_FIELDS = ("severity", "action_set", "exploitation")
AGENT_RUNS_24H = _metric(
    Gauge,
    "forti_agent_runs_24h",
    "ADK investigation runs created in the last 24 h, by mode and outcome (agent_runs)",
    ["mode", "outcome"],
)
AGENT_SHADOW_COMPARISONS_24H = _metric(
    Gauge,
    "forti_agent_shadow_comparisons_24h",
    "Shadow-mode ADK assessments compared with the legacy assessment in the last 24 h (shadow_assessments)",
)
AGENT_SHADOW_AGREEING_24H = _metric(
    Gauge,
    "forti_agent_shadow_agreeing_24h",
    "Shadow comparisons in the last 24 h that agree with the legacy assessment, by field (severity, action_set, exploitation)",
    ["field"],
)


def create_app(db=None, service_state: Optional[dict] = None) -> FastAPI:
    app = FastAPI(title="FortiGate Firewall Intelligence Service")

    @app.get("/metrics")
    def get_metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/health/live")
    def liveness():
        return {"status": "alive"}

    @app.get("/health/ready")
    async def readiness(response: Response):
        if db is not None:
            try:
                await db.fetch_one("SELECT 1")
            except Exception as e:
                response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
                return {"status": "not_ready", "error": f"Database unreachable: {e}"}

        # Check poller liveness (last success within 3x poll interval)
        if service_state and "last_poller_success" in service_state:
            last_poll = service_state.get("last_poller_success", 0)
            poll_interval = service_state.get("poll_interval_seconds", 15.0)
            import time
            if last_poll > 0 and (time.time() - last_poll) > (3 * poll_interval):
                response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
                return {"status": "not_ready", "error": "Poller lag exceeded 3x interval"}

        # Model outage reports degraded, not not_ready
        if service_state and service_state.get("model_degraded"):
            return {"status": "degraded", "database": "connected", "note": "Model inference degraded; deterministic rules active"}

        return {"status": "ready", "database": "connected"}

    return app
