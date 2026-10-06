"""Prometheus metrics and FastAPI health/readiness HTTP endpoints."""

import logging
from fastapi import FastAPI, Response, status
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

logger = logging.getLogger(__name__)

# Prometheus metrics
POLLER_QUERY_DURATION = Histogram(
    "forti_poller_query_duration_seconds",
    "Time spent executing Loki query_range requests",
)
RAW_LINES_TOTAL = Counter(
    "forti_poller_raw_lines_total",
    "Total raw log lines fetched from Loki",
)
NORMALIZED_EVENTS_TOTAL = Counter(
    "forti_poller_normalized_events_total",
    "Total security events normalized and persisted",
)
PARSER_ERRORS_TOTAL = Counter(
    "forti_parser_errors_total",
    "Total log parsing errors encountered",
)
COVERAGE_GAPS_TOTAL = Counter(
    "forti_coverage_gaps_total",
    "Total coverage gaps recorded due to saturation or errors",
)
INCIDENTS_ACTIVE = Gauge(
    "forti_incidents_active_count",
    "Current active attack episodes in memory",
)
MODEL_INFERENCE_DURATION = Histogram(
    "forti_model_inference_duration_seconds",
    "Time spent running ADK local Qwen investigation",
)
MODEL_FAILURES_TOTAL = Counter(
    "forti_model_failures_total",
    "Failures during local model investigation",
)
OUTBOX_DELIVERED_TOTAL = Counter(
    "forti_outbox_delivered_total",
    "Alerts successfully dispatched to Google Chat",
)
OUTBOX_FAILURES_TOTAL = Counter(
    "forti_outbox_failures_total",
    "Failures while dispatching alerts to Google Chat",
)


def create_app(db=None) -> FastAPI:
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
                # Ping database
                await db.fetch_one("SELECT 1")
                return {"status": "ready", "database": "connected"}
            except Exception as e:
                response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
                return {"status": "not_ready", "error": str(e)}
        return {"status": "ready"}

    return app
