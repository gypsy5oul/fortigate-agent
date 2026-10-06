"""Main asynchronous supervisor for FortiGate Firewall Intelligence Service."""

import os
import sys
import time
import signal
import asyncio
import logging
import uvicorn
from datetime import datetime, timezone

from config.settings import get_settings
from src.storage.database import Database
from src.storage.repository import Repository
from src.sources.loki_client import LokiClient
from src.sources.checkpoints import PollerOrchestrator
from src.correlator.session_aggregator import SessionAggregator
from src.rules.engine import RuleEngine
from src.investigation.schemas import IncidentPacket
from src.investigation.adk_workflow import ADKInvestigationWorkflow
from src.notifications.gchat_cards import build_gchat_card
from src.notifications.outbox_worker import OutboxWorker
from src.observability.metrics import (
    create_app,
    POLLER_QUERY_DURATION,
    RAW_LINES_TOTAL,
    NORMALIZED_EVENTS_TOTAL,
    INCIDENTS_ACTIVE,
    MODEL_INFERENCE_DURATION,
    OUTBOX_DELIVERED_TOTAL,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("firewall_intel")


class IntelligenceService:
    def __init__(self):
        self.settings = get_settings()
        self.db = Database(self.settings.database_url)
        self.repo = Repository(self.db)

        self.loki_client = LokiClient(
            base_url=self.settings.loki_base_url,
            user=self.settings.loki_user,
            password=self.settings.loki_password,
            bearer_token=self.settings.loki_bearer_token,
            tenant_id=self.settings.loki_tenant_id,
            tls_verify=self.settings.loki_tls_verify,
            timeout_seconds=self.settings.loki_query_timeout_seconds,
        )

        self.poller = PollerOrchestrator(
            loki_client=self.loki_client,
            repository=self.repo,
            selector=self.settings.loki_selector,
            overlap_seconds=self.settings.loki_replay_overlap_seconds,
            query_end_delay_seconds=15,
            default_bootstrap_seconds=600,
            limit=self.settings.loki_max_entries_per_query,
        )

        self.aggregator = SessionAggregator(
            idle_timeout_seconds=120,
            max_episode_seconds=600,
        )

        self.rule_engine = RuleEngine()

        self.adk_workflow = ADKInvestigationWorkflow(
            base_url=self.settings.llm_base_url,
            model=self.settings.llm_model,
            api_key=self.settings.llm_api_key,
            timeout_seconds=self.settings.llm_timeout_seconds,
        )

        self.outbox_worker = OutboxWorker(
            repository=self.repo,
            webhook_url=self.settings.gchat_webhook_url,
            dry_run=self.settings.gchat_dry_run,
            rate_limit_delay_seconds=self.settings.gchat_rate_limit_delay_seconds,
        )

        self.running = False

    async def start(self):
        logger.info("Starting FortiGate Firewall Intelligence Service...")
        await self.db.connect()
        self.running = True

        # Start HTTP server for metrics and health checks
        app = create_app(self.db)
        server_config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=self.settings.metrics_port,
            log_level="warning",
        )
        server = uvicorn.Server(server_config)
        server_task = asyncio.create_task(server.serve())

        # Start supervisor worker loops
        poller_task = asyncio.create_task(self._run_poller_loop())
        investigation_task = asyncio.create_task(self._run_investigation_loop())
        outbox_task = asyncio.create_task(self._run_outbox_loop())

        logger.info("Service initialized. Running asynchronous supervision loops.")

        try:
            await asyncio.gather(server_task, poller_task, investigation_task, outbox_task)
        except asyncio.CancelledError:
            logger.info("Service shutdown received.")
        finally:
            await self.stop()

    async def stop(self):
        self.running = False
        await self.loki_client.close()
        await self.adk_workflow.close()
        await self.outbox_worker.close()
        await self.db.close()
        logger.info("Service terminated gracefully.")

    # --- Supervised Loops ---
    async def _run_poller_loop(self):
        """Continuously polls Loki, correlates events, and runs deterministic rules."""
        while self.running:
            try:
                t0 = time.time()
                raw_count, saved_count = await self.poller.poll_once()
                duration = time.time() - t0
                POLLER_QUERY_DURATION.observe(duration)
                RAW_LINES_TOTAL.inc(raw_count)
                NORMALIZED_EVENTS_TOTAL.inc(saved_count)

                # Fetch recently saved events to correlate
                if saved_count > 0:
                    events = await self.db.fetch_all(
                        "SELECT * FROM selected_events ORDER BY created_at DESC LIMIT $1",
                        min(saved_count, 100)
                    )
                    episodes = self.aggregator.process_events(events)
                    INCIDENTS_ACTIVE.set(len(episodes))

                    for ep in episodes:
                        rule_eval = self.rule_engine.evaluate_episode(ep)
                        matched_rules = rule_eval["matched_rule_ids"]
                        if not matched_rules:
                            continue

                        sev_floor = rule_eval["severity_floor"]
                        routing = rule_eval["routing_outcome"]
                        inc_id = ep["incident_id"]

                        # 1. Upsert incident
                        inc_data = {
                            "id": inc_id,
                            "current_revision": 1,
                            "status": "ACTIVE",
                            "severity": sev_floor,
                            "enforcement": ep["enforcement"],
                            "exploitation_assessment": "ATTEMPT_OBSERVED" if ep["enforcement"] in ("ALLOWED_OR_DETECTED", "MIXED") else "INSUFFICIENT_EVIDENCE",
                            "source_ip": ep["source_ip"],
                            "target_ip": ep["target_ip"],
                            "first_seen": ep["first_seen"],
                            "last_seen": ep["last_seen"],
                            "event_count": ep["event_count"],
                            "summary": "; ".join(rule_eval["reasons"]),
                        }
                        await self.repo.upsert_incident(inc_data)

                        # 2. Urgent deterministic alert to Outbox immediately
                        if routing == "URGENT_ALERT_AND_INVESTIGATE":
                            urgent_card = build_gchat_card(
                                incident=inc_data,
                                revision=1,
                                assessment={
                                    "severity": sev_floor,
                                    "enforcement": ep["enforcement"],
                                    "summary": f"[DETERMINISTIC PERIMETER ALERT] {'; '.join(rule_eval['reasons'])}",
                                    "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS", "ACT_QUARANTINE_SRC_IP"],
                                },
                                grafana_base_url=self.settings.grafana_base_url,
                                datasource_uid=self.settings.grafana_datasource_uid,
                            )
                            await self.repo.enqueue_notification(inc_id, 1, "URGENT", urgent_card)

                        # 3. Enqueue investigation job for ADK & Qwen
                        if self.settings.llm_enabled:
                            job_payload = {
                                "incident_id": inc_id,
                                "episode": ep,
                                "rule_eval": rule_eval,
                            }
                            await self.repo.enqueue_job(f"JOB-{inc_id}-1", "INVESTIGATE_INCIDENT", job_payload, priority=20)

                self.aggregator.prune_stale_episodes()
            except Exception as e:
                logger.error("Error in poller loop: %s", e, exc_info=True)

            await asyncio.sleep(self.settings.loki_poll_interval_seconds)

    async def _run_investigation_loop(self):
        """Processes queued incident investigation jobs using Google ADK and local Qwen."""
        while self.running:
            try:
                job = await self.repo.lease_next_job("worker-supervisor", lease_duration_seconds=90)
                if not job:
                    await asyncio.sleep(3.0)
                    continue

                job_id = job["id"]
                payload = job.get("payload", {})
                ep = payload.get("episode", {})
                rule_eval = payload.get("rule_eval", {})
                inc_id = payload.get("incident_id")

                logger.info("Processing investigation job %s for Incident %s", job_id, inc_id)

                packet = IncidentPacket(
                    incident_id=inc_id,
                    incident_revision=2,
                    source_ip=ep["source_ip"],
                    target_ip=ep["target_ip"],
                    first_seen=str(ep["first_seen"]),
                    last_seen=str(ep["last_seen"]),
                    event_count=ep["event_count"],
                    enforcement=ep["enforcement"],
                    enforcement_counts=ep.get("enforcement_counts", {}),
                    deterministic_rule_ids=rule_eval.get("matched_rule_ids", []),
                    deterministic_severity_floor=rule_eval.get("severity_floor", "LOW"),
                    deterministic_reasons=rule_eval.get("reasons", []),
                    signatures=ep.get("signatures", []),
                    evidence_events=ep.get("events", []),
                    action_catalog=[],
                )

                t0 = time.time()
                assessment = await self.adk_workflow.investigate_packet(packet)
                MODEL_INFERENCE_DURATION.observe(time.time() - t0)

                # Record revision in database
                await self.repo.add_incident_revision({
                    "incident_id": inc_id,
                    "revision": 2,
                    "rule_ids": rule_eval.get("matched_rule_ids", []),
                    "severity": assessment.severity,
                    "enforcement": assessment.enforcement,
                    "assessment_json": assessment.model_dump(),
                    "model_name": self.settings.llm_model,
                    "reasoning_summary": assessment.summary,
                    "evidence_ids": [f.evidence_ids[0] for f in assessment.findings if f.evidence_ids],
                })

                # Build updated Google Chat card and enqueue to outbox
                card_payload = build_gchat_card(
                    incident={"id": inc_id, "source_ip": ep["source_ip"], "target_ip": ep["target_ip"], "event_count": ep["event_count"]},
                    revision=2,
                    assessment=assessment.model_dump(),
                    grafana_base_url=self.settings.grafana_base_url,
                    datasource_uid=self.settings.grafana_datasource_uid,
                )
                await self.repo.enqueue_notification(inc_id, 2, "INVESTIGATION_UPDATE", card_payload)

                # Complete job
                await self.repo.complete_job(job_id, job["version_token"])
                logger.info("Investigation job %s completed successfully", job_id)

            except Exception as e:
                logger.error("Error in investigation worker loop: %s", e, exc_info=True)
                await asyncio.sleep(2.0)

    async def _run_outbox_loop(self):
        """Processes outgoing notifications to Google Chat with rate-limiting."""
        while self.running:
            try:
                sent = await self.outbox_worker.process_outbox_batch(limit=5)
                if sent > 0:
                    OUTBOX_DELIVERED_TOTAL.inc(sent)
            except Exception as e:
                logger.error("Error in outbox loop: %s", e)

            await asyncio.sleep(self.settings.gchat_rate_limit_delay_seconds)


def main():
    service = IntelligenceService()
    loop = asyncio.get_event_loop()

    def _sig_handler():
        logger.info("Received termination signal.")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _sig_handler)

    try:
        loop.run_until_complete(service.start())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    main()
