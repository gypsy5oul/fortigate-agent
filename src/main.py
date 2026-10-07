"""Main asynchronous supervisor for FortiGate Firewall Intelligence Service."""

import os
import sys
import re
import time
import signal
import asyncio
import logging
from collections import defaultdict
from typing import Dict, List, Optional
import uvicorn
from datetime import datetime, timezone

from config.settings import get_settings
from src.storage.database import Database
from src.storage.repository import Repository, RevisionConflict
from src.storage.timeutil import to_utc_datetime
from src.sources.loki_client import LokiClient
from src.sources.checkpoints import PollerOrchestrator
from src.correlator.session_aggregator import SessionAggregator
from src.rules.engine import RuleEngine
from src.investigation.schemas import IncidentPacket
from src.investigation.eligibility import get_eligible_actions
from src.investigation.adk_workflow import ADKInvestigationWorkflow
from src.notifications.gchat_cards import build_gchat_card, build_digest_gchat_card
from src.notifications.outbox_worker import OutboxWorker
from src.observability.metrics import (
    create_app,
    POLLER_QUERY_DURATION,
    RAW_LINES_TOTAL,
    NORMALIZED_EVENTS_TOTAL,
    INCIDENTS_ACTIVE,
    MODEL_INFERENCE_DURATION,
    INVESTIGATIONS_RATE_LIMITED_TOTAL,
)

# Quiet HTTP transport logging to prevent credential exposure in URLs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class SensitiveDataFilter(logging.Filter):
    """Filter redacting secrets, query params, tokens, and keys from all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self.redact(v) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self.redact(v) if isinstance(v, str) else v for v in record.args)
        return True

    @staticmethod
    def redact(msg: str) -> str:
        msg = re.sub(r'(key=)[^&\s]+', r'\1[REDACTED]', msg)
        msg = re.sub(r'(token=)[^&\s]+', r'\1[REDACTED]', msg)
        msg = re.sub(r'(Authorization:\s*(?:Bearer\s+)?)[^\s]+', r'\1[REDACTED]', msg, flags=re.IGNORECASE)
        msg = re.sub(r'(password=)[^&\s]+', r'\1[REDACTED]', msg, flags=re.IGNORECASE)
        return msg


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
for handler in logging.root.handlers:
    handler.addFilter(SensitiveDataFilter())
logging.getLogger().addFilter(SensitiveDataFilter())

logger = logging.getLogger("firewall_intel")


class IntelligenceService:
    def __init__(self):
        self.settings = get_settings()

        # Startup configuration validation
        if not self.settings.gchat_dry_run and not self.settings.gchat_webhook_url:
            raise ValueError("GCHAT_DRY_RUN is false but GCHAT_WEBHOOK_URL is not configured")
        if not self.settings.loki_tls_verify and not self.settings.allow_insecure_tls:
            raise ValueError("LOKI_TLS_VERIFY is false but ALLOW_INSECURE_TLS is not true")

        self.db = Database(self.settings.database_url)
        self.repo = Repository(self.db)
        self._source_investigation_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._target_investigation_timestamps: Dict[str, List[float]] = defaultdict(list)

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
            query_end_delay_seconds=5,
            default_bootstrap_seconds=60,
            slice_seconds=self.settings.loki_slice_seconds,
            limit=self.settings.loki_max_entries_per_query,
            max_slices_per_cycle=self.settings.loki_max_slices_per_cycle,
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
            max_output_tokens=self.settings.llm_max_output_tokens,
        )

        self.outbox_worker = OutboxWorker(
            repository=self.repo,
            webhook_url=self.settings.gchat_webhook_url,
            dry_run=self.settings.gchat_dry_run,
            rate_limit_delay_seconds=self.settings.gchat_rate_limit_delay_seconds,
            thread_by_incident=self.settings.gchat_thread_by_incident,
        )

        self.service_state = {
            "last_poller_success": 0.0,
            "poll_interval_seconds": self.settings.loki_poll_interval_seconds,
            "model_degraded": False,
        }

        self.running = False

    async def start(self):
        logger.info("Starting FortiGate Firewall Intelligence Service...")
        await self.db.connect()
        self.running = True

        # Restore open episodes on startup (B6)
        try:
            open_eps = await self.repo.load_open_episodes()
            self.aggregator.load_open_episodes(open_eps)
            logger.info("Restored %s open episodes from persistent database.", len(open_eps))
        except Exception as e:
            logger.warning("Failed to restore open episodes on startup: %s", e)

        # Start HTTP server for metrics and health checks
        app = create_app(self.db, service_state=self.service_state)
        server_config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=self.settings.metrics_port,
            log_level="warning",
        )
        server = uvicorn.Server(server_config)
        self._server = server
        server_task = asyncio.create_task(server.serve())

        # Start supervisor worker loops
        poller_task = asyncio.create_task(self._run_poller_loop())
        investigation_task = asyncio.create_task(self._run_investigation_loop())
        outbox_task = asyncio.create_task(self._run_outbox_loop())
        digest_task = asyncio.create_task(self._run_digest_loop())

        logger.info("Service initialized. Running asynchronous supervision loops.")

        try:
            await asyncio.gather(server_task, poller_task, investigation_task, outbox_task, digest_task)
        except asyncio.CancelledError:
            logger.info("Service shutdown received.")
        finally:
            await self.stop()

    async def stop(self):
        self.running = False
        if hasattr(self, "_server") and self._server:
            self._server.should_exit = True
        await self.loki_client.close()
        await self.adk_workflow.close()
        await self.outbox_worker.close()
        await self.db.close()
        logger.info("Service terminated gracefully.")

    # --- Supervised Loops ---
    async def _run_poller_loop(self):
        """Continuously polls Loki, drains durable inbox, correlates events, and runs deterministic rules."""
        severity_ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        while self.running:
            try:
                t0 = time.time()
                raw_count, saved_count = await self.poller.poll_once()
                duration = time.time() - t0
                POLLER_QUERY_DURATION.observe(duration)
                RAW_LINES_TOTAL.inc(raw_count)
                NORMALIZED_EVENTS_TOTAL.inc(saved_count)
                self.service_state["last_poller_success"] = time.time()

                # Drain durable inbox (all pending events in stable ascending order)
                while self.running:
                    pending_events = await self.repo.fetch_pending_events(limit=100)
                    if not pending_events:
                        break

                    episodes = self.aggregator.process_events(pending_events)
                    INCIDENTS_ACTIVE.set(len(episodes))
                    try:
                        await self.repo.save_episodes(episodes)
                    except Exception as ep_err:
                        logger.warning("Failed to persist episodes to database: %s", ep_err)
                    pending_ids = [ev["id"] for ev in pending_events]
                    touched = {(ev.get("vd", "root"), ev.get("direction", "INBOUND"), ev["srcip"], ev["dstip"]) for ev in pending_events}

                    for ep in episodes:
                        # Only episodes that received events in this batch can change
                        if (ep.get("vdom", "root"), ep.get("direction", "INBOUND"), ep["source_ip"], ep["target_ip"]) not in touched:
                            continue
                        rule_eval = self.rule_engine.evaluate_episode(ep)
                        matched_rules = rule_eval["matched_rule_ids"]
                        if not matched_rules:
                            continue

                        sev_floor = rule_eval["severity_floor"]
                        routing = rule_eval["routing_outcome"]
                        inc_id = ep["incident_id"]

                        existing = await self.repo.get_incident(inc_id)
                        is_new = existing is None

                        material_change = False
                        if is_new:
                            material_change = True
                        else:
                            det_sev = existing.get("deterministic_severity") or existing.get("severity", "LOW")
                            det_enf = existing.get("deterministic_enforcement") or existing.get("enforcement", "UNKNOWN")
                            det_rules = set(existing.get("deterministic_rule_ids") or [])

                            # Escalation evaluation based strictly on deterministic facts
                            if severity_ranks.get(sev_floor, 1) > severity_ranks.get(det_sev, 1):
                                material_change = True
                            elif det_enf == "BLOCKED" and ep["enforcement"] in ("ALLOWED_OR_DETECTED", "MIXED"):
                                material_change = True
                            elif set(matched_rules) - det_rules:
                                material_change = True

                        cur_rev = existing.get("current_revision", 1) if existing else 1
                        next_rev = (cur_rev + 1) if (material_change and not is_new) else cur_rev

                        # Cooldown check for URGENT notifications
                        now_epoch = time.time()
                        last_urgent_dt = to_utc_datetime(existing.get("last_urgent_at")) if existing else None
                        last_urgent_ts = last_urgent_dt.timestamp() if last_urgent_dt else 0.0

                        severity_rose = not is_new and severity_ranks.get(sev_floor, 1) > severity_ranks.get(det_sev, 1)
                        cooldown_elapsed = (now_epoch - last_urgent_ts) >= self.settings.urgent_cooldown_seconds

                        if is_new or severity_rose or cooldown_elapsed:
                            notif_type = "URGENT"
                            urgent_ts_to_save = datetime.now(timezone.utc)
                        else:
                            notif_type = "INVESTIGATION_UPDATE"
                            urgent_ts_to_save = last_urgent_dt

                        inc_data = {
                            "id": inc_id,
                            "current_revision": next_rev,
                            "status": "ACTIVE",
                            "severity": sev_floor,
                            "enforcement": ep["enforcement"],
                            "exploitation_assessment": "ATTEMPT_OBSERVED" if ep["enforcement"] in ("ALLOWED_OR_DETECTED", "MIXED") else "INSUFFICIENT_EVIDENCE",
                            "vd": ep.get("vdom", "root"),
                            "direction": ep.get("direction", "INBOUND"),
                            "source_ip": ep["source_ip"],
                            "target_ip": ep["target_ip"],
                            "target_port": ep.get("target_port"),
                            "target_service": ep.get("target_service"),
                            "first_seen": ep["first_seen"],
                            "last_seen": ep["last_seen"],
                            "event_count": ep["event_count"],
                            "summary": "; ".join(rule_eval["reasons"]),
                            "rule_ids": matched_rules,
                            "deterministic_severity": sev_floor,
                            "deterministic_enforcement": ep["enforcement"],
                            "deterministic_rule_ids": matched_rules,
                            "last_urgent_at": urgent_ts_to_save if (routing == "URGENT_ALERT_AND_INVESTIGATE" and notif_type == "URGENT") else (last_urgent_dt),
                        }

                        rev_data = None
                        notif_card = None
                        job_data = None

                        if material_change:
                            rev_data = {
                                "incident_id": inc_id,
                                "revision": next_rev,
                                "rule_ids": matched_rules,
                                "severity": sev_floor,
                                "enforcement": ep["enforcement"],
                                "assessment_json": {
                                    "severity": sev_floor,
                                    "enforcement": ep["enforcement"],
                                    "summary": f"[DETERMINISTIC PERIMETER ALERT - REV {next_rev}] {'; '.join(rule_eval['reasons'])}",
                                    "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"] if sev_floor in ("CRITICAL", "HIGH") else ["ACT_MONITOR_AND_DIGEST"],
                                },
                                "model_name": None,
                                "reasoning_summary": "; ".join(rule_eval["reasons"]),
                                "evidence_ids": ep.get("evidence_ids", [])[:5],
                                "assessment_source": "DETERMINISTIC",
                            }

                            if routing == "URGENT_ALERT_AND_INVESTIGATE":
                                notif_card = {
                                    "incident_id": inc_id,
                                    "revision": next_rev,
                                    "notification_type": notif_type,
                                    "payload": build_gchat_card(
                                        incident=inc_data,
                                        revision=next_rev,
                                        assessment=rev_data["assessment_json"],
                                        grafana_base_url=self.settings.grafana_base_url,
                                        datasource_uid=self.settings.grafana_datasource_uid,
                                        cli_recommendations_enabled=self.settings.cli_recommendations_enabled,
                                        fortios_build=self.settings.fortios_build,
                                    ),
                                }

                            # Only queue LLM investigation for URGENT or INVESTIGATE (never DIGEST)
                            if routing in ("URGENT_ALERT_AND_INVESTIGATE", "INVESTIGATE") and self.settings.llm_enabled:
                                src_ip = ep["source_ip"]
                                tgt_ip = ep["target_ip"]
                                one_hr_ago = time.time() - 3600.0
                                self._source_investigation_timestamps[src_ip] = [t for t in self._source_investigation_timestamps[src_ip] if t > one_hr_ago]
                                self._target_investigation_timestamps[tgt_ip] = [t for t in self._target_investigation_timestamps[tgt_ip] if t > one_hr_ago]

                                is_rate_limited = (
                                    len(self._source_investigation_timestamps[src_ip]) >= self.settings.investigation_rate_limit_per_source_hour
                                    or len(self._target_investigation_timestamps[tgt_ip]) >= self.settings.investigation_rate_limit_per_target_hour
                                )

                                if is_rate_limited:
                                    INVESTIGATIONS_RATE_LIMITED_TOTAL.inc()
                                    logger.warning("Investigation job rate limited for source %s -> target %s", src_ip, tgt_ip)
                                    rev_data["assessment_source"] = "RATE_LIMITED"
                                    job_data = None
                                else:
                                    self._source_investigation_timestamps[src_ip].append(time.time())
                                    self._target_investigation_timestamps[tgt_ip].append(time.time())
                                    job_payload = {
                                        "incident_id": inc_id,
                                        "revision": next_rev,
                                        "episode": ep,
                                        "rule_eval": rule_eval,
                                    }
                                    job_data = {
                                        "id": f"JOB-{inc_id}-{next_rev}",
                                        "job_type": "INVESTIGATE_INCIDENT",
                                        "payload": job_payload,
                                        "priority": 20 if sev_floor in ("CRITICAL", "HIGH") else 10,
                                    }

                        # Persist with optimistic revision check and retry once on conflict
                        try:
                            await self.repo.record_incident_transition(
                                incident=inc_data,
                                revision=rev_data,
                                notification=notif_card,
                                job=job_data,
                                processed_event_ids=None,
                                expected_revision=existing.get("current_revision") if existing else None,
                            )
                        except RevisionConflict:
                            logger.warning("RevisionConflict on incident %s; retrying once", inc_id)
                            fresh = await self.repo.get_incident(inc_id)
                            if fresh:
                                inc_data["current_revision"] = fresh["current_revision"] + 1
                                if rev_data:
                                    rev_data["revision"] = inc_data["current_revision"]
                                if notif_card:
                                    notif_card["revision"] = inc_data["current_revision"]
                                if job_data:
                                    job_data["payload"]["revision"] = inc_data["current_revision"]
                                    job_data["id"] = f"JOB-{inc_id}-{inc_data['current_revision']}"
                                try:
                                    await self.repo.record_incident_transition(
                                        incident=inc_data,
                                        revision=rev_data,
                                        notification=notif_card,
                                        job=job_data,
                                        processed_event_ids=None,
                                        expected_revision=fresh.get("current_revision"),
                                    )
                                except Exception as retry_err:
                                    logger.error("Retry transition failed on incident %s: %s", inc_id, retry_err)

                    # Acknowledge all processed events for this batch
                    if pending_ids:
                        await self.repo.mark_events_processed(pending_ids)

                self.aggregator.prune_stale_episodes()
            except Exception as e:
                logger.error("Error in poller loop: %s", e, exc_info=True)

            await asyncio.sleep(self.settings.loki_poll_interval_seconds)

    async def _run_investigation_loop(self):
        """Processes queued incident investigation jobs using Google ADK and local Qwen."""
        while self.running:
            job = None
            try:
                job = await self.repo.lease_next_job("worker-supervisor", lease_duration_seconds=90)
                if not job:
                    await asyncio.sleep(3.0)
                    continue

                job_id = job["id"]
                version_token = job["version_token"]
                payload = job.get("payload", {})
                ep = payload.get("episode", {})
                rule_eval = payload.get("rule_eval", {})
                inc_id = payload.get("incident_id")
                trigger_rev = payload.get("revision", 1)
                target_rev = trigger_rev + 1

                logger.info("Processing investigation job %s for Incident %s (Trigger Rev %s)", job_id, inc_id, trigger_rev)

                packet = IncidentPacket(
                    incident_id=inc_id,
                    incident_revision=target_rev,
                    source_ip=ep["source_ip"],
                    target_ip=ep["target_ip"],
                    target_app=ep.get("target_service") or f"Target ({ep['target_ip']})",
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
                    action_catalog=get_eligible_actions(ep, configured_build=self.settings.fortios_build),
                )

                t0 = time.time()
                assessment = await self.adk_workflow.investigate_packet(packet)
                MODEL_INFERENCE_DURATION.observe(time.time() - t0)

                # Enforcement and exploitation on incident row remain deterministic
                det_enforcement = ep["enforcement"]
                det_exploit = "ATTEMPT_OBSERVED" if det_enforcement in ("ALLOWED_OR_DETECTED", "MIXED") else "INSUFFICIENT_EVIDENCE"

                # Build chat card
                card_payload = build_gchat_card(
                    incident={
                        "id": inc_id,
                        "source_ip": ep["source_ip"],
                        "target_ip": ep["target_ip"],
                        "event_count": ep["event_count"],
                        "target_app": ep.get("target_service") or f"Target Host ({ep['target_ip']})",
                        "rule_ids": rule_eval.get("matched_rule_ids", []),
                    },
                    revision=target_rev,
                    assessment=assessment.model_dump(),
                    grafana_base_url=self.settings.grafana_base_url,
                    datasource_uid=self.settings.grafana_datasource_uid,
                    cli_recommendations_enabled=self.settings.cli_recommendations_enabled,
                    fortios_build=self.settings.fortios_build,
                )

                # Atomic incident revision, outbox notification, and job completion fence
                await self.repo.record_incident_transition(
                    incident={
                        "id": inc_id,
                        "current_revision": target_rev,
                        "status": "ACTIVE",
                        "severity": assessment.severity,
                        "enforcement": det_enforcement,
                        "exploitation_assessment": det_exploit,
                        "vd": ep.get("vdom", "root"),
                        "direction": ep.get("direction", "INBOUND"),
                        "source_ip": ep["source_ip"],
                        "target_ip": ep["target_ip"],
                        "target_port": ep.get("target_port"),
                        "target_service": ep.get("target_service"),
                        "first_seen": ep["first_seen"],
                        "last_seen": ep["last_seen"],
                        "event_count": ep["event_count"],
                        "summary": assessment.summary,
                    },
                    revision={
                        "incident_id": inc_id,
                        "revision": target_rev,
                        "rule_ids": rule_eval.get("matched_rule_ids", []),
                        "severity": assessment.severity,
                        "enforcement": det_enforcement,
                        "assessment_json": assessment.model_dump(),
                        "model_name": self.settings.llm_model,
                        "reasoning_summary": assessment.summary,
                        "evidence_ids": [f.evidence_ids[0] for f in assessment.findings if f.evidence_ids],
                        "assessment_source": assessment.assessment_source,
                    },
                    notification={
                        "incident_id": inc_id,
                        "revision": target_rev,
                        "notification_type": "INVESTIGATION_UPDATE",
                        "payload": card_payload,
                    },
                    model_run=getattr(assessment, "model_run", None),
                    expected_revision=trigger_rev,
                    fence_job_id=job_id,
                    fence_version_token=version_token,
                )
                logger.info("Investigation job %s completed and committed successfully", job_id)

            except Exception as e:
                logger.error("Error in investigation worker loop: %s", e, exc_info=True)
                if job:
                    try:
                        await self.repo.fail_job(job["id"], job["version_token"], str(e))
                    except Exception as fail_err:
                        logger.error("Failed to fail_job %s: %s", job["id"], fail_err)
                await asyncio.sleep(2.0)

    async def _run_outbox_loop(self):
        """Processes outgoing notifications to Google Chat with rate-limiting."""
        while self.running:
            try:
                await self.outbox_worker.process_outbox_batch(limit=5)
            except Exception as e:
                logger.error("Error in outbox loop: %s", e)

            await asyncio.sleep(self.settings.gchat_rate_limit_delay_seconds)

    async def _run_digest_loop(self):
        """Periodically aggregates DIGEST-priority incidents into summary notifications (B6)."""
        logger.info("Starting periodic DIGEST aggregation worker loop.")
        interval_secs = max(5.0, self.settings.digest_interval_minutes * 60.0)
        last_digest_time = datetime.now(timezone.utc)

        while self.running:
            try:
                await asyncio.sleep(interval_secs)
                if not self.running:
                    break

                now_dt = datetime.now(timezone.utc)
                summary = await self.repo.get_digest_summary(last_digest_time)
                if summary.get("total_incidents", 0) > 0:
                    card_payload = build_digest_gchat_card(
                        summary,
                        grafana_base_url=self.settings.grafana_base_url,
                        datasource_uid=self.settings.grafana_datasource_uid,
                    )
                    rev_ts = int(now_dt.timestamp())
                    await self.repo.enqueue_notification(
                        incident_id="DIGEST-PERIODIC",
                        revision=rev_ts,
                        notif_type="DIGEST",
                        payload=card_payload,
                    )
                    logger.info("Queued periodic DIGEST notification with %s incidents", summary["total_incidents"])
                    last_digest_time = now_dt
            except Exception as e:
                logger.error("Error in digest aggregation worker: %s", e, exc_info=True)
                await asyncio.sleep(5.0)


def main():
    service = IntelligenceService()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _sig_handler():
        logger.info("Received termination signal.")
        service.running = False
        server = getattr(service, "_server", None)
        if server is not None:
            server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _sig_handler)

    try:
        loop.run_until_complete(service.start())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    main()
