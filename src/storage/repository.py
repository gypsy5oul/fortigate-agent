"""Repository implementing durable state operations, leased queues, and outbox."""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from src.storage.database import Database

logger = logging.getLogger(__name__)


class Repository:
    def __init__(self, db: Database):
        self.db = db

    # --- Checkpoints & Coverage Gaps ---
    async def get_checkpoint(self, stream_name: str) -> Optional[int]:
        query = "SELECT last_queried_ts_ns FROM query_checkpoints WHERE stream_name = $1"
        row = await self.db.fetch_one(query, stream_name)
        if row:
            return row["last_queried_ts_ns"]
        return None

    async def save_checkpoint(self, stream_name: str, ts_ns: int):
        if self.db.is_sqlite:
            query = """
            INSERT INTO query_checkpoints (stream_name, last_queried_ts_ns, updated_at)
            VALUES ($1, $2, CURRENT_TIMESTAMP)
            ON CONFLICT(stream_name) DO UPDATE SET
                last_queried_ts_ns = excluded.last_queried_ts_ns,
                updated_at = CURRENT_TIMESTAMP
            """
        else:
            query = """
            INSERT INTO query_checkpoints (stream_name, last_queried_ts_ns, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (stream_name) DO UPDATE SET
                last_queried_ts_ns = EXCLUDED.last_queried_ts_ns,
                updated_at = NOW()
            """
        await self.db.execute(query, stream_name, ts_ns)

    async def record_coverage_gap(self, stream_name: str, start_ns: int, end_ns: int, reason: str):
        query = """
        INSERT INTO coverage_gaps (stream_name, start_ts_ns, end_ts_ns, reason)
        VALUES ($1, $2, $3, $4)
        """
        await self.db.execute(query, stream_name, start_ns, end_ns, reason)
        logger.warning("Recorded coverage gap on stream %s from %s to %s: %s", stream_name, start_ns, end_ns, reason)

    # --- Selected Events (Deduplicated) ---
    async def save_events(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0
        query = """
        INSERT INTO selected_events (
            id, loki_ts_ns, eventtime_ns, devid, logid, log_type, subtype,
            action_raw, action_normalized, srcip, srcport, dstip, dstport,
            proto, service, policyid, sessionid, signature, url, http_method,
            severity_raw, raw_message
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
        ON CONFLICT (id) DO NOTHING
        """
        rows = [
            (
                ev["id"],
                ev["loki_ts_ns"],
                ev.get("eventtime_ns"),
                ev.get("devid"),
                ev.get("logid"),
                ev["log_type"],
                ev.get("subtype"),
                ev.get("action_raw"),
                ev["action_normalized"],
                ev["srcip"],
                ev.get("srcport"),
                ev["dstip"],
                ev.get("dstport"),
                ev.get("proto"),
                ev.get("service"),
                ev.get("policyid"),
                ev.get("sessionid"),
                ev.get("signature"),
                ev.get("url"),
                ev.get("http_method"),
                ev.get("severity_raw"),
                ev["raw_message"],
            )
            for ev in events
        ]
        chunk_size = 500
        for i in range(0, len(rows), chunk_size):
            chunk = rows[i : i + chunk_size]
            try:
                await self.db.execute_many(query, chunk)
            except Exception as e:
                logger.error("Failed to batch insert events chunk: %s", e)
        return len(rows)

    # --- Incidents & Revisions ---
    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        query = "SELECT * FROM incidents WHERE id = $1"
        return await self.db.fetch_one(query, incident_id)

    async def upsert_incident(self, incident: Dict[str, Any]):
        if self.db.is_sqlite:
            query = """
            INSERT INTO incidents (
                id, current_revision, status, severity, enforcement,
                exploitation_assessment, source_ip, target_ip, target_app,
                first_seen, last_seen, event_count, summary, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                current_revision = excluded.current_revision,
                status = excluded.status,
                severity = excluded.severity,
                enforcement = excluded.enforcement,
                exploitation_assessment = excluded.exploitation_assessment,
                last_seen = excluded.last_seen,
                event_count = excluded.event_count,
                summary = excluded.summary,
                updated_at = CURRENT_TIMESTAMP
            """
        else:
            query = """
            INSERT INTO incidents (
                id, current_revision, status, severity, enforcement,
                exploitation_assessment, source_ip, target_ip, target_app,
                first_seen, last_seen, event_count, summary, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
            ON CONFLICT (id) DO UPDATE SET
                current_revision = EXCLUDED.current_revision,
                status = EXCLUDED.status,
                severity = EXCLUDED.severity,
                enforcement = EXCLUDED.enforcement,
                exploitation_assessment = EXCLUDED.exploitation_assessment,
                last_seen = EXCLUDED.last_seen,
                event_count = EXCLUDED.event_count,
                summary = EXCLUDED.summary,
                updated_at = NOW()
            """
        await self.db.execute(
            query,
            incident["id"],
            incident.get("current_revision", 1),
            incident.get("status", "ACTIVE"),
            incident["severity"],
            incident["enforcement"],
            incident.get("exploitation_assessment", "INSUFFICIENT_EVIDENCE"),
            incident["source_ip"],
            incident["target_ip"],
            incident.get("target_app"),
            incident["first_seen"],
            incident["last_seen"],
            incident.get("event_count", 1),
            incident.get("summary"),
        )

    async def add_incident_revision(self, revision: Dict[str, Any]):
        rule_ids = revision.get("rule_ids", [])
        evidence_ids = revision.get("evidence_ids", [])
        assessment_json = json.dumps(revision.get("assessment_json", {}), default=str)

        if self.db.is_sqlite:
            query = """
            INSERT INTO incident_revisions (
                incident_id, revision, rule_ids, severity, enforcement,
                assessment_json, model_name, reasoning_summary, evidence_ids
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """
            await self.db.execute(
                query,
                revision["incident_id"],
                revision["revision"],
                json.dumps(rule_ids),
                revision["severity"],
                revision["enforcement"],
                assessment_json,
                revision.get("model_name"),
                revision.get("reasoning_summary"),
                json.dumps(evidence_ids),
            )
        else:
            query = """
            INSERT INTO incident_revisions (
                incident_id, revision, rule_ids, severity, enforcement,
                assessment_json, model_name, reasoning_summary, evidence_ids
            ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
            """
            await self.db.execute(
                query,
                revision["incident_id"],
                revision["revision"],
                rule_ids,
                revision["severity"],
                revision["enforcement"],
                assessment_json,
                revision.get("model_name"),
                revision.get("reasoning_summary"),
                evidence_ids,
            )

    # --- Leased Job Queue ---
    async def enqueue_job(self, job_id: str, job_type: str, payload: Dict[str, Any], priority: int = 10):
        payload_str = json.dumps(payload, default=str)
        if self.db.is_sqlite:
            query = """
            INSERT INTO jobs (id, job_type, payload_json, priority, status, next_run_at)
            VALUES ($1, $2, $3, $4, 'PENDING', CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                priority = excluded.priority,
                status = CASE WHEN jobs.status IN ('COMPLETED', 'LEASED') THEN jobs.status ELSE 'PENDING' END,
                updated_at = CURRENT_TIMESTAMP
            """
        else:
            query = """
            INSERT INTO jobs (id, job_type, payload_json, priority, status, next_run_at)
            VALUES ($1, $2, $3::jsonb, $4, 'PENDING', NOW())
            ON CONFLICT (id) DO UPDATE SET
                priority = EXCLUDED.priority,
                status = CASE WHEN jobs.status IN ('COMPLETED', 'LEASED') THEN jobs.status ELSE 'PENDING' END,
                updated_at = NOW()
            """
        await self.db.execute(query, job_id, job_type, payload_str, priority)

    async def lease_next_job(self, worker_id: str, lease_duration_seconds: int = 60) -> Optional[Dict[str, Any]]:
        # Find candidate pending or expired lease
        now = datetime.now(timezone.utc)
        if self.db.is_sqlite:
            select_query = """
            SELECT id, version_token FROM jobs
            WHERE status = 'PENDING' OR (status = 'LEASED' AND lease_expires_at < CURRENT_TIMESTAMP)
            ORDER BY priority DESC, next_run_at ASC
            LIMIT 1
            """
        else:
            select_query = """
            SELECT id, version_token FROM jobs
            WHERE status = 'PENDING' OR (status = 'LEASED' AND lease_expires_at < NOW())
            ORDER BY priority DESC, next_run_at ASC
            LIMIT 1
            """
        candidate = await self.db.fetch_one(select_query)
        if not candidate:
            return None

        job_id = candidate["id"]
        v_token = candidate["version_token"]
        lease_expires = now + timedelta(seconds=lease_duration_seconds)

        if self.db.is_sqlite:
            update_query = """
            UPDATE jobs
            SET status = 'LEASED', lease_owner = $1, lease_expires_at = $2,
                version_token = version_token + 1, attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = $3 AND version_token = $4
            """
        else:
            update_query = """
            UPDATE jobs
            SET status = 'LEASED', lease_owner = $1, lease_expires_at = $2,
                version_token = version_token + 1, attempts = attempts + 1, updated_at = NOW()
            WHERE id = $3 AND version_token = $4
            """
        await self.db.execute(update_query, worker_id, lease_expires, job_id, v_token)

        # Retrieve freshly leased job
        job_row = await self.db.fetch_one("SELECT * FROM jobs WHERE id = $1 AND lease_owner = $2", job_id, worker_id)
        if job_row:
            payload = job_row["payload_json"]
            if isinstance(payload, str):
                job_row["payload"] = json.loads(payload)
            else:
                job_row["payload"] = payload
            return job_row
        return None

    async def complete_job(self, job_id: str, version_token: int):
        if self.db.is_sqlite:
            query = "UPDATE jobs SET status = 'COMPLETED', updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND version_token = $2"
        else:
            query = "UPDATE jobs SET status = 'COMPLETED', updated_at = NOW() WHERE id = $1 AND version_token = $2"
        await self.db.execute(query, job_id, version_token)

    async def fail_job(self, job_id: str, version_token: int, error_msg: str):
        if self.db.is_sqlite:
            query = """
            UPDATE jobs
            SET status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'PENDING' END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1 AND version_token = $2
            """
        else:
            query = """
            UPDATE jobs
            SET status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'PENDING' END,
                updated_at = NOW()
            WHERE id = $1 AND version_token = $2
            """
        await self.db.execute(query, job_id, version_token)
        logger.error("Job %s failed: %s", job_id, error_msg)

    # --- Notification Outbox ---
    async def enqueue_notification(self, incident_id: str, revision: int, notif_type: str, payload: Dict[str, Any]):
        payload_str = json.dumps(payload, default=str)
        if self.db.is_sqlite:
            query = """
            INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status)
            VALUES ($1, $2, $3, $4, 'PENDING')
            ON CONFLICT(incident_id, revision, notification_type) DO NOTHING
            """
        else:
            query = """
            INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status)
            VALUES ($1, $2, $3, $4::jsonb, 'PENDING')
            ON CONFLICT (incident_id, revision, notification_type) DO NOTHING
            """
        await self.db.execute(query, incident_id, revision, notif_type, payload_str)

    async def fetch_pending_notifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        query = "SELECT * FROM notification_outbox WHERE status = 'PENDING' ORDER BY id ASC LIMIT $1"
        rows = await self.db.fetch_all(query, limit)
        for r in rows:
            if isinstance(r["payload_json"], str):
                r["payload"] = json.loads(r["payload_json"])
            else:
                r["payload"] = r["payload_json"]
        return rows

    async def mark_notification_sent(self, outbox_id: int):
        if self.db.is_sqlite:
            query = "UPDATE notification_outbox SET status = 'SENT', sent_at = CURRENT_TIMESTAMP WHERE id = $1"
        else:
            query = "UPDATE notification_outbox SET status = 'SENT', sent_at = NOW() WHERE id = $1"
        await self.db.execute(query, outbox_id)

    async def mark_notification_failed(self, outbox_id: int, error_msg: str):
        if self.db.is_sqlite:
            query = """
            UPDATE notification_outbox
            SET attempts = attempts + 1, last_error = $1,
                status = CASE WHEN attempts >= 5 THEN 'DEAD_LETTER' ELSE 'PENDING' END
            WHERE id = $2
            """
        else:
            query = """
            UPDATE notification_outbox
            SET attempts = attempts + 1, last_error = $1,
                status = CASE WHEN attempts >= 5 THEN 'DEAD_LETTER' ELSE 'PENDING' END
            WHERE id = $2
            """
        await self.db.execute(query, error_msg[:500], outbox_id)
