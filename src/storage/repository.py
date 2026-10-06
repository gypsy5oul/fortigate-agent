"""Repository implementing durable state operations, leased queues, outbox, and atomic transitions."""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
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

    # --- Selected Events (Deduplicated with Accurate Counts) ---
    async def save_events(self, events: List[Dict[str, Any]]) -> int:
        """Insert events idempotently and return the count of newly inserted rows."""
        if not events:
            return 0

        rows = [
            (
                ev["id"],
                ev["loki_ts_ns"],
                ev.get("eventtime_ns"),
                ev.get("devid"),
                ev.get("vd", "root"),
                ev.get("direction", "UNKNOWN"),
                ev.get("srcintfrole"),
                ev.get("dstintfrole"),
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
                ev.get("processing_status", "PENDING"),
            )
            for ev in events
        ]

        if self.db.is_sqlite:
            initial_changes = self.db._sqlite_conn.total_changes
            query = """
            INSERT INTO selected_events (
                id, loki_ts_ns, eventtime_ns, devid, vd, direction, srcintfrole, dstintfrole,
                logid, log_type, subtype, action_raw, action_normalized, srcip, srcport,
                dstip, dstport, proto, service, policyid, sessionid, signature, url,
                http_method, severity_raw, raw_message, processing_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING
            """
            chunk_size = 500
            for i in range(0, len(rows), chunk_size):
                chunk = rows[i : i + chunk_size]
                await self.db._sqlite_conn.executemany(query, chunk)
                await self.db._sqlite_conn.commit()
            return self.db._sqlite_conn.total_changes - initial_changes

        # PostgreSQL: multi-row insert with RETURNING id
        chunk_size = 200
        total_inserted = 0
        async with self.db._pg_pool.acquire() as conn:
            for i in range(0, len(rows), chunk_size):
                chunk = rows[i : i + chunk_size]
                values_clauses = []
                flat_args = []
                for r_idx, row in enumerate(chunk):
                    param_start = r_idx * 27 + 1
                    placeholders = ", ".join(f"${param_start + k}" for k in range(27))
                    values_clauses.append(f"({placeholders})")
                    flat_args.extend(row)

                insert_sql = f"""
                INSERT INTO selected_events (
                    id, loki_ts_ns, eventtime_ns, devid, vd, direction, srcintfrole, dstintfrole,
                    logid, log_type, subtype, action_raw, action_normalized, srcip, srcport,
                    dstip, dstport, proto, service, policyid, sessionid, signature, url,
                    http_method, severity_raw, raw_message, processing_status
                ) VALUES {', '.join(values_clauses)}
                ON CONFLICT (id) DO NOTHING
                RETURNING id;
                """
                inserted_rows = await conn.fetch(insert_sql, *flat_args)
                total_inserted += len(inserted_rows)
        return total_inserted

    async def fetch_pending_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch pending events in stable ascending chronological order."""
        query = """
        SELECT * FROM selected_events
        WHERE processing_status = 'PENDING'
        ORDER BY loki_ts_ns ASC, id ASC
        LIMIT $1
        """
        return await self.db.fetch_all(query, limit)

    async def mark_events_processed(self, event_ids: List[str]) -> None:
        if not event_ids:
            return
        if self.db.is_sqlite:
            for eid in event_ids:
                await self.db.execute(
                    "UPDATE selected_events SET processing_status = 'PROCESSED', processed_at = CURRENT_TIMESTAMP WHERE id = $1",
                    eid,
                )
        else:
            await self.db.execute(
                "UPDATE selected_events SET processing_status = 'PROCESSED', processed_at = NOW() WHERE id = ANY($1::varchar[])",
                event_ids,
            )

    # --- Incidents & Revisions ---
    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        query = "SELECT * FROM incidents WHERE id = $1"
        return await self.db.fetch_one(query, incident_id)

    async def upsert_incident(self, incident: Dict[str, Any]):
        if self.db.is_sqlite:
            query = """
            INSERT INTO incidents (
                id, current_revision, status, severity, enforcement,
                exploitation_assessment, vd, direction, source_ip, target_ip,
                target_port, target_service, target_app,
                first_seen, last_seen, event_count, summary, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                current_revision = excluded.current_revision,
                status = excluded.status,
                severity = excluded.severity,
                enforcement = excluded.enforcement,
                exploitation_assessment = excluded.exploitation_assessment,
                target_port = excluded.target_port,
                target_service = excluded.target_service,
                last_seen = excluded.last_seen,
                event_count = excluded.event_count,
                summary = excluded.summary,
                updated_at = CURRENT_TIMESTAMP
            """
        else:
            query = """
            INSERT INTO incidents (
                id, current_revision, status, severity, enforcement,
                exploitation_assessment, vd, direction, source_ip, target_ip,
                target_port, target_service, target_app,
                first_seen, last_seen, event_count, summary, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NOW())
            ON CONFLICT (id) DO UPDATE SET
                current_revision = EXCLUDED.current_revision,
                status = EXCLUDED.status,
                severity = EXCLUDED.severity,
                enforcement = EXCLUDED.enforcement,
                exploitation_assessment = EXCLUDED.exploitation_assessment,
                target_port = EXCLUDED.target_port,
                target_service = EXCLUDED.target_service,
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
            incident.get("vd", "root"),
            incident.get("direction", "INBOUND"),
            incident["source_ip"],
            incident["target_ip"],
            incident.get("target_port"),
            incident.get("target_service"),
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
            ON CONFLICT(incident_id, revision) DO NOTHING
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
            ON CONFLICT (incident_id, revision) DO NOTHING
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

    async def record_incident_transition(
        self,
        incident: Dict[str, Any],
        revision: Optional[Dict[str, Any]] = None,
        notification: Optional[Dict[str, Any]] = None,
        job: Optional[Dict[str, Any]] = None,
        processed_event_ids: Optional[List[str]] = None,
    ) -> None:
        """Atomic transaction updating incident, revision, outbox, job queue, and acknowledging processed events."""
        async with self.db.transaction() as tx:
            # 1. Upsert incident
            if self.db.is_sqlite:
                inc_query = """
                INSERT INTO incidents (
                    id, current_revision, status, severity, enforcement,
                    exploitation_assessment, vd, direction, source_ip, target_ip,
                    target_port, target_service, target_app,
                    first_seen, last_seen, event_count, summary, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    current_revision = excluded.current_revision,
                    status = excluded.status,
                    severity = excluded.severity,
                    enforcement = excluded.enforcement,
                    exploitation_assessment = excluded.exploitation_assessment,
                    target_port = excluded.target_port,
                    target_service = excluded.target_service,
                    last_seen = excluded.last_seen,
                    event_count = excluded.event_count,
                    summary = excluded.summary,
                    updated_at = CURRENT_TIMESTAMP
                """
            else:
                inc_query = """
                INSERT INTO incidents (
                    id, current_revision, status, severity, enforcement,
                    exploitation_assessment, vd, direction, source_ip, target_ip,
                    target_port, target_service, target_app,
                    first_seen, last_seen, event_count, summary, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    current_revision = EXCLUDED.current_revision,
                    status = EXCLUDED.status,
                    severity = EXCLUDED.severity,
                    enforcement = EXCLUDED.enforcement,
                    exploitation_assessment = EXCLUDED.exploitation_assessment,
                    target_port = EXCLUDED.target_port,
                    target_service = EXCLUDED.target_service,
                    last_seen = EXCLUDED.last_seen,
                    event_count = EXCLUDED.event_count,
                    summary = EXCLUDED.summary,
                    updated_at = NOW()
                """
            await tx.execute(
                inc_query,
                incident["id"],
                incident.get("current_revision", 1),
                incident.get("status", "ACTIVE"),
                incident["severity"],
                incident["enforcement"],
                incident.get("exploitation_assessment", "INSUFFICIENT_EVIDENCE"),
                incident.get("vd", "root"),
                incident.get("direction", "INBOUND"),
                incident["source_ip"],
                incident["target_ip"],
                incident.get("target_port"),
                incident.get("target_service"),
                incident.get("target_app"),
                incident["first_seen"],
                incident["last_seen"],
                incident.get("event_count", 1),
                incident.get("summary"),
            )

            # 2. Add revision if provided
            if revision:
                rule_ids = revision.get("rule_ids", [])
                evidence_ids = revision.get("evidence_ids", [])
                assessment_json = json.dumps(revision.get("assessment_json", {}), default=str)
                if self.db.is_sqlite:
                    rev_query = """
                    INSERT INTO incident_revisions (
                        incident_id, revision, rule_ids, severity, enforcement,
                        assessment_json, model_name, reasoning_summary, evidence_ids
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT(incident_id, revision) DO NOTHING
                    """
                    await tx.execute(
                        rev_query,
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
                    rev_query = """
                    INSERT INTO incident_revisions (
                        incident_id, revision, rule_ids, severity, enforcement,
                        assessment_json, model_name, reasoning_summary, evidence_ids
                    ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
                    ON CONFLICT (incident_id, revision) DO NOTHING
                    """
                    await tx.execute(
                        rev_query,
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

            # 3. Enqueue notification if provided
            if notification:
                n_payload = json.dumps(notification["payload"], default=str)
                if self.db.is_sqlite:
                    notif_query = """
                    INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status)
                    VALUES ($1, $2, $3, $4, 'PENDING')
                    ON CONFLICT(incident_id, revision, notification_type) DO NOTHING
                    """
                else:
                    notif_query = """
                    INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status)
                    VALUES ($1, $2, $3, $4::jsonb, 'PENDING')
                    ON CONFLICT (incident_id, revision, notification_type) DO NOTHING
                    """
                await tx.execute(
                    notif_query,
                    notification["incident_id"],
                    notification["revision"],
                    notification["notification_type"],
                    n_payload,
                )

            # 4. Enqueue job if provided
            if job:
                j_payload = json.dumps(job["payload"], default=str)
                if self.db.is_sqlite:
                    job_query = """
                    INSERT INTO jobs (id, job_type, payload_json, priority, status, next_run_at)
                    VALUES ($1, $2, $3, $4, 'PENDING', CURRENT_TIMESTAMP)
                    ON CONFLICT(id) DO UPDATE SET
                        priority = excluded.priority,
                        status = CASE WHEN jobs.status IN ('COMPLETED', 'LEASED') THEN jobs.status ELSE 'PENDING' END,
                        updated_at = CURRENT_TIMESTAMP
                    """
                else:
                    job_query = """
                    INSERT INTO jobs (id, job_type, payload_json, priority, status, next_run_at)
                    VALUES ($1, $2, $3::jsonb, $4, 'PENDING', NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        priority = EXCLUDED.priority,
                        status = CASE WHEN jobs.status IN ('COMPLETED', 'LEASED') THEN jobs.status ELSE 'PENDING' END,
                        updated_at = NOW()
                    """
                await tx.execute(job_query, job["id"], job["job_type"], j_payload, job.get("priority", 10))

            # 5. Acknowledge processed events
            if processed_event_ids:
                if self.db.is_sqlite:
                    for eid in processed_event_ids:
                        await tx.execute(
                            "UPDATE selected_events SET processing_status = 'PROCESSED', processed_at = CURRENT_TIMESTAMP WHERE id = $1",
                            eid,
                        )
                else:
                    await tx.execute(
                        "UPDATE selected_events SET processing_status = 'PROCESSED', processed_at = NOW() WHERE id = ANY($1::varchar[])",
                        processed_event_ids,
                    )

    # --- Leased Job Queue (Atomic & Fenced) ---
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
        if not self.db.is_sqlite:
            # Atomic PostgreSQL CTE lease with FOR UPDATE SKIP LOCKED
            query = """
            WITH candidate AS (
                SELECT id, version_token FROM jobs
                WHERE (status = 'PENDING' AND next_run_at <= NOW())
                   OR (status = 'LEASED' AND lease_expires_at < NOW())
                ORDER BY priority DESC, next_run_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE jobs j
            SET status = 'LEASED',
                lease_owner = $1,
                lease_expires_at = NOW() + ($2 || ' seconds')::interval,
                version_token = j.version_token + 1,
                attempts = j.attempts + 1,
                updated_at = NOW()
            FROM candidate c
            WHERE j.id = c.id
            RETURNING j.*;
            """
            async with self.db._pg_pool.acquire() as conn:
                row = await conn.fetchrow(query, worker_id, str(lease_duration_seconds))
                if row:
                    job_dict = dict(row)
                    payload = job_dict.get("payload_json")
                    if isinstance(payload, str):
                        job_dict["payload"] = json.loads(payload)
                    else:
                        job_dict["payload"] = payload
                    return job_dict
                return None

        # SQLite atomic transaction
        now = datetime.now(timezone.utc)
        async with self.db.transaction() as tx:
            select_query = """
            SELECT id, version_token FROM jobs
            WHERE (status = 'PENDING' AND next_run_at <= CURRENT_TIMESTAMP)
               OR (status = 'LEASED' AND lease_expires_at < CURRENT_TIMESTAMP)
            ORDER BY priority DESC, next_run_at ASC
            LIMIT 1
            """
            candidate = await tx.fetch_one(select_query)
            if not candidate:
                return None

            job_id = candidate["id"]
            v_token = candidate["version_token"]
            lease_expires = (now + timedelta(seconds=lease_duration_seconds)).strftime("%Y-%m-%d %H:%M:%S")

            update_query = """
            UPDATE jobs
            SET status = 'LEASED', lease_owner = $1, lease_expires_at = $2,
                version_token = version_token + 1, attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = $3 AND version_token = $4
            """
            await tx.execute(update_query, worker_id, lease_expires, job_id, v_token)

            job_row = await tx.fetch_one("SELECT * FROM jobs WHERE id = $1 AND lease_owner = $2", job_id, worker_id)
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

    async def mark_notification_simulated(self, outbox_id: int):
        if self.db.is_sqlite:
            query = "UPDATE notification_outbox SET status = 'SIMULATED', sent_at = CURRENT_TIMESTAMP WHERE id = $1"
        else:
            query = "UPDATE notification_outbox SET status = 'SIMULATED', sent_at = NOW() WHERE id = $1"
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
