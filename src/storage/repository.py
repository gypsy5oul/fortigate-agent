"""Repository implementing durable state operations, leased queues, outbox, and atomic transitions."""

import json
import logging
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from src.storage.database import Database
from src.storage.timeutil import to_utc_datetime
from src.observability.metrics import PARSER_ERRORS_TOTAL, MODEL_FAILURES_TOTAL

logger = logging.getLogger(__name__)


class RevisionConflict(Exception):
    """Raised when an incident transition update fails due to revision mismatch."""
    pass


class StaleJobLeaseError(Exception):
    """Raised when a job write attempts to commit with a stale version token or expired lease."""
    pass


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
        existing = await self.get_checkpoint(stream_name)
        if existing is not None:
            assert ts_ns >= existing, f"Checkpoint regression: existing {existing} > new {ts_ns}"

        if self.db.is_sqlite:
            query = """
            INSERT INTO query_checkpoints (stream_name, last_queried_ts_ns, updated_at)
            VALUES ($1, $2, CURRENT_TIMESTAMP)
            ON CONFLICT(stream_name) DO UPDATE SET
                last_queried_ts_ns = MAX(query_checkpoints.last_queried_ts_ns, excluded.last_queried_ts_ns),
                updated_at = CURRENT_TIMESTAMP
            """
        else:
            query = """
            INSERT INTO query_checkpoints (stream_name, last_queried_ts_ns, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (stream_name) DO UPDATE SET
                last_queried_ts_ns = GREATEST(query_checkpoints.last_queried_ts_ns, EXCLUDED.last_queried_ts_ns),
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

    async def get_coverage_gaps(self, stream_name: str) -> List[Dict[str, Any]]:
        query = "SELECT * FROM coverage_gaps WHERE stream_name = $1 ORDER BY start_ts_ns ASC"
        return await self.db.fetch_all(query, stream_name)

    # --- Selected Events (Deduplicated with Accurate Counts) ---
    async def save_events(self, events: List[Dict[str, Any]]) -> int:
        """Insert events idempotently and return the count of newly inserted rows.
        
        If a batch insert fails, retries row-by-row, logging failed rows to rejected_events,
        incrementing PARSER_ERRORS_TOTAL, and allowing the checkpoint to advance.
        """
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
                ev.get("utmaction"),
                bool(ev.get("signature_truncated", False)),
            )
            for ev in events
        ]

        if self.db.is_sqlite:
            inserted_count = 0
            query = """
            INSERT INTO selected_events (
                id, loki_ts_ns, eventtime_ns, devid, vd, direction, srcintfrole, dstintfrole,
                logid, log_type, subtype, action_raw, action_normalized, srcip, srcport,
                dstip, dstport, proto, service, policyid, sessionid, signature, url,
                http_method, severity_raw, raw_message, processing_status, utmaction, signature_truncated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING
            """
            chunk_size = 500
            for i in range(0, len(rows), chunk_size):
                chunk = rows[i : i + chunk_size]
                chunk_events = events[i : i + chunk_size]
                try:
                    ch_before = self.db._sqlite_conn.total_changes
                    await self.db._sqlite_conn.executemany(query, chunk)
                    await self.db._sqlite_conn.commit()
                    inserted_count += (self.db._sqlite_conn.total_changes - ch_before)
                except Exception as batch_err:
                    await self.db._sqlite_conn.rollback()
                    logger.warning("SQLite batch insert failed (%s), falling back to row-by-row insert", batch_err)
                    for row_tuple, ev in zip(chunk, chunk_events):
                        try:
                            ch_before = self.db._sqlite_conn.total_changes
                            await self.db._sqlite_conn.execute(query, row_tuple)
                            await self.db._sqlite_conn.commit()
                            inserted_count += (self.db._sqlite_conn.total_changes - ch_before)
                        except Exception as row_err:
                            await self.db._sqlite_conn.rollback()
                            PARSER_ERRORS_TOTAL.inc()
                            raw_sha256 = hashlib.sha256((ev.get("raw_message") or "").encode("utf-8")).hexdigest()
                            logger.error("Row insert rejected for event %s: %s", ev.get("id"), row_err)
                            await self.db._sqlite_conn.execute(
                                "INSERT INTO rejected_events (id, reason, raw_sha256) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING",
                                (ev.get("id", str(uuid.uuid4())), str(row_err)[:1000], raw_sha256),
                            )
                            await self.db._sqlite_conn.commit()
            return inserted_count

        # PostgreSQL: multi-row insert with RETURNING id
        chunk_size = 200
        total_inserted = 0
        async with self.db._pg_pool.acquire() as conn:
            for i in range(0, len(rows), chunk_size):
                chunk = rows[i : i + chunk_size]
                chunk_events = events[i : i + chunk_size]
                values_clauses = []
                flat_args = []
                for r_idx, row in enumerate(chunk):
                    param_start = r_idx * 29 + 1
                    placeholders = ", ".join(f"${param_start + k}" for k in range(29))
                    values_clauses.append(f"({placeholders})")
                    flat_args.extend(row)

                insert_sql = f"""
                INSERT INTO selected_events (
                    id, loki_ts_ns, eventtime_ns, devid, vd, direction, srcintfrole, dstintfrole,
                    logid, log_type, subtype, action_raw, action_normalized, srcip, srcport,
                    dstip, dstport, proto, service, policyid, sessionid, signature, url,
                    http_method, severity_raw, raw_message, processing_status, utmaction, signature_truncated
                ) VALUES {', '.join(values_clauses)}
                ON CONFLICT (id) DO NOTHING
                RETURNING id;
                """
                try:
                    inserted_rows = await conn.fetch(insert_sql, *flat_args)
                    total_inserted += len(inserted_rows)
                except Exception as batch_err:
                    logger.warning("Postgres batch insert failed (%s), falling back to row-by-row insert", batch_err)
                    single_sql = f"""
                    INSERT INTO selected_events (
                        id, loki_ts_ns, eventtime_ns, devid, vd, direction, srcintfrole, dstintfrole,
                        logid, log_type, subtype, action_raw, action_normalized, srcip, srcport,
                        dstip, dstport, proto, service, policyid, sessionid, signature, url,
                        http_method, severity_raw, raw_message, processing_status, utmaction, signature_truncated
                    ) VALUES ({', '.join(f'${k+1}' for k in range(29))})
                    ON CONFLICT (id) DO NOTHING
                    RETURNING id;
                    """
                    for row_tuple, ev in zip(chunk, chunk_events):
                        try:
                            res = await conn.fetch(single_sql, *row_tuple)
                            total_inserted += len(res)
                        except Exception as row_err:
                            PARSER_ERRORS_TOTAL.inc()
                            raw_sha256 = hashlib.sha256((ev.get("raw_message") or "").encode("utf-8")).hexdigest()
                            logger.error("Row insert rejected for event %s: %s", ev.get("id"), row_err)
                            await conn.execute(
                                "INSERT INTO rejected_events (id, reason, raw_sha256) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
                                ev.get("id", str(uuid.uuid4())),
                                str(row_err)[:1000],
                                raw_sha256,
                            )
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
        row = await self.db.fetch_one(query, incident_id)
        if row and self.db.is_sqlite and isinstance(row.get("deterministic_rule_ids"), str):
            try:
                row["deterministic_rule_ids"] = json.loads(row["deterministic_rule_ids"])
            except Exception:
                row["deterministic_rule_ids"] = []
        return row

    async def upsert_incident(self, incident: Dict[str, Any]):
        first_seen_dt = to_utc_datetime(incident["first_seen"])
        last_seen_dt = to_utc_datetime(incident["last_seen"])
        last_urgent_at_dt = to_utc_datetime(incident.get("last_urgent_at"))
        rule_ids = incident.get("deterministic_rule_ids", [])
        if isinstance(rule_ids, set):
            rule_ids = list(rule_ids)

        if self.db.is_sqlite:
            query = """
            INSERT INTO incidents (
                id, current_revision, status, severity, enforcement,
                exploitation_assessment, vd, direction, source_ip, target_ip,
                target_port, target_service, target_app,
                first_seen, last_seen, event_count, summary,
                deterministic_severity, deterministic_enforcement, deterministic_rule_ids,
                last_urgent_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, CURRENT_TIMESTAMP)
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
                deterministic_severity = excluded.deterministic_severity,
                deterministic_enforcement = excluded.deterministic_enforcement,
                deterministic_rule_ids = excluded.deterministic_rule_ids,
                last_urgent_at = excluded.last_urgent_at,
                updated_at = CURRENT_TIMESTAMP
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
                first_seen_dt.strftime("%Y-%m-%d %H:%M:%S") if first_seen_dt else None,
                last_seen_dt.strftime("%Y-%m-%d %H:%M:%S") if last_seen_dt else None,
                incident.get("event_count", 1),
                incident.get("summary"),
                incident.get("deterministic_severity", incident["severity"]),
                incident.get("deterministic_enforcement", incident["enforcement"]),
                json.dumps(rule_ids),
                last_urgent_at_dt.strftime("%Y-%m-%d %H:%M:%S") if last_urgent_at_dt else None,
            )
        else:
            query = """
            INSERT INTO incidents (
                id, current_revision, status, severity, enforcement,
                exploitation_assessment, vd, direction, source_ip, target_ip,
                target_port, target_service, target_app,
                first_seen, last_seen, event_count, summary,
                deterministic_severity, deterministic_enforcement, deterministic_rule_ids,
                last_urgent_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW())
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
                deterministic_severity = EXCLUDED.deterministic_severity,
                deterministic_enforcement = EXCLUDED.deterministic_enforcement,
                deterministic_rule_ids = EXCLUDED.deterministic_rule_ids,
                last_urgent_at = EXCLUDED.last_urgent_at,
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
                first_seen_dt,
                last_seen_dt,
                incident.get("event_count", 1),
                incident.get("summary"),
                incident.get("deterministic_severity", incident["severity"]),
                incident.get("deterministic_enforcement", incident["enforcement"]),
                rule_ids,
                last_urgent_at_dt,
            )

    async def add_incident_revision(self, revision: Dict[str, Any]):
        rule_ids = revision.get("rule_ids", [])
        if isinstance(rule_ids, set):
            rule_ids = list(rule_ids)
        evidence_ids = revision.get("evidence_ids", [])
        assessment_json = json.dumps(revision.get("assessment_json", {}), default=str)
        assessment_source = revision.get("assessment_source", "DETERMINISTIC")

        if self.db.is_sqlite:
            query = """
            INSERT INTO incident_revisions (
                incident_id, revision, rule_ids, severity, enforcement,
                assessment_json, model_name, reasoning_summary, evidence_ids, assessment_source
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
                assessment_source,
            )
        else:
            query = """
            INSERT INTO incident_revisions (
                incident_id, revision, rule_ids, severity, enforcement,
                assessment_json, model_name, reasoning_summary, evidence_ids, assessment_source
            ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
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
                assessment_source,
            )

    async def record_incident_transition(
        self,
        incident: Dict[str, Any],
        revision: Optional[Dict[str, Any]] = None,
        notification: Optional[Dict[str, Any]] = None,
        job: Optional[Dict[str, Any]] = None,
        processed_event_ids: Optional[List[str]] = None,
        expected_revision: Optional[int] = None,
        fence_job_id: Optional[str] = None,
        fence_version_token: Optional[int] = None,
    ) -> int:
        """Atomic transaction updating incident, revision, outbox, job queue, and acknowledging processed events.
        
        Enforces optimistic revision concurrency and job leasing fences.
        Revision number is allocated inside transaction from freshly read current_revision.
        """
        async with self.db.transaction() as tx:
            # 1. Fence check if completing a leased job
            if fence_job_id is not None and fence_version_token is not None:
                if self.db.is_sqlite:
                    cursor = await tx.execute(
                        "UPDATE jobs SET status = 'COMPLETED', updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND version_token = $2",
                        fence_job_id, fence_version_token,
                    )
                    if cursor.rowcount == 0:
                        raise StaleJobLeaseError(f"Job {fence_job_id} lease stale (token {fence_version_token})")
                else:
                    res = await tx.fetch(
                        "UPDATE jobs SET status = 'COMPLETED', updated_at = NOW() WHERE id = $1 AND version_token = $2 RETURNING id",
                        fence_job_id, fence_version_token,
                    )
                    if not res:
                        raise StaleJobLeaseError(f"Job {fence_job_id} lease stale (token {fence_version_token})")

            # 2. Fetch existing incident row to verify revision and allocate next revision
            if self.db.is_sqlite:
                existing = await tx.fetch_one("SELECT * FROM incidents WHERE id = $1", incident["id"])
            else:
                existing = await tx.fetch_one("SELECT * FROM incidents WHERE id = $1 FOR UPDATE", incident["id"])

            if existing:
                current_rev = existing["current_revision"]
                if expected_revision is not None and current_rev != expected_revision:
                    raise RevisionConflict(
                        f"Incident {incident['id']} current revision is {current_rev}, expected {expected_revision}"
                    )
                new_rev = current_rev + 1
            else:
                if expected_revision is not None and expected_revision > 0:
                    raise RevisionConflict(
                        f"Incident {incident['id']} does not exist, but expected_revision was {expected_revision}"
                    )
                new_rev = 1

            first_seen_dt = to_utc_datetime(incident["first_seen"])
            last_seen_dt = to_utc_datetime(incident["last_seen"])
            last_urgent_at_dt = to_utc_datetime(incident.get("last_urgent_at"))
            rule_ids = incident.get("deterministic_rule_ids", [])
            if isinstance(rule_ids, set):
                rule_ids = list(rule_ids)

            # 3. Update or Insert Incident row
            if self.db.is_sqlite:
                if existing:
                    upd_query = """
                    UPDATE incidents SET
                        current_revision = $1, status = $2, severity = $3, enforcement = $4,
                        exploitation_assessment = $5, target_port = $6, target_service = $7,
                        last_seen = $8, event_count = $9, summary = $10,
                        deterministic_severity = $11, deterministic_enforcement = $12,
                        deterministic_rule_ids = $13, last_urgent_at = $14,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $15 AND current_revision = $16
                    """
                    cursor = await tx.execute(
                        upd_query,
                        new_rev,
                        incident.get("status", "ACTIVE"),
                        incident["severity"],
                        incident["enforcement"],
                        incident.get("exploitation_assessment", "INSUFFICIENT_EVIDENCE"),
                        incident.get("target_port"),
                        incident.get("target_service"),
                        last_seen_dt.strftime("%Y-%m-%d %H:%M:%S") if last_seen_dt else None,
                        incident.get("event_count", 1),
                        incident.get("summary"),
                        incident.get("deterministic_severity", incident["severity"]),
                        incident.get("deterministic_enforcement", incident["enforcement"]),
                        json.dumps(rule_ids),
                        last_urgent_at_dt.strftime("%Y-%m-%d %H:%M:%S") if last_urgent_at_dt else None,
                        incident["id"],
                        current_rev,
                    )
                    if cursor.rowcount == 0:
                        raise RevisionConflict(f"Concurrent update conflict on incident {incident['id']}")
                else:
                    ins_query = """
                    INSERT INTO incidents (
                        id, current_revision, status, severity, enforcement,
                        exploitation_assessment, vd, direction, source_ip, target_ip,
                        target_port, target_service, target_app,
                        first_seen, last_seen, event_count, summary,
                        deterministic_severity, deterministic_enforcement, deterministic_rule_ids,
                        last_urgent_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, CURRENT_TIMESTAMP)
                    """
                    await tx.execute(
                        ins_query,
                        incident["id"],
                        new_rev,
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
                        first_seen_dt.strftime("%Y-%m-%d %H:%M:%S") if first_seen_dt else None,
                        last_seen_dt.strftime("%Y-%m-%d %H:%M:%S") if last_seen_dt else None,
                        incident.get("event_count", 1),
                        incident.get("summary"),
                        incident.get("deterministic_severity", incident["severity"]),
                        incident.get("deterministic_enforcement", incident["enforcement"]),
                        json.dumps(rule_ids),
                        last_urgent_at_dt.strftime("%Y-%m-%d %H:%M:%S") if last_urgent_at_dt else None,
                    )
            else:
                if existing:
                    upd_query = """
                    UPDATE incidents SET
                        current_revision = $1, status = $2, severity = $3, enforcement = $4,
                        exploitation_assessment = $5, target_port = $6, target_service = $7,
                        last_seen = $8, event_count = $9, summary = $10,
                        deterministic_severity = $11, deterministic_enforcement = $12,
                        deterministic_rule_ids = $13, last_urgent_at = $14,
                        updated_at = NOW()
                    WHERE id = $15 AND current_revision = $16
                    RETURNING id;
                    """
                    res = await tx.fetch(
                        upd_query,
                        new_rev,
                        incident.get("status", "ACTIVE"),
                        incident["severity"],
                        incident["enforcement"],
                        incident.get("exploitation_assessment", "INSUFFICIENT_EVIDENCE"),
                        incident.get("target_port"),
                        incident.get("target_service"),
                        last_seen_dt,
                        incident.get("event_count", 1),
                        incident.get("summary"),
                        incident.get("deterministic_severity", incident["severity"]),
                        incident.get("deterministic_enforcement", incident["enforcement"]),
                        rule_ids,
                        last_urgent_at_dt,
                        incident["id"],
                        current_rev,
                    )
                    if not res:
                        raise RevisionConflict(f"Concurrent update conflict on incident {incident['id']}")
                else:
                    ins_query = """
                    INSERT INTO incidents (
                        id, current_revision, status, severity, enforcement,
                        exploitation_assessment, vd, direction, source_ip, target_ip,
                        target_port, target_service, target_app,
                        first_seen, last_seen, event_count, summary,
                        deterministic_severity, deterministic_enforcement, deterministic_rule_ids,
                        last_urgent_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW())
                    """
                    await tx.execute(
                        ins_query,
                        incident["id"],
                        new_rev,
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
                        first_seen_dt,
                        last_seen_dt,
                        incident.get("event_count", 1),
                        incident.get("summary"),
                        incident.get("deterministic_severity", incident["severity"]),
                        incident.get("deterministic_enforcement", incident["enforcement"]),
                        rule_ids,
                        last_urgent_at_dt,
                    )

            # 4. Add revision if provided
            if revision:
                rev_rule_ids = revision.get("rule_ids", [])
                if isinstance(rev_rule_ids, set):
                    rev_rule_ids = list(rev_rule_ids)
                rev_evidence_ids = revision.get("evidence_ids", [])
                assessment_json = json.dumps(revision.get("assessment_json", {}), default=str)
                assessment_src = revision.get("assessment_source", "DETERMINISTIC")

                if self.db.is_sqlite:
                    rev_query = """
                    INSERT INTO incident_revisions (
                        incident_id, revision, rule_ids, severity, enforcement,
                        assessment_json, model_name, reasoning_summary, evidence_ids, assessment_source
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT(incident_id, revision) DO NOTHING
                    """
                    await tx.execute(
                        rev_query,
                        incident["id"],
                        new_rev,
                        json.dumps(rev_rule_ids),
                        revision["severity"],
                        revision["enforcement"],
                        assessment_json,
                        revision.get("model_name"),
                        revision.get("reasoning_summary"),
                        json.dumps(rev_evidence_ids),
                        assessment_src,
                    )
                else:
                    rev_query = """
                    INSERT INTO incident_revisions (
                        incident_id, revision, rule_ids, severity, enforcement,
                        assessment_json, model_name, reasoning_summary, evidence_ids, assessment_source
                    ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
                    ON CONFLICT (incident_id, revision) DO NOTHING
                    """
                    await tx.execute(
                        rev_query,
                        incident["id"],
                        new_rev,
                        rev_rule_ids,
                        revision["severity"],
                        revision["enforcement"],
                        assessment_json,
                        revision.get("model_name"),
                        revision.get("reasoning_summary"),
                        rev_evidence_ids,
                        assessment_src,
                    )

            # 5. Enqueue notification if provided
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
                    incident["id"],
                    new_rev,
                    notification["notification_type"],
                    n_payload,
                )

            # 6. Enqueue job if provided
            if job:
                j_payload = dict(job.get("payload", {}))
                j_payload["revision"] = new_rev
                j_payload_str = json.dumps(j_payload, default=str)
                job_id = f"JOB-{incident['id']}-{new_rev}"
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
                await tx.execute(job_query, job_id, job["job_type"], j_payload_str, job.get("priority", 10))

            # 7. Acknowledge processed events
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

            return new_rev

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
                WHERE ((status = 'PENDING' AND next_run_at <= NOW())
                   OR (status = 'LEASED' AND lease_expires_at < NOW()))
                  AND attempts < max_attempts
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
            WHERE ((status = 'PENDING' AND next_run_at <= CURRENT_TIMESTAMP)
               OR (status = 'LEASED' AND lease_expires_at < CURRENT_TIMESTAMP))
              AND attempts < max_attempts
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
        job = await self.db.fetch_one("SELECT * FROM jobs WHERE id = $1", job_id)
        if not job:
            return
        attempts = job["attempts"]
        max_attempts = job.get("max_attempts", 3)

        if attempts >= max_attempts:
            if self.db.is_sqlite:
                await self.db.execute(
                    "UPDATE jobs SET status = 'FAILED', updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND version_token = $2",
                    job_id, version_token,
                )
            else:
                await self.db.execute(
                    "UPDATE jobs SET status = 'FAILED', updated_at = NOW() WHERE id = $1 AND version_token = $2",
                    job_id, version_token,
                )
            MODEL_FAILURES_TOTAL.inc()
            logger.error("Job %s reached max_attempts (%s); marked FAILED: %s", job_id, max_attempts, error_msg)

            # Persist MODEL_REJECTED_FALLBACK revision
            payload = job.get("payload_json")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = {}
            if isinstance(payload, dict):
                inc_id = payload.get("incident_id")
                rule_eval = payload.get("rule_eval", {})
                if inc_id:
                    existing_inc = await self.get_incident(inc_id)
                    cur_rev = existing_inc["current_revision"] if existing_inc else payload.get("revision", 1)
                    fallback_rev_num = cur_rev + 1
                    fallback_summary = "Deterministic assessment only. Model analysis unavailable (reason code: MODEL_UNREACHABLE)."
                    fallback_rev = {
                        "incident_id": inc_id,
                        "revision": fallback_rev_num,
                        "rule_ids": rule_eval.get("matched_rule_ids", []),
                        "severity": rule_eval.get("severity_floor", "MEDIUM"),
                        "enforcement": payload.get("episode", {}).get("enforcement", "UNKNOWN"),
                        "assessment_json": {
                            "severity": rule_eval.get("severity_floor", "MEDIUM"),
                            "enforcement": payload.get("episode", {}).get("enforcement", "UNKNOWN"),
                            "summary": fallback_summary,
                            "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"],
                            "reason_code": "MODEL_UNREACHABLE",
                        },
                        "model_name": None,
                        "reasoning_summary": fallback_summary,
                        "evidence_ids": [],
                        "assessment_source": "MODEL_REJECTED_FALLBACK",
                    }
                    try:
                        await self.add_incident_revision(fallback_rev)
                        if existing_inc:
                            if self.db.is_sqlite:
                                await self.db.execute("UPDATE incidents SET current_revision = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", fallback_rev_num, inc_id)
                            else:
                                await self.db.execute("UPDATE incidents SET current_revision = $1, updated_at = NOW() WHERE id = $2", fallback_rev_num, inc_id)
                    except Exception as rev_err:
                        logger.warning("Could not persist fallback revision for %s: %s", inc_id, rev_err)
        else:
            delay_seconds = min((2 ** attempts) * 30, 900)
            if self.db.is_sqlite:
                now = datetime.now(timezone.utc)
                next_run = (now + timedelta(seconds=delay_seconds)).strftime("%Y-%m-%d %H:%M:%S")
                await self.db.execute(
                    "UPDATE jobs SET status = 'PENDING', next_run_at = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND version_token = $3",
                    next_run, job_id, version_token,
                )
            else:
                await self.db.execute(
                    "UPDATE jobs SET status = 'PENDING', next_run_at = NOW() + ($1 || ' seconds')::interval, updated_at = NOW() WHERE id = $2 AND version_token = $3",
                    str(delay_seconds), job_id, version_token,
                )
            logger.warning("Job %s backoff scheduled in %ss (attempt %s/%s): %s", job_id, delay_seconds, attempts, max_attempts, error_msg)

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
