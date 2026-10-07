"""Repository implementing durable state operations, leased queues, outbox, and atomic transitions."""

import json
import logging
import hashlib
import uuid
from collections import defaultdict
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
        last_urgent_at_dt = to_utc_datetime(incident["last_urgent_at"]) if incident.get("last_urgent_at") is not None else None
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

    async def record_model_run(
        self,
        incident_id: str,
        revision: int,
        model_run: Dict[str, Any],
        commit_status: str = "PENDING",
    ) -> Optional[int]:
        """Record model run audit row in an independent transaction with commit_status."""
        m_run = dict(model_run)
        m_reason_codes = m_run.get("reason_codes", [])
        if isinstance(m_reason_codes, set):
            m_reason_codes = list(m_reason_codes)

        if self.db.is_sqlite:
            m_query = """
            INSERT INTO model_runs (
                incident_id, revision, model_id, server_reported_model,
                prompt_version, schema_version, rule_pack_version, catalog_version,
                action_map_version, input_hash, input_tokens, output_tokens,
                latency_ms, structured_output_mode, validation_result, reason_codes, commit_status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            """
            await self.db.execute(
                m_query,
                incident_id,
                revision,
                m_run.get("model_id", "qwen3.8-27b"),
                m_run.get("server_reported_model"),
                m_run.get("prompt_version", "1.0.0"),
                m_run.get("schema_version", "1.0.0"),
                m_run.get("rule_pack_version", "1.0.0"),
                m_run.get("catalog_version", "1.0.0"),
                m_run.get("action_map_version", "1.0.0"),
                m_run.get("input_hash", ""),
                m_run.get("input_tokens", 0),
                m_run.get("output_tokens", 0),
                m_run.get("latency_ms", 0),
                m_run.get("structured_output_mode", "json_schema"),
                m_run.get("validation_result", "VALID"),
                json.dumps(m_reason_codes),
                commit_status,
            )
            row = await self.db.fetch_one("SELECT last_insert_rowid() as id")
            return row["id"] if row else None
        else:
            m_query = """
            INSERT INTO model_runs (
                incident_id, revision, model_id, server_reported_model,
                prompt_version, schema_version, rule_pack_version, catalog_version,
                action_map_version, input_hash, input_tokens, output_tokens,
                latency_ms, structured_output_mode, validation_result, reason_codes, commit_status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            RETURNING id
            """
            row = await self.db.fetch_one(
                m_query,
                incident_id,
                revision,
                m_run.get("model_id", "qwen3.8-27b"),
                m_run.get("server_reported_model"),
                m_run.get("prompt_version", "1.0.0"),
                m_run.get("schema_version", "1.0.0"),
                m_run.get("rule_pack_version", "1.0.0"),
                m_run.get("catalog_version", "1.0.0"),
                m_run.get("action_map_version", "1.0.0"),
                m_run.get("input_hash", ""),
                m_run.get("input_tokens", 0),
                m_run.get("output_tokens", 0),
                m_run.get("latency_ms", 0),
                m_run.get("structured_output_mode", "json_schema"),
                m_run.get("validation_result", "VALID"),
                m_reason_codes,
                commit_status,
            )
            return row["id"] if row else None

    async def update_model_run_status(self, model_run_id: int, commit_status: str):
        """Update commit_status on an existing model_runs row."""
        if not model_run_id:
            return
        query = "UPDATE model_runs SET commit_status = $1 WHERE id = $2"
        await self.db.execute(query, commit_status, model_run_id)

    async def record_incident_transition(
        self,
        incident: Dict[str, Any],
        revision: Optional[Dict[str, Any]] = None,
        notification: Optional[Dict[str, Any]] = None,
        job: Optional[Dict[str, Any]] = None,
        model_run: Optional[Dict[str, Any]] = None,
        processed_event_ids: Optional[List[str]] = None,
        expected_revision: Optional[int] = None,
        fence_job_id: Optional[str] = None,
        fence_version_token: Optional[int] = None,
    ) -> int:
        """Atomic transaction updating incident, revision, outbox, job queue, and acknowledging processed events.
        
        Enforces optimistic revision concurrency and job leasing fences.
        Revision number is allocated inside transaction from freshly read current_revision.
        Model runs are recorded in an independent transaction with commit_status.
        """
        model_run_id = None
        if model_run:
            target_rev = (expected_revision + 1) if (expected_revision is not None and expected_revision > 0) else incident.get("current_revision", 1)
            try:
                model_run_id = await self.record_model_run(
                    incident_id=incident["id"],
                    revision=target_rev,
                    model_run=model_run,
                    commit_status="PENDING",
                )
            except Exception as mr_err:
                logger.warning("Failed to record pre-transition model_run: %s", mr_err)

        try:
            new_rev = await self._execute_incident_transition(
                incident=incident,
                revision=revision,
                notification=notification,
                job=job,
                processed_event_ids=processed_event_ids,
                expected_revision=expected_revision,
                fence_job_id=fence_job_id,
                fence_version_token=fence_version_token,
            )
        except RevisionConflict:
            if model_run_id:
                try:
                    await self.update_model_run_status(model_run_id, "CONFLICT")
                except Exception as update_err:
                    logger.warning("Failed to update model_run status to CONFLICT: %s", update_err)
            raise
        except Exception:
            if model_run_id:
                try:
                    await self.update_model_run_status(model_run_id, "FAILED")
                except Exception as update_err:
                    logger.warning("Failed to update model_run status to FAILED: %s", update_err)
            raise

        if model_run_id:
            try:
                await self.update_model_run_status(model_run_id, "COMMITTED")
            except Exception as update_err:
                logger.warning("Failed to update model_run status to COMMITTED: %s", update_err)

        return new_rev

    async def _execute_incident_transition(
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
                # Allocate a new revision only when a revision row is being written;
                # a counts-only update must not advance current_revision.
                new_rev = current_rev + 1 if revision is not None else current_rev
            else:
                if expected_revision is not None and expected_revision > 0:
                    raise RevisionConflict(
                        f"Incident {incident['id']} does not exist, but expected_revision was {expected_revision}"
                    )
                new_rev = 1

            first_seen_dt = to_utc_datetime(incident["first_seen"])
            last_seen_dt = to_utc_datetime(incident["last_seen"])
            last_urgent_at_dt = to_utc_datetime(incident["last_urgent_at"]) if incident.get("last_urgent_at") is not None else None
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
                n_type = notification["notification_type"]
                prio = 10 if "URGENT" in n_type else (20 if "INVESTIGATION" in n_type else 50)
                n_payload = json.dumps(notification["payload"], default=str)
                if self.db.is_sqlite:
                    notif_query = """
                    INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status, type_priority)
                    VALUES ($1, $2, $3, $4, 'PENDING', $5)
                    ON CONFLICT(incident_id, revision, notification_type) DO NOTHING
                    """
                else:
                    notif_query = """
                    INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status, type_priority)
                    VALUES ($1, $2, $3, $4::jsonb, 'PENDING', $5)
                    ON CONFLICT (incident_id, revision, notification_type) DO NOTHING
                    """
                await tx.execute(
                    notif_query,
                    incident["id"],
                    new_rev,
                    n_type,
                    n_payload,
                    prio,
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
        prio = 10 if "URGENT" in notif_type else (20 if "INVESTIGATION" in notif_type else 50)
        if self.db.is_sqlite:
            query = """
            INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status, type_priority)
            VALUES ($1, $2, $3, $4, 'PENDING', $5)
            ON CONFLICT(incident_id, revision, notification_type) DO NOTHING
            """
        else:
            query = """
            INSERT INTO notification_outbox (incident_id, revision, notification_type, payload_json, status, type_priority)
            VALUES ($1, $2, $3, $4::jsonb, 'PENDING', $5)
            ON CONFLICT (incident_id, revision, notification_type) DO NOTHING
            """
        await self.db.execute(query, incident_id, revision, notif_type, payload_str, prio)

    async def fetch_pending_notifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch pending notifications ordered strictly by priority (urgent first) and retry availability."""
        if self.db.is_sqlite:
            query = """
            SELECT * FROM notification_outbox
            WHERE status = 'PENDING' AND (retry_after_ts IS NULL OR retry_after_ts <= CURRENT_TIMESTAMP)
            ORDER BY type_priority ASC, id ASC
            LIMIT $1
            """
        else:
            query = """
            SELECT * FROM notification_outbox
            WHERE status = 'PENDING' AND (retry_after_ts IS NULL OR retry_after_ts <= NOW())
            ORDER BY type_priority ASC, id ASC
            LIMIT $1
            """
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

    async def mark_notification_failed(
        self,
        outbox_id: int,
        error_msg: str,
        retry_after_seconds: Optional[float] = None,
        dead_letter: bool = False,
    ):
        """Mark notification failure with exponential backoff or immediate dead-letter."""
        delay = max(1.0, float(retry_after_seconds or 30.0))
        if self.db.is_sqlite:
            if dead_letter:
                query = "UPDATE notification_outbox SET attempts = attempts + 1, last_error = $1, status = 'DEAD_LETTER' WHERE id = $2"
                await self.db.execute(query, error_msg[:500], outbox_id)
            else:
                query = """
                UPDATE notification_outbox
                SET attempts = attempts + 1, last_error = $1,
                    status = CASE WHEN attempts >= 10 THEN 'DEAD_LETTER' ELSE 'PENDING' END,
                    retry_after_ts = datetime(CURRENT_TIMESTAMP, '+' || $2 || ' seconds')
                WHERE id = $3
                """
                await self.db.execute(query, error_msg[:500], int(delay), outbox_id)
        else:
            if dead_letter:
                query = "UPDATE notification_outbox SET attempts = attempts + 1, last_error = $1, status = 'DEAD_LETTER' WHERE id = $2"
                await self.db.execute(query, error_msg[:500], outbox_id)
            else:
                query = """
                UPDATE notification_outbox
                SET attempts = attempts + 1, last_error = $1,
                    status = CASE WHEN attempts >= 10 THEN 'DEAD_LETTER' ELSE 'PENDING' END,
                    retry_after_ts = NOW() + ($2 || ' seconds')::interval
                WHERE id = $3
                """
                await self.db.execute(query, error_msg[:500], str(int(delay)), outbox_id)

    # --- Episode Persistence (B6) ---
    async def save_episodes(self, episodes: List[Dict[str, Any]]):
        """Persist or update episodes in the episodes table with enforcement counts and signatures."""
        if not episodes:
            return
        for ep in episodes:
            ep_id = ep.get("episode_id") or ep.get("id") or f"{ep.get('vdom', 'root')}:{ep.get('source_ip')}->{ep.get('target_ip')}"
            first_dt = ep.get("first_seen")
            last_dt = ep.get("last_seen")
            first_str = first_dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(first_dt, datetime) else str(first_dt)
            last_str = last_dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(last_dt, datetime) else str(last_dt)
            ev_ids = [str(x) for x in ep.get("evidence_ids", [])]
            s_ids = [int(x) for x in ep.get("session_ids", [])]
            enf_counts = ep.get("enforcement_counts", {})
            sigs = list(ep.get("signatures", []))

            if self.db.is_sqlite:
                query = """
                INSERT INTO episodes (
                    id, vdom, direction, source_ip, target_ip, service,
                    incident_id, status, first_seen, last_seen, last_event_ts_ns,
                    event_count, enforcement, enforcement_counts, signatures, evidence_ids, session_ids, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    last_event_ts_ns = excluded.last_event_ts_ns,
                    event_count = excluded.event_count,
                    enforcement = excluded.enforcement,
                    enforcement_counts = excluded.enforcement_counts,
                    signatures = excluded.signatures,
                    evidence_ids = excluded.evidence_ids,
                    session_ids = excluded.session_ids,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """
                await self.db.execute(
                    query,
                    ep_id,
                    ep.get("vdom", "root"),
                    ep.get("direction", "INBOUND"),
                    ep["source_ip"],
                    ep["target_ip"],
                    ep.get("service"),
                    ep["incident_id"],
                    ep.get("status", "OPEN"),
                    first_str,
                    last_str,
                    ep.get("last_event_ts_ns", 0),
                    ep.get("event_count", 1),
                    ep.get("enforcement", "UNKNOWN"),
                    json.dumps(enf_counts),
                    json.dumps(sigs),
                    json.dumps(ev_ids),
                    json.dumps(s_ids),
                )
            else:
                query = """
                INSERT INTO episodes (
                    id, vdom, direction, source_ip, target_ip, service,
                    incident_id, status, first_seen, last_seen, last_event_ts_ns,
                    event_count, enforcement, enforcement_counts, signatures, evidence_ids, session_ids, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15, $16, $17, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    last_event_ts_ns = EXCLUDED.last_event_ts_ns,
                    event_count = EXCLUDED.event_count,
                    enforcement = EXCLUDED.enforcement,
                    enforcement_counts = EXCLUDED.enforcement_counts,
                    signatures = EXCLUDED.signatures,
                    evidence_ids = EXCLUDED.evidence_ids,
                    session_ids = EXCLUDED.session_ids,
                    status = EXCLUDED.status,
                    updated_at = NOW()
                """
                await self.db.execute(
                    query,
                    ep_id,
                    ep.get("vdom", "root"),
                    ep.get("direction", "INBOUND"),
                    ep["source_ip"],
                    ep["target_ip"],
                    ep.get("service"),
                    ep["incident_id"],
                    ep.get("status", "OPEN"),
                    first_dt if isinstance(first_dt, datetime) else to_utc_datetime(first_dt),
                    last_dt if isinstance(last_dt, datetime) else to_utc_datetime(last_dt),
                    ep.get("last_event_ts_ns", 0),
                    ep.get("event_count", 1),
                    ep.get("enforcement", "UNKNOWN"),
                    json.dumps(enf_counts),
                    sigs,
                    ev_ids,
                    s_ids,
                )

    async def close_episodes(self, episode_ids: List[str]):
        """Mark specified episodes as CLOSED in the database."""
        if not episode_ids:
            return
        if self.db.is_sqlite:
            for eid in episode_ids:
                await self.db.execute(
                    "UPDATE episodes SET status = 'CLOSED', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                    eid,
                )
        else:
            await self.db.execute(
                "UPDATE episodes SET status = 'CLOSED', updated_at = NOW() WHERE id = ANY($1::varchar[])",
                episode_ids,
            )

    async def load_open_episodes(self, idle_timeout_seconds: int = 120) -> List[Dict[str, Any]]:
        """Fetch all currently open episodes within idle_timeout_seconds of the newest; closes older rows."""
        query = "SELECT * FROM episodes WHERE status = 'OPEN' ORDER BY last_seen DESC"
        rows = await self.db.fetch_all(query)
        if not rows:
            return []

        # Find newest last_seen
        newest_row = rows[0]
        newest_dt = newest_row.get("last_seen")
        newest_ts = newest_dt.timestamp() if isinstance(newest_dt, datetime) else to_utc_datetime(newest_dt).timestamp()

        stale_ids = []
        active_episodes = []

        for r in rows:
            d = dict(r)
            r_dt = d.get("last_seen")
            r_ts = r_dt.timestamp() if isinstance(r_dt, datetime) else to_utc_datetime(r_dt).timestamp()

            if (newest_ts - r_ts) > idle_timeout_seconds:
                stale_ids.append(d["id"])
            else:
                if self.db.is_sqlite:
                    if isinstance(d.get("evidence_ids"), str):
                        try:
                            d["evidence_ids"] = json.loads(d["evidence_ids"])
                        except Exception:
                            d["evidence_ids"] = []
                    if isinstance(d.get("session_ids"), str):
                        try:
                            d["session_ids"] = json.loads(d["session_ids"])
                        except Exception:
                            d["session_ids"] = []
                    if isinstance(d.get("enforcement_counts"), str):
                        try:
                            d["enforcement_counts"] = json.loads(d["enforcement_counts"])
                        except Exception:
                            d["enforcement_counts"] = {}
                    if isinstance(d.get("signatures"), str):
                        try:
                            d["signatures"] = json.loads(d["signatures"])
                        except Exception:
                            d["signatures"] = []
                else:
                    if isinstance(d.get("enforcement_counts"), str):
                        try:
                            d["enforcement_counts"] = json.loads(d["enforcement_counts"])
                        except Exception:
                            d["enforcement_counts"] = {}
                active_episodes.append(d)

        if stale_ids:
            logger.info("Closing %s stale open episodes older than idle_timeout (%s s)", len(stale_ids), idle_timeout_seconds)
            await self.close_episodes(stale_ids)

        return active_episodes

    async def get_digest_summary(self, since_dt: datetime) -> Dict[str, Any]:
        """Aggregate DIGEST incidents into summary counts across sources, targets, and rules."""
        since_val = since_dt.strftime("%Y-%m-%d %H:%M:%S") if self.db.is_sqlite else since_dt

        # Select incidents updated in window, excluding incidents with URGENT cards
        query = """
        SELECT i.id, i.source_ip, i.target_ip, i.event_count, i.deterministic_rule_ids,
               i.deterministic_severity, i.current_revision
        FROM incidents i
        WHERE i.updated_at >= $1
          AND (i.last_urgent_at IS NULL OR i.last_urgent_at < $1)
          AND i.id NOT IN (
              SELECT DISTINCT incident_id FROM notification_outbox
              WHERE notification_type = 'URGENT' AND created_at >= $1
          )
        """
        rows = await self.db.fetch_all(query, since_val)

        digest_rows = []
        for r in rows:
            inc_id = r["id"]
            rev_num = r.get("current_revision", 1)
            rev_row = await self.db.fetch_one(
                "SELECT assessment_json, rule_ids FROM incident_revisions WHERE incident_id = $1 AND revision = $2",
                inc_id,
                rev_num,
            )
            routing = None
            if rev_row:
                aj = rev_row.get("assessment_json")
                if isinstance(aj, str):
                    try:
                        aj = json.loads(aj)
                    except Exception:
                        aj = {}
                if isinstance(aj, dict):
                    routing = aj.get("routing")

            if not routing:
                rules_raw = r.get("deterministic_rule_ids")
                if isinstance(rules_raw, str):
                    try:
                        rules_list = json.loads(rules_raw)
                    except Exception:
                        rules_list = [rules_raw]
                else:
                    rules_list = rules_raw or []

                routing = "DIGEST"
                for r_id in rules_list:
                    if r_id in ("RULE_NONBLOCKED_EXPLOIT_ATTEMPT", "RULE_ANTIVIRUS_DETECTION"):
                        routing = "URGENT_ALERT_AND_INVESTIGATE"
                        break
                    elif r_id in ("RULE_UNKNOWN_ACTION_MAPPING", "RULE_HIGH_PARSER_ERROR_RATE", "RULE_LOG_SILENCE", "RULE_COVERAGE_GAP", "RULE_PROCESSING_BACKLOG"):
                        routing = "RETAIN_WITH_VISIBILITY_GAP"

            if routing == "DIGEST" or (routing and routing.startswith("RETAIN_")):
                digest_rows.append(r)

        counts_by_source: Dict[str, int] = defaultdict(int)
        counts_by_target: Dict[str, int] = defaultdict(int)
        counts_by_rule: Dict[str, int] = defaultdict(int)
        total_events = 0

        for r in digest_rows:
            src = r["source_ip"]
            dst = r["target_ip"]
            ev_cnt = r.get("event_count", 1)
            total_events += ev_cnt
            counts_by_source[src] += ev_cnt
            counts_by_target[dst] += ev_cnt
            rules_raw = r.get("deterministic_rule_ids")
            if isinstance(rules_raw, str):
                try:
                    rules_list = json.loads(rules_raw)
                except Exception:
                    rules_list = [rules_raw]
            else:
                rules_list = rules_raw or []
            for r_id in rules_list:
                counts_by_rule[r_id] += 1

        return {
            "since": since_dt,
            "total_incidents": len(digest_rows),
            "total_events": total_events,
            "counts_by_source": dict(counts_by_source),
            "counts_by_target": dict(counts_by_target),
            "counts_by_rule": dict(counts_by_rule),
        }
