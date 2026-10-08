"""Database connection manager supporting async PostgreSQL (production) and SQLite (tests)."""

import os
import re
import json
import logging
from contextlib import asynccontextmanager
from typing import Optional, Any, List, Dict, Tuple
import asyncpg
import aiosqlite

logger = logging.getLogger(__name__)


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS query_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_name TEXT NOT NULL UNIQUE,
    last_queried_ts_ns INTEGER NOT NULL,
    last_successful_run TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS coverage_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_ts_ns INTEGER NOT NULL,
    end_ts_ns INTEGER NOT NULL,
    stream_name TEXT NOT NULL,
    reason TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS selected_events (
    id TEXT PRIMARY KEY,
    loki_ts_ns INTEGER NOT NULL,
    eventtime_ns INTEGER,
    devid TEXT,
    vd TEXT DEFAULT 'root',
    direction TEXT DEFAULT 'UNKNOWN',
    srcintfrole TEXT,
    dstintfrole TEXT,
    logid TEXT,
    log_type TEXT NOT NULL,
    subtype TEXT,
    action_raw TEXT,
    action_normalized TEXT NOT NULL,
    srcip TEXT NOT NULL,
    srcport INTEGER,
    dstip TEXT NOT NULL,
    dstport INTEGER,
    proto INTEGER,
    service TEXT,
    policyid INTEGER,
    sessionid INTEGER,
    signature TEXT,
    url TEXT,
    http_method TEXT,
    severity_raw TEXT,
    raw_message TEXT NOT NULL,
    processing_status TEXT NOT NULL DEFAULT 'PENDING',
    processed_at TIMESTAMP,
    utmaction TEXT,
    signature_truncated INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_pending ON selected_events(processing_status, loki_ts_ns);
CREATE INDEX IF NOT EXISTS idx_events_srcip_ts ON selected_events(srcip, created_at);
CREATE INDEX IF NOT EXISTS idx_events_dstip_ts ON selected_events(dstip, created_at);
CREATE INDEX IF NOT EXISTS idx_events_loki_ts ON selected_events(loki_ts_ns);

CREATE TABLE IF NOT EXISTS rejected_events (
    id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    current_revision INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    severity TEXT NOT NULL,
    enforcement TEXT NOT NULL,
    exploitation_assessment TEXT NOT NULL DEFAULT 'INSUFFICIENT_EVIDENCE',
    vd TEXT DEFAULT 'root',
    direction TEXT DEFAULT 'INBOUND',
    source_ip TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    target_port INTEGER,
    target_service TEXT,
    target_app TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    summary TEXT,
    deterministic_severity TEXT,
    deterministic_enforcement TEXT,
    deterministic_rule_ids TEXT DEFAULT '[]',
    last_urgent_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incidents_status_updated ON incidents(status, updated_at);

CREATE TABLE IF NOT EXISTS incident_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    rule_ids TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL,
    enforcement TEXT NOT NULL,
    assessment_json TEXT,
    model_name TEXT,
    reasoning_summary TEXT,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    assessment_source TEXT DEFAULT 'DETERMINISTIC',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(incident_id, revision)
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 10,
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    lease_owner TEXT,
    lease_expires_at TIMESTAMP,
    version_token INTEGER NOT NULL DEFAULT 1,
    next_run_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs(status, next_run_at, priority);

CREATE TABLE IF NOT EXISTS notification_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    notification_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    type_priority INTEGER DEFAULT 50,
    retry_after_ts TIMESTAMP,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    sent_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(incident_id, revision, notification_type)
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending ON notification_outbox(status, created_at);

CREATE TABLE IF NOT EXISTS model_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    model_id TEXT NOT NULL,
    server_reported_model TEXT,
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    rule_pack_version TEXT NOT NULL,
    catalog_version TEXT NOT NULL,
    action_map_version TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    structured_output_mode TEXT NOT NULL DEFAULT 'json_schema',
    validation_result TEXT NOT NULL,
    reason_codes TEXT DEFAULT '[]',
    commit_status TEXT NOT NULL DEFAULT 'COMMITTED',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_model_runs_inc_rev ON model_runs(incident_id, revision);

CREATE TABLE IF NOT EXISTS episodes (
    id TEXT PRIMARY KEY,
    vdom TEXT NOT NULL DEFAULT 'root',
    direction TEXT NOT NULL DEFAULT 'UNKNOWN',
    source_ip TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    service TEXT,
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    last_event_ts_ns INTEGER NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    enforcement TEXT NOT NULL,
    enforcement_counts TEXT DEFAULT '{}',
    signatures TEXT DEFAULT '[]',
    utm_subtypes TEXT DEFAULT '[]',
    evidence_ids TEXT DEFAULT '[]',
    session_ids TEXT DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_episodes_open ON episodes(status, vdom, direction, source_ip, target_ip);
"""


def _to_sqlite_query(query: str) -> str:
    """Translate PostgreSQL $1, $2 parameter placeholders and syntax for SQLite."""
    # Replace $n with ?
    q = re.sub(r"\$\d+", "?", query)
    # Remove ::jsonb or ::interval casts
    q = re.sub(r"::jsonb\b", "", q)
    q = re.sub(r"::interval\b", "", q)
    return q


class SQLiteTransaction:
    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def execute(self, query: str, *args) -> Any:
        q = _to_sqlite_query(query)
        return await self.conn.execute(q, args)

    async def execute_many(self, query: str, args_list: list) -> None:
        if not args_list:
            return
        q = _to_sqlite_query(query)
        await self.conn.executemany(q, args_list)

    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        q = _to_sqlite_query(query)
        cursor = await self.conn.execute(q, args)
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        q = _to_sqlite_query(query)
        cursor = await self.conn.execute(q, args)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def fetch(self, query: str, *args) -> List[Dict[str, Any]]:
        return await self.fetch_all(query, *args)


class PostgresTransaction:
    def __init__(self, conn: asyncpg.Connection):
        self.conn = conn

    async def execute(self, query: str, *args) -> Any:
        return await self.conn.execute(query, *args)

    async def execute_many(self, query: str, args_list: list) -> None:
        if not args_list:
            return
        await self.conn.executemany(query, args_list)

    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        row = await self.conn.fetchrow(query, *args)
        return dict(row) if row is not None else None

    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        rows = await self.conn.fetch(query, *args)
        return [dict(r) for r in rows]

    async def fetch(self, query: str, *args) -> list:
        return await self.conn.fetch(query, *args)


class Database:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.is_sqlite = dsn.startswith("sqlite")
        self._pg_pool: Optional[asyncpg.Pool] = None
        self._sqlite_conn: Optional[aiosqlite.Connection] = None

    async def connect(self):
        if self.is_sqlite:
            db_path = self.dsn.replace("sqlite:///", "").replace("sqlite://", "")
            if not db_path:
                db_path = ":memory:"
            self._sqlite_conn = await aiosqlite.connect(db_path)
            self._sqlite_conn.row_factory = aiosqlite.Row
            await self._sqlite_conn.executescript(SQLITE_SCHEMA)
            # Dev-only SQLite files created before migration 005 lack this column.
            try:
                await self._sqlite_conn.execute("ALTER TABLE episodes ADD COLUMN utm_subtypes TEXT DEFAULT '[]'")
                await self._sqlite_conn.commit()
            except Exception:
                pass
            await self._sqlite_conn.commit()
            logger.info("Initialized SQLite database: %s", db_path)
        else:
            self._pg_pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10)
            logger.info("Connected to PostgreSQL pool: %s", self.dsn.split("@")[-1])
            await self.apply_postgres_migrations()

    async def apply_postgres_migrations(self):
        """Apply ordered migrations tracked by schema_migrations table."""
        async with self._pg_pool.acquire() as conn:
            # 1. Ensure schema_migrations table exists
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(64) PRIMARY KEY,
                applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
            );
            """)

            rows = await conn.fetch("SELECT version FROM schema_migrations")
            applied_versions = {r["version"] for r in rows}

            migrations_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "migrations"))
            if not os.path.exists(migrations_dir):
                logger.error("Database migrations directory not found at %s", migrations_dir)
                raise RuntimeError(f"migrations directory not found: {migrations_dir}")

            sql_files = sorted([f for f in os.listdir(migrations_dir) if f.endswith(".sql")])
            for fname in sql_files:
                version = os.path.splitext(fname)[0]
                if version not in applied_versions:
                    file_path = os.path.join(migrations_dir, fname)
                    with open(file_path, "r", encoding="utf-8") as f:
                        sql = f.read()
                    async with conn.transaction():
                        await conn.execute(sql)
                        await conn.execute(
                            "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, NOW())",
                            version,
                        )
                    logger.info("Applied PostgreSQL migration: %s", version)

    async def close(self):
        if self._pg_pool:
            await self._pg_pool.close()
        if self._sqlite_conn:
            await self._sqlite_conn.close()

    @asynccontextmanager
    async def transaction(self):
        """Context manager providing an atomic database transaction."""
        if self.is_sqlite:
            await self._sqlite_conn.execute("BEGIN")
            tx = SQLiteTransaction(self._sqlite_conn)
            try:
                yield tx
                await self._sqlite_conn.commit()
            except Exception:
                await self._sqlite_conn.rollback()
                raise
        else:
            async with self._pg_pool.acquire() as conn:
                async with conn.transaction():
                    yield PostgresTransaction(conn)

    async def execute(self, query: str, *args) -> None:
        if self.is_sqlite:
            q = _to_sqlite_query(query)
            await self._sqlite_conn.execute(q, args)
            await self._sqlite_conn.commit()
        else:
            async with self._pg_pool.acquire() as conn:
                await conn.execute(query, *args)

    async def execute_many(self, query: str, args_list: list) -> None:
        if not args_list:
            return
        if self.is_sqlite:
            q = _to_sqlite_query(query)
            await self._sqlite_conn.executemany(q, args_list)
            await self._sqlite_conn.commit()
        else:
            async with self._pg_pool.acquire() as conn:
                await conn.executemany(query, args_list)

    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        if self.is_sqlite:
            q = _to_sqlite_query(query)
            cursor = await self._sqlite_conn.execute(q, args)
            row = await cursor.fetchone()
            if row is None:
                return None
            return dict(row)
        else:
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(query, *args)
                if row is None:
                    return None
                return dict(row)

    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        if self.is_sqlite:
            q = _to_sqlite_query(query)
            cursor = await self._sqlite_conn.execute(q, args)
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
        else:
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *args)
                return [dict(r) for r in rows]
