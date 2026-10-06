"""Database connection manager supporting async PostgreSQL (production) and SQLite (tests)."""

import os
import json
import logging
from typing import Optional, Any, List, Dict
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
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    current_revision INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    severity TEXT NOT NULL,
    enforcement TEXT NOT NULL,
    exploitation_assessment TEXT NOT NULL DEFAULT 'INSUFFICIENT_EVIDENCE',
    source_ip TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    target_app TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    summary TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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

CREATE TABLE IF NOT EXISTS notification_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    notification_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    sent_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(incident_id, revision, notification_type)
);
"""


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
            await self._sqlite_conn.commit()
            logger.info("Initialized SQLite database: %s", db_path)
        else:
            self._pg_pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10)
            logger.info("Connected to PostgreSQL pool: %s", self.dsn.split("@")[-1])
            await self.apply_postgres_migrations()

    async def apply_postgres_migrations(self):
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                ddl = f.read()
            async with self._pg_pool.acquire() as conn:
                await conn.execute(ddl)
            logger.info("Applied PostgreSQL DDL schema successfully.")

    async def close(self):
        if self._pg_pool:
            await self._pg_pool.close()
        if self._sqlite_conn:
            await self._sqlite_conn.close()

    async def execute(self, query: str, *args) -> None:
        if self.is_sqlite:
            # Replace $1, $2 placeholders with ?
            q = query
            for i in range(len(args), 0, -1):
                q = q.replace(f"${i}", "?")
            await self._sqlite_conn.execute(q, args)
            await self._sqlite_conn.commit()
        else:
            async with self._pg_pool.acquire() as conn:
                await conn.execute(query, *args)

    async def execute_many(self, query: str, args_list: list) -> None:
        if not args_list:
            return
        if self.is_sqlite:
            import re
            q = query
            placeholders = re.findall(r"\$(\d+)", query)
            max_idx = max(int(p) for p in placeholders) if placeholders else 0
            for i in range(max_idx, 0, -1):
                q = q.replace(f"${i}", "?")
            await self._sqlite_conn.executemany(q, args_list)
            await self._sqlite_conn.commit()
        else:
            async with self._pg_pool.acquire() as conn:
                await conn.executemany(query, args_list)

    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        if self.is_sqlite:
            q = query
            for i in range(len(args), 0, -1):
                q = q.replace(f"${i}", "?")
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
            q = query
            for i in range(len(args), 0, -1):
                q = q.replace(f"${i}", "?")
            cursor = await self._sqlite_conn.execute(q, args)
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
        else:
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *args)
                return [dict(r) for r in rows]
