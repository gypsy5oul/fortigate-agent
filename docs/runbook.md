# FortiGate Agent Operational Runbook

This operational runbook documents deployment procedures, failure modes, data maintenance, backup/restore steps, and recovery policies for the FortiGate Firewall Intelligence Service.

---

## 1. System Overview & Architecture

The service runs as a containerized Python service alongside a dedicated PostgreSQL 16 database. It ingests FortiOS security syslog events from Grafana Loki, normalizes and correlates them into persistent attack episodes, evaluates deterministic security rules, selectively requests one bounded structured investigation per incident revision from the local Qwen model served by vLLM (`LLM_MODEL`, default `qwen3.8-27b`), and dispatches rate-limited Cards v2 alerts to Google Chat via an outbox worker.

---

## 2. Backup and Restore Procedures

### 2.1 Database Backup
Perform regular PostgreSQL physical or logical backups using `pg_dump`:

```bash
# Logical backup of schema and data
docker exec -t forti-intel-postgres pg_dump \
    -U forti_intel \
    -d forti_intelligence \
    --format=custom \
    --file=/var/lib/postgresql/data/backup_forti_$(date +%Y%m%d_%H%M%S).dump
```

Ensure the output dump file is archived to off-site backup storage.

### 2.2 Database Restore
To restore into a clean PostgreSQL container:

```bash
# 1. Stop the application container to avoid concurrent writes
docker compose stop app

# 2. Drop existing database connections and recreate
docker exec -i forti-intel-postgres psql -U forti_intel -d postgres -c "DROP DATABASE IF EXISTS forti_intelligence;"
docker exec -i forti-intel-postgres psql -U forti_intel -d postgres -c "CREATE DATABASE forti_intelligence OWNER forti_intel;"

# 3. Restore dump
docker exec -i forti-intel-postgres pg_restore \
    -U forti_intel \
    -d forti_intelligence \
    /var/lib/postgresql/data/<backup_filename>.dump

# 4. Start the application container
docker compose start app
```

---

## 3. Checkpoint Management & Reprocessing

### 3.1 Checkpoint Semantics
Log ingestion cursors are durably stored in the `query_checkpoints` table keyed by profile stream keys (`<stream_selector>#<profile>@v<version>`):
- **Monotonic Forward Progress**: The poller queries Loki in finite time slices (`LOKI_SLICE_SECONDS`, default 30 s) and only advances `last_queried_ts_ns` upon successful persistence of events in PostgreSQL.
- **Bootstrapping**: If no checkpoint exists, the service bootstraps looking back 60 seconds before current time (or seeds from an existing bare selector checkpoint).

### 3.2 Implications After Database Restore
Restoring a backup from $T_{\text{backup}}$ will roll back the checkpoint cursor in `query_checkpoints` to $T_{\text{backup}}$:
- The poller will resume querying Loki starting at $T_{\text{backup}}$, re-ingesting events that arrived between $T_{\text{backup}}$ and the current time.
- **Idempotency Guarantee**: All event inserts into `selected_events` use deterministic primary keys (`id` = SHA256 fingerprint). Re-ingested events trigger `ON CONFLICT (id) DO NOTHING` without creating duplicate records or inflating counts.
- **Episode Linking**: Episodes with the same campaign tuple within 30 minutes are updated rather than duplicated.

### 3.3 Manual Reprocessing Procedure
If an operator needs to deliberately replay or reprocess logs from a specific historical timestamp:

```sql
-- Rewind the checkpoint of the live stream profile to 2 hours ago (nanoseconds).
-- The key is <LOKI_SELECTOR>#<LOKI_QUERY_PROFILE>@v1; check it first with
--   SELECT stream_name FROM query_checkpoints;
UPDATE query_checkpoints
SET last_queried_ts_ns = EXTRACT(EPOCH FROM (NOW() - INTERVAL '2 hours'))::BIGINT * 1000000000
WHERE stream_name = '{service_name="forticlient"}#security_events@v1';
```

Restart the agent to begin historical ingestion:
```bash
docker compose restart app
```

---

## 4. Degraded Modes & Recovery

### 4.1 Loki Outage or Poller Lag
- **Symptom**: Metric `forti_loki_last_success_age_seconds` exceeds 3× `LOKI_POLL_INTERVAL_SECONDS`. `/health/ready` reports HTTP 503 with `{"status": "not_ready", "error": "Poller lag exceeded 3x interval"}`.
- **Behavior**: The poller logs the error and retries on the next poll interval (`LOKI_POLL_INTERVAL_SECONDS`); there is no additional backoff. The ingestion cursor remains at the last committed nanosecond; no events are skipped.
- **Action**: Check Loki read gateway availability and network connectivity (`ping loki.internal`). Once Loki is reachable, the poller automatically drains the lag in bounded slices.

### 4.2 Local LLM Gateway Outage
- **Symptom**: Metric `forti_model_last_success_age_seconds` grows; `forti_model_failures_total` and `forti_model_consecutive_failures` increase.
- **Behavior**: The service enters **Degraded Mode** (advisory model failure).
  - Deterministic rules and severity floors continue to function without interruption.
  - Urgent alerts are dispatched with deterministic assessment.
  - Investigation jobs trigger the deterministic fallback validator, recording `MODEL_REJECTED_FALLBACK` in `incident_revisions` and auditing the failure in `model_runs`.
  - After 3 consecutive failures `/health/ready` reports HTTP 200 with `{"status": "degraded", "database": "connected", "note": "Model inference degraded; deterministic rules active"}` (does not trigger container restarts), and the `FortiGateModelDegraded` alert fires on `forti_model_consecutive_failures >= 3`.
- **Action**: Verify vLLM service health and GPU memory utilization.

### 4.3 Google Chat Rate Limiting & Webhook Errors
- **Symptom**: `forti_outbox_failures_total` increments. Warnings logged by `outbox_worker`.
- **Behavior**:
  - **HTTP 429 (Rate Limit)**: Honors the `Retry-After` header (integer seconds or HTTP-date); without the header the row is retried after a fixed 3 s. Outbox rows remain `PENDING`.
  - **HTTP 408, 5xx and network errors**: Retried with exponential backoff and jitter (`min(900, 30 x 2^attempts)` plus 0.5 to 3 s). A row is dead-lettered on its 10th failed attempt.
  - **Permanent 4xx Errors (400, 401, 403, 404)**: Immediately transitioned to `DEAD_LETTER` to prevent blocking the outbox queue.
  - **Priority Ordering**: URGENT (priority 10) alerts are dispatched before INVESTIGATION_UPDATE (priority 20) and DIGEST (priority 50).
- **Action**:
  - Inspect dead-lettered alerts: `SELECT * FROM notification_outbox WHERE status = 'DEAD_LETTER';`.
  - Validate webhook key and space permissions.
