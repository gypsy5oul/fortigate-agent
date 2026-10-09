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

---

## 5. Investigator Modes (ADK agent investigator)

`INVESTIGATOR_MODE` (`legacy` default, `shadow`, `adk`) selects who writes the investigation revision; see README section 5 and `docs/adr/005-adk-investigator.md`. Detection, URGENT cards, the outbox and checkpoints do not depend on it.

### 5.1 Enabling shadow mode
1. vLLM must serve the model with `--enable-auto-tool-choice --tool-call-parser hermes` (Qwen tool calling). Without it the specialists cannot call tools and shadow runs end `ERROR` or `SCHEMA_INVALID`; the legacy path is unaffected.
2. Set `INVESTIGATOR_MODE=shadow` in `.env` (optionally `AGENT_MAX_LLM_CALLS`, default 8, and `AGENT_TIMEOUT_SECONDS`, default 120) and restart: `docker compose up -d app`.
3. Check the start-up log for `Investigator mode: shadow` and that migration `006_agent_audit` is applied: `SELECT version FROM schema_migrations;`. The error `ADK investigator unavailable; shadow runs are disabled` means the agent could not be set up; the service then runs legacy-only (in `adk` mode the same failure stops the service).

Shadow runs happen in the investigation loop after the legacy revision is committed, so each investigated revision takes up to `AGENT_TIMEOUT_SECONDS` longer to clear from the queue (`forti_jobs_oldest_pending_seconds`). They never produce a revision, a card or an outbox row, and their failure never fails the job.

### 5.2 Reading shadow results
The comparison harness reads the audit tables (read-only) and prints agreement with the legacy assessment, outcomes and the validator hard-reject rate, p50/p95 latency, tokens and model calls per run, tool calls and refusals, and the plan C2.5 criteria with what was measured:
```bash
docker compose exec -T app python scripts/shadow_report.py --hours 24            # Markdown
docker compose exec -T app python scripts/shadow_report.py --since 2026-10-10T00:00:00Z --json
```
`--check lab` (or `--check golden`) exits 1 when that criteria set is not met. The same numbers as SQL:
```sql
-- Outcomes of the last day
SELECT mode, outcome, COUNT(*), PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_ms
FROM agent_runs WHERE created_at > NOW() - INTERVAL '1 day' GROUP BY 1, 2 ORDER BY 1, 2;

-- Agreement with the legacy assessment
SELECT COUNT(*) AS runs,
       AVG(severity_equal::int) AS severity_agreement,
       AVG(action_set_equal::int) AS action_set_agreement,
       AVG(exploitation_equal::int) AS exploitation_agreement,
       AVG((assessment_source = 'MODEL_REJECTED_FALLBACK')::int) AS fallback_rate
FROM shadow_assessments WHERE created_at > NOW() - INTERVAL '1 day';

-- Why the agent said what it said: the ordered trail of one run
SELECT seq, agent_name, kind, tool_name, args_json, refused, latency_ms, tokens
FROM agent_events WHERE run_id = <agent_runs.id> ORDER BY seq;
```
Metrics: `forti_agent_runs_total{mode,outcome}`, `forti_agent_llm_calls_total{agent}`, `forti_agent_tool_calls_total{tool,outcome}`, `forti_agent_run_duration_seconds`, `forti_agent_tokens_total{direction}`, `forti_agent_budget_exhausted_total` (incremented after each run; Grafana row "ADK Agent Investigator" of `dashboards/agent_operations.json`), and the last-24-hour gauges `forti_agent_runs_24h{mode,outcome}`, `forti_agent_shadow_comparisons_24h` and `forti_agent_shadow_agreeing_24h{field}`, which the operational metrics updater sets from the audit tables every 5 s in every mode (row "ADK Shadow Comparison"). Alerts: `FortiGateAgentHardRejectRate` (more than 5% of the last 24 h's runs hard-rejected) and `FortiGateAgentBudgetExhaustion` (more than 2% stopped by the budget), both only once there are at least 20 runs in the window. Repeated `lookup_asset` refusals mean the agent is guessing IPs; review the instructions before anything else.

### 5.3 Run outcomes
| `agent_runs.outcome` | Meaning | What to check |
|---|---|---|
| `VALID` | the writer's assessment passed the validator | nothing |
| `REJECTED` | the validator hard-rejected it (identity, forbidden claim, ungrounded evidence id); fallback used | `reason_codes`, then the run's `agent_events` |
| `BUDGET_EXHAUSTED` | `AGENT_MAX_LLM_CALLS` model calls used before the writer finished | the last `agent_events` row (refused `llm`) shows which agent asked for one more; raise the budget only with evidence |
| `TIMEOUT` | the run exceeded `AGENT_TIMEOUT_SECONDS` | vLLM latency (`latency_ms` per `llm` event) |
| `SCHEMA_INVALID` | the writer produced no object or an invalid one | vLLM guided decoding for `json_schema`; the writer's request in `adk.events` |
| `ERROR` | anything else, e.g. the endpoint was unreachable | `reason_codes` (exception class) and the service log |

### 5.4 ADK session store
ADK keeps one session per investigated revision (`<incident_id>:<revision>`, app `forti-investigator`, user `system`) in schema `adk` of the service database (tables created by ADK on first use). Its state holds the incident identity and the redacted packet; its events, every model and tool turn. Nothing prunes it automatically yet. To keep 30 days (events cascade):
```sql
DELETE FROM adk.sessions WHERE app_name = 'forti-investigator' AND update_time < NOW() - INTERVAL '30 days';
```
`agent_runs` and `agent_events` are the audit record and are not touched by this statement.

### 5.5 Promotion evidence (plan C2.5)
Phase C.3 promotes `adk` mode only when the C2.5 criteria hold on the golden set and on at least 50 real shadow runs. The offline part runs in CI (`tests/agent/test_golden_set.py`, `tests/e2e/test_service_e2e.py::test_e2e_offline_shadow_run_over_the_golden_scenarios`). In the lab:

1. Collect: run in shadow mode (5.1) until at least 50 incidents have been investigated, then
   ```bash
   docker compose exec -T app python scripts/shadow_report.py --since <shadow start, ISO 8601> --check lab
   ```
   exit status 0 means: at least 50 shadow runs, hard-reject rate under 5%, p95 latency under 90 s, budget exhaustion under 2%, no `lookup_asset` refusal.
2. Evaluate the golden set against the lab model from a checkout with `requirements-dev.txt` plus `google-adk[eval]==2.11.0` (README section 6):
   ```bash
   RUN_LAB_EVALS=1 LLM_BASE_URL=http://<vllm-host>:8000/v1 LLM_MODEL=<served-model> \
     pytest -m lab -v tests/agent/test_golden_eval_lab.py
   ```
3. Add two reviewed real incidents to the golden set: `docker compose exec -T app python scripts/export_golden_incident.py <incident_id> <revision> > evals/lab/<name>.test.json`, review the file (`evals/lab/README.md`), commit it, and repeat step 2.

Evaluation reads tool data from the evalset only (no Loki, no database) and writes nothing.

### 5.6 Rolling back and `adk` mode
Rollback is `INVESTIGATOR_MODE=legacy` and a restart; legacy mode does not load ADK at all, and the audit tables stay as a record. `INVESTIGATOR_MODE=adk` makes the agent's validated assessment (or the deterministic fallback) the investigation revision and card, committed through the same CAS and job fence, with a `model_runs` row (`structured_output_mode = adk_json_schema`). It is promoted to default only in Phase C.3, after the C.2 shadow criteria are met; do not enable it in production before that.
