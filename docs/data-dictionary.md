# FortiGate Agent Data Dictionary

This document details the relational data schema, domain enumerations, and telemetry lifecycle maintained by the FortiGate Firewall Intelligence Service within PostgreSQL 16.

---

## 1. Database Schema

### 1.1 `selected_events`
Stores security-relevant events extracted from FortiGate syslog via Loki. Routine forward accepted traffic (`action="accept"`, `action="close"`) is explicitly dropped at ingest and is NOT mirrored here.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(64)` | No | - | Deterministic SHA256 hex digest of the normalized event tuple |
| `loki_ts_ns` | `BIGINT` | No | - | Nanosecond timestamp assigned by Loki at stream ingestion |
| `eventtime_ns` | `BIGINT` | Yes | - | High-precision FortiOS event timestamp if present in log line |
| `devid` | `TEXT` | Yes | - | FortiGate device serial / identifier |
| `vd` | `TEXT` | Yes | `'root'` | FortiOS Virtual Domain partition |
| `direction` | `VARCHAR(16)` | Yes | `'UNKNOWN'` | Inferred traffic flow direction (`INBOUND`, `OUTBOUND`, `LATERAL`, `EXTERNAL`, `UNKNOWN`) |
| `srcintfrole` | `TEXT` | Yes | - | Source interface role (e.g. `wan`, `lan`, `dmz`) |
| `dstintfrole` | `TEXT` | Yes | - | Destination interface role (e.g. `wan`, `lan`, `dmz`) |
| `logid` | `TEXT` | Yes | - | FortiOS 10-digit log message ID |
| `log_type` | `TEXT` | No | - | FortiOS primary log category (`utm`, `traffic`, `event`) |
| `subtype` | `TEXT` | Yes | - | FortiOS subsystem subtype (`ips`, `virus`, `waf`, `ssl`, `forward`, `system`) |
| `action_raw` | `TEXT` | Yes | - | Exact raw `action` string reported in FortiOS log |
| `action_normalized` | `VARCHAR(32)` | No | - | Normalized enforcement category (`BLOCKED`, `ALLOWED_OR_DETECTED`, `UNKNOWN`) |
| `utmaction` | `TEXT` | Yes | - | UTM action reported by security profile |
| `srcip` | `VARCHAR(64)` | No | - | Source IP address (IPv4 or IPv6) |
| `srcport` | `INT` | Yes | - | Source Layer 4 port number |
| `dstip` | `VARCHAR(64)` | Yes | - | Destination IP address (nullable for pure system/auth events) |
| `dstport` | `INT` | Yes | - | Destination Layer 4 port number |
| `proto` | `INT` | Yes | - | IP protocol number (e.g. 6 = TCP, 17 = UDP, 1 = ICMP) |
| `service` | `TEXT` | Yes | - | Layer 7 service name identifier (e.g. `HTTPS`, `DNS`, `SSH`) |
| `policyid` | `INT` | Yes | - | Firewall policy rule ID |
| `sessionid` | `BIGINT` | Yes | - | FortiOS firewall session identifier |
| `signature` | `TEXT` | Yes | - | Threat signature name, attack identifier, or virus name |
| `signature_truncated` | `BOOLEAN` | Yes | `FALSE` | Flag indicating if signature exceeded 256 characters and was truncated |
| `url` | `TEXT` | Yes | - | Target URL path (cleaned of parameters) |
| `http_method` | `VARCHAR(16)` | Yes | - | Sanitized and length-capped HTTP request method |
| `severity_raw` | `TEXT` | Yes | - | Raw severity string reported in syslog line |
| `raw_message` | `TEXT` | No | - | Untrusted original log message payload |
| `processing_status` | `VARCHAR(16)` | No | `'PENDING'` | Ingest state (`PENDING`, `PROCESSED`) |
| `processed_at` | `TIMESTAMPTZ` | Yes | - | Timestamp when normalizer/correlator processed event |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Database record insertion timestamp |

---

### 1.2 `query_checkpoints`
Maintains monotonic log ingestion positions per query profile and Loki stream selector.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Primary key surrogate |
| `stream_name` | `VARCHAR(256)` | No | - | Compound stream profile tag (`<selector>#<profile>@v<version>`); UNIQUE, the upsert key |
| `last_queried_ts_ns` | `BIGINT` | No | - | Monotonically advancing upper boundary nanosecond timestamp from Loki |
| `last_successful_run` | `TIMESTAMPTZ` | No | `NOW()` | Timestamp of last successful polling cycle |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Timestamp when the checkpoint was durably advanced |

---

### 1.3 `coverage_gaps`
Tracks unpolled or skipped Loki timestamp intervals resulting from network partitions or errors.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Primary key surrogate |
| `start_ts_ns` | `BIGINT` | No | - | Gap start timestamp in nanoseconds |
| `end_ts_ns` | `BIGINT` | No | - | Gap end timestamp in nanoseconds |
| `stream_name` | `VARCHAR(128)` | No | - | Loki stream identifier |
| `reason` | `TEXT` | No | - | Reason gap occurred (e.g. timeout, backoff abort) |
| `resolved` | `BOOLEAN` | No | `FALSE` | Reserved for a future backfill; nothing sets it today |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Gap creation timestamp |

---

### 1.4 `rejected_events`
Stores unparseable or constraint-violating log lines quarantined during normalization.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(64)` | No | - | Primary key digest |
| `reason` | `TEXT` | No | - | Failure explanation (e.g. invalid syntax, missing required fields) |
| `raw_sha256` | `VARCHAR(64)` | No | - | SHA256 hex digest of unparseable raw log payload |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Quarantine timestamp |

---

### 1.5 `episodes`
Tracks active and closed attack episodes correlated over 30-minute campaign windows.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(128)` | No | - | Primary key: SHA256 hex digest prefix (`EP-<hash>`) of `vdom\|direction\|src\|dst\|start` |
| `vdom` | `VARCHAR(64)` | No | `'root'` | FortiOS Virtual Domain partition |
| `direction` | `VARCHAR(16)` | No | `'UNKNOWN'` | Traffic direction (`INBOUND`, `OUTBOUND`, `LATERAL`, `EXTERNAL`, `UNKNOWN`) |
| `source_ip` | `VARCHAR(64)` | No | - | Adversary or originating host IP address |
| `target_ip` | `VARCHAR(64)` | No | - | Protected target host or VIP address |
| `service` | `VARCHAR(64)` | Yes | - | Primary targeted application service |
| `incident_id` | `VARCHAR(64)` | No | - | Identifier of the incident linked to this episode |
| `status` | `VARCHAR(16)` | No | `'OPEN'` | Episode lifecycle state (`OPEN`, `CLOSED`) |
| `first_seen` | `TIMESTAMPTZ` | No | - | Timestamp of first event in episode |
| `last_seen` | `TIMESTAMPTZ` | No | - | Timestamp of most recent event in episode |
| `last_event_ts_ns` | `BIGINT` | No | - | Upper bound nanosecond timestamp among ingested events |
| `event_count` | `INT` | No | `1` | Total count of security events aggregated |
| `enforcement` | `VARCHAR(32)` | No | - | Aggregate enforcement (`BLOCKED`, `ALLOWED_OR_DETECTED`, `MIXED`) |
| `evidence_ids` | `TEXT[]` | Yes | `'{}'` | Array of up to 25 representative event IDs preserved as evidence |
| `session_ids` | `BIGINT[]` | Yes | `'{}'` | Array of FortiOS firewall session IDs associated with episode |
| `enforcement_counts` | `JSONB` | Yes | `'{}'` | Cached count of events per enforcement category (`BLOCKED`, `ALLOWED_OR_DETECTED`) |
| `signatures` | `TEXT[]` | Yes | `'{}'` | Cached list of threat signatures matched in episode |
| `utm_subtypes` | `TEXT[]` | Yes | `'{}'` | UTM log subtypes seen in the episode (`ips`, `waf`, `virus`, `ssl`, ...), used with `signatures` and `enforcement_counts` to re-evaluate rules after a restart (migration 005) |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Record creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Record modification timestamp |

---

### 1.6 `incidents`
Top-level security incident entities representing actionable operational threats.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(64)` | No | - | Primary key: deterministic incident identifier (`INC-<hash>`) |
| `current_revision` | `INT` | No | `1` | Optimistic concurrency control revision counter |
| `status` | `VARCHAR(32)` | No | `'ACTIVE'` | Incident lifecycle status; `ACTIVE` is the only value written today (suppression and closure are Phase D analyst actions) |
| `severity` | `VARCHAR(16)` | No | - | Incident severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`); monotonic, never lowered by a re-evaluation or a model revision |
| `enforcement` | `VARCHAR(32)` | No | - | Primary enforcement state (`ALLOWED_OR_DETECTED`, `BLOCKED`, `MIXED`) |
| `exploitation_assessment` | `VARCHAR(32)` | No | `'INSUFFICIENT_EVIDENCE'` | Analyst/Model verdict (`ATTEMPT_OBSERVED`, `SUSPICIOUS_SEQUENCE`, `INSUFFICIENT_EVIDENCE`) |
| `vd` | `VARCHAR(64)` | Yes | `'root'` | FortiOS VDOM |
| `direction` | `VARCHAR(16)` | Yes | `'INBOUND'` | Flow direction |
| `source_ip` | `VARCHAR(64)` | No | - | Originating source IP |
| `target_ip` | `VARCHAR(64)` | No | - | Target IP |
| `target_port` | `INT` | Yes | - | Destination port |
| `target_service` | `VARCHAR(64)` | Yes | - | Destination service |
| `target_app` | `VARCHAR(128)` | Yes | - | Enriched asset identity / service name from `assets.yaml` |
| `first_seen` | `TIMESTAMPTZ` | No | - | Earliest event timestamp in campaign |
| `last_seen` | `TIMESTAMPTZ` | No | - | Latest event timestamp in campaign |
| `event_count` | `INT` | No | `1` | Cumulative event count across episodes |
| `summary` | `TEXT` | Yes | - | Human-readable incident summary |
| `deterministic_severity` | `VARCHAR(16)` | Yes | - | Baseline severity calculated by deterministic rule engine |
| `deterministic_enforcement` | `VARCHAR(32)` | Yes | - | Baseline enforcement calculated by deterministic rule engine |
| `deterministic_rule_ids` | `TEXT[]` | Yes | `'{}'` | Rule identifiers matched during deterministic evaluation |
| `last_urgent_at` | `TIMESTAMPTZ` | Yes | - | Timestamp when last URGENT alert was dispatched |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Incident creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Incident last updated timestamp |

---

### 1.7 `incident_revisions`
Immutable audit history of all deterministic and model assessments per incident revision.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Primary key surrogate |
| `incident_id` | `VARCHAR(64)` | No | - | Foreign key referencing `incidents(id)` |
| `revision` | `INT` | No | - | Revision number (1 for initial deterministic, 2+ for investigation) |
| `assessment_source` | `VARCHAR(32)` | Yes | `'DETERMINISTIC'` | Source of revision (`DETERMINISTIC`, `RATE_LIMITED`, `MODEL_VALIDATED`, `MODEL_REPAIRED`, `MODEL_REJECTED_FALLBACK`) |
| `rule_ids` | `TEXT[]` | No | `'{}'` | Rules triggering this assessment |
| `severity` | `VARCHAR(16)` | No | - | Assessed severity floor |
| `enforcement` | `VARCHAR(32)` | No | - | Assessed enforcement |
| `assessment_json` | `JSONB` | Yes | - | Full structured output assessment payload |
| `model_name` | `VARCHAR(64)` | Yes | - | Model identifier if assessed by LLM |
| `reasoning_summary` | `TEXT` | Yes | - | Synthesized investigation summary |
| `evidence_ids` | `TEXT[]` | No | `'{}'` | Pinned evidence IDs cited in assessment |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Revision creation timestamp |

---

### 1.8 `jobs`
Asynchronous investigation work queue leased by worker loops.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(64)` | No | - | Primary key (`JOB-<incident_id>-<revision>`) |
| `job_type` | `VARCHAR(64)` | No | - | Type of background job (`INVESTIGATE_INCIDENT`) |
| `payload_json` | `JSONB` | No | - | Serialized job execution parameters and context |
| `priority` | `INT` | No | `10` | Higher integer = higher priority |
| `status` | `VARCHAR(32)` | No | `'PENDING'` | Lifecycle state (`PENDING`, `LEASED`, `COMPLETED`, `FAILED`) |
| `attempts` | `INT` | No | `0` | Execution attempt count |
| `max_attempts` | `INT` | No | `3` | Maximum retry threshold before permanent failure |
| `lease_owner` | `VARCHAR(64)` | Yes | - | Unique worker process / task identifier holding the lease |
| `lease_expires_at` | `TIMESTAMPTZ` | Yes | - | Lease expiration deadline |
| `version_token` | `INT` | No | `1` | Monotonic token preventing lost updates during lease renewal |
| `next_run_at` | `TIMESTAMPTZ` | No | `NOW()` | Next eligible execution timestamp (supports exponential backoff) |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Job enqueue timestamp |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Job update timestamp |

---

### 1.9 `model_runs`
Complete audit trail for every LLM interaction, token usage, validation result, and transactional outcome.

In `adk` mode every row (`structured_output_mode = 'adk_json_schema'`) has a matching `agent_runs` row (section 1.12) for the same `incident_id` and `revision`, with the same `model_id`, tokens and latency, and `validation_result` equal to that run's `outcome`. There is no foreign key between the two tables, so join on `incident_id` and `revision` (and `agent_runs.mode = 'live'`). A job that is retried adds a row to each table; a commit refused by the revision CAS (another writer took the revision first) leaves `commit_status = 'CONFLICT'` and the `agent_runs` row in place. Rows of the legacy single call have no `agent_runs` row.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Surrogate primary key |
| `incident_id` | `VARCHAR(64)` | No | - | Incident evaluated |
| `revision` | `INT` | No | - | Target incident revision |
| `model_id` | `VARCHAR(128)` | No | - | Configured model identifier (e.g. `qwen3.8-27b`) |
| `server_reported_model` | `VARCHAR(128)` | Yes | - | Exact model string returned in API completion payload |
| `prompt_version` | `VARCHAR(32)` | No | - | Version identifier of prompt template used |
| `schema_version` | `VARCHAR(32)` | No | - | Pydantic JSON schema version enforced |
| `rule_pack_version` | `VARCHAR(32)` | No | - | Active version of `rules.yaml` |
| `catalog_version` | `VARCHAR(32)` | No | - | Active version of `action_catalog.yaml` |
| `action_map_version` | `VARCHAR(32)` | No | - | Active version of `action_map.yaml` |
| `input_hash` | `VARCHAR(64)` | No | - | SHA256 digest of input prompt and evidence packet |
| `input_tokens` | `INT` | No | `0` | Prompt token count consumed |
| `output_tokens` | `INT` | No | `0` | Completion tokens generated |
| `latency_ms` | `INT` | No | `0` | Model roundtrip latency in milliseconds |
| `structured_output_mode` | `VARCHAR(32)` | No | `'json_schema'` | Mode used (`json_schema` or `json_object` by the legacy single call; `adk_json_schema` for an ADK revision in `INVESTIGATOR_MODE=adk`) |
| `validation_result` | `VARCHAR(32)` | No | - | Schema check result (`VALID`, `REPAIRED`, `REJECTED`, `TIMEOUT`, `ERROR`); an ADK revision writes its `agent_runs.outcome` here (`VALID`, `REJECTED`, `BUDGET_EXHAUSTED`, `TIMEOUT`, `SCHEMA_INVALID`, `ERROR`) |
| `reason_codes` | `TEXT[]` | Yes | `'{}'` | Guardrail rule violations or validator downgrade reasons |
| `commit_status` | `VARCHAR(32)` | No | `'COMMITTED'` | State of transaction (`PENDING`, `COMMITTED`, `CONFLICT`, `FAILED`) |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Audit record creation timestamp |

---

### 1.10 `notification_outbox`
Transactional outbox guaranteeing at-least-once, rate-limited Google Chat webhook delivery.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Surrogate primary key |
| `incident_id` | `VARCHAR(64)` | No | - | Incident referenced by alert |
| `revision` | `INT` | No | - | Incident revision displayed in alert |
| `notification_type` | `VARCHAR(32)` | No | - | Alert type (`URGENT`, `INVESTIGATION_UPDATE`, `DIGEST`) |
| `type_priority` | `INT` | No | `50` | Outbox dispatch order: `10` (URGENT), `20` (INVESTIGATION), `50` (DIGEST) |
| `payload_json` | `JSONB` | No | - | Google Chat Cards v2 webhook payload |
| `status` | `VARCHAR(32)` | No | `'PENDING'` | Delivery state (`PENDING`, `SENT`, `SIMULATED`, `DEAD_LETTER`) |
| `attempts` | `INT` | No | `0` | Webhook dispatch attempt count |
| `retry_after_ts` | `TIMESTAMPTZ` | Yes | - | Earliest timestamp for next retry attempt |
| `last_error` | `TEXT` | Yes | - | Sanitized error message (secrets and URLs strictly redacted) |
| `sent_at` | `TIMESTAMPTZ` | Yes | - | Delivery timestamp |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Outbox insertion timestamp |

---

### 1.11 `schema_migrations`
Records which SQL files under `migrations/` have been applied; `Database.connect()` applies the missing ones in order and refuses to start without the directory.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `version` | `VARCHAR(64)` | No | - | Primary key: migration file stem, e.g. `004_phase_b1` |
| `applied_at` | `TIMESTAMPTZ` | No | `NOW()` | When the migration was applied |

---

### 1.12 `agent_runs`
One row per ADK investigation (migration 006, ADR 005), written by the runtime wrapper (`src/investigation/agent/audit.py`) after the run, whatever its outcome. In `shadow` mode this is the only record of the run besides `agent_events` and `shadow_assessments`; in `adk` mode the same run also produces the revision and, through the commit, a `model_runs` row for the same incident revision (section 1.9). A run abandoned because the service was stopped mid-run leaves no `agent_runs` row, and its job is retried.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Surrogate primary key |
| `incident_id` | `VARCHAR(64)` | No | - | Incident investigated |
| `revision` | `INT` | No | - | Revision the run assessed (the revision the investigation produces or shadows) |
| `session_id` | `VARCHAR(160)` | No | - | ADK session id, `<incident_id>:<revision>` (`adk.sessions.id`) |
| `mode` | `VARCHAR(16)` | No | - | `shadow` (INVESTIGATOR_MODE=shadow) or `live` (INVESTIGATOR_MODE=adk) |
| `adk_version` | `VARCHAR(32)` | No | - | Installed `google-adk` version |
| `model_id` | `VARCHAR(128)` | No | - | Configured model (`LLM_MODEL`) |
| `prompt_versions` | `JSONB` | No | `'{}'` | `# Version:` of each instruction file, keyed by agent name |
| `total_llm_calls` | `INT` | No | `0` | Model calls that reached the model, all four agents together (a call refused by the budget is not counted) |
| `total_tool_calls` | `INT` | No | `0` | Tool calls, including the master's two AgentTool calls and refused calls |
| `input_tokens` | `INT` | No | `0` | Prompt tokens reported by the endpoint, summed over the run |
| `output_tokens` | `INT` | No | `0` | Completion tokens reported by the endpoint, summed over the run |
| `latency_ms` | `INT` | No | `0` | Wall-clock duration of the run |
| `outcome` | `VARCHAR(32)` | No | - | `VALID`, `REJECTED`, `BUDGET_EXHAUSTED`, `TIMEOUT`, `SCHEMA_INVALID` or `ERROR` (section 2.6) |
| `reason_codes` | `TEXT[]` | No | `'{}'` | Validator reason codes for `VALID`; `AGENT_VALIDATION_REJECTED` plus the validator's codes for `REJECTED`; `AGENT_BUDGET_EXHAUSTED`, `AGENT_TIMEOUT`, `AGENT_SCHEMA_INVALID`, or `AGENT_ERROR` plus the exception class or ADK error code otherwise |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Row creation timestamp |

---

### 1.13 `agent_events`
One row per model call or tool call of an ADK run, in order: the trail an analyst reads to see why the agent said what it said.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `run_id` | `INT` | No | - | `agent_runs(id)`, `ON DELETE CASCADE`; primary key with `seq` |
| `seq` | `INT` | No | - | Order within the run, from 1 |
| `agent_name` | `VARCHAR(64)` | No | - | `incident_investigator`, `evidence_agent`, `context_agent` or `assessment_writer` |
| `kind` | `VARCHAR(8)` | No | - | `llm` or `tool` |
| `tool_name` | `VARCHAR(64)` | Yes | - | For `tool`: `evidence_agent` and `context_agent` (the master's AgentTool calls), `get_incident_packet`, `query_traffic_context`, `lookup_asset`, `lookup_signature`, `recent_incidents_for_source`, `get_action_catalog` |
| `args_json` | `JSONB` | Yes | - | For `tool`: the arguments after clamping and after undeclared arguments were dropped. For `llm`: `{"error": "<exception class>"}` when the call failed or was refused by the budget, otherwise null |
| `response_bytes` | `INT` | No | `0` | Size of the serialized tool result after redaction, delimiting and the 6 KB cap, or of the model's response content |
| `refused` | `BOOLEAN` | No | `FALSE` | Tool: the call was refused (allowlist, per-run cap of 3, invalid argument, IP or signature not part of the incident). LLM: the call was refused by the `AGENT_MAX_LLM_CALLS` ceiling |
| `latency_ms` | `INT` | No | `0` | Duration of the call (for an AgentTool call, the whole specialist run) |
| `tokens` | `INT` | No | `0` | `llm`: prompt plus completion tokens reported by the endpoint |
| `request_hash` | `VARCHAR(64)` | Yes | - | `llm`: SHA256 of the request as sent (after truncation) |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Row creation timestamp |

---

### 1.14 `shadow_assessments`
The ADK result of a `shadow` run next to its agreement with the legacy assessment of the same revision. Never shown to anyone: no revision and no card come from it.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Surrogate primary key |
| `incident_id` | `VARCHAR(64)` | No | - | Incident investigated |
| `revision` | `INT` | No | - | Revision the legacy call wrote and the ADK run shadowed |
| `run_id` | `INT` | Yes | - | `agent_runs(id)`, `ON DELETE SET NULL`; null if the audit write failed |
| `assessment_json` | `JSONB` | No | - | The ADK assessment after the validator, or the deterministic fallback |
| `assessment_source` | `VARCHAR(32)` | No | - | `MODEL_VALIDATED` or `MODEL_REJECTED_FALLBACK` |
| `validation_reason_codes` | `TEXT[]` | No | `'{}'` | The validator's reason codes (or the run's AGENT_* codes when the validator never ran) |
| `severity_equal` | `BOOLEAN` | No | - | ADK severity equals the legacy severity |
| `action_set_equal` | `BOOLEAN` | No | - | Same set of recommended action ids |
| `exploitation_equal` | `BOOLEAN` | No | - | Same `exploitation_assessment` |
| `findings_count` | `INT` | No | - | Findings in the ADK assessment |
| `legacy_findings_count` | `INT` | No | - | Findings in the legacy assessment |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Row creation timestamp |

### 1.15 Schema `adk`
Created by migration 006 for ADK's `DatabaseSessionService`, which creates and owns its tables there on first use (`sessions`, `events`, `app_states`, `user_states`, `adk_internal_metadata`). One session per investigated revision, id `<incident_id>:<revision>`, app `forti-investigator`, user `system`; its state holds the incident identity and the redacted packet, and its events every model and tool turn. A retried job replaces the session. Nothing prunes these tables yet (see the runbook).

---

## 2. Domain Enumerations

### 2.1 Severity Levels
- `CRITICAL`: Immediate threat to critical asset, verified exploit attempt without perimeter block.
- `HIGH`: Exploit attempt or mixed enforcement pattern requiring analyst investigation.
- `MEDIUM`: Contained threat, blocked port scanner, or known blocked malware download.
- `LOW`: Routine reconnaissance or unmapped log action visibility gap.

### 2.2 Exploitation Assessment
- `ATTEMPT_OBSERVED`: Evidence definitively documents an adversary attack signature or exploit attempt.
- `SUSPICIOUS_SEQUENCE`: Inbound pattern reflects anomalous probe progression or scanning behavior.
- `INSUFFICIENT_EVIDENCE`: Firewall telemetry alone cannot prove successful compromise or exploitation.

### 2.3 Assessment Sources
- `DETERMINISTIC`: Revision created directly from deterministic signature / threshold rule evaluations.
- `MODEL_VALIDATED`: Model investigation assessment validated on first pass against strict schema and guardrails.
- `MODEL_REPAIRED`: Model investigation assessment required single-repair bounded pass before acceptance. Written only by the legacy single call; the ADK path has no repair pass.
- `MODEL_REJECTED_FALLBACK`: Model investigation rejected or failed; deterministic fallback values applied. In `adk` mode the cause is the run's outcome (`agent_runs.outcome`, `model_runs.validation_result`) and the `AGENT_*` reason code in the summary.
- `RATE_LIMITED`: Deterministic revision whose investigation job was not queued because the per-source or per-target hourly limit was reached.

### 2.4 Model Run Commit Status
- `PENDING`: Model inference executed; awaiting database revision transaction.
- `COMMITTED`: Model assessment revision successfully committed to `incidents` and `incident_revisions`.
- `CONFLICT`: Revision optimistic concurrency check failed (e.g., incident advanced concurrently).
- `FAILED`: Model execution or transaction aborted due to exception.

### 2.5 Enforcement Outcomes
- `BLOCKED`: Traffic or payload definitively dropped or reset by FortiOS.
- `ALLOWED_OR_DETECTED`: Payload observed and permitted through to application backend.
- `MIXED`: Inbound campaign exhibited both dropped probes and allowed sessions.
- `UNKNOWN`: Unrecognized FortiOS action value requiring configuration review.

### 2.6 ADK Investigation Outcomes (`agent_runs.outcome`)
- `VALID`: the writer's object passed the schema and `validate_assessment`; the assessment is `MODEL_VALIDATED`.
- `REJECTED`: the validator hard-rejected the writer's object (identity mismatch, forbidden claim, ungrounded evidence id); deterministic fallback.
- `BUDGET_EXHAUSTED`: the run reached `AGENT_MAX_LLM_CALLS` model calls across all agents (or ADK raised `LlmCallsLimitExceededError`); deterministic fallback.
- `TIMEOUT`: the run exceeded `AGENT_TIMEOUT_SECONDS`; deterministic fallback.
- `SCHEMA_INVALID`: the writer produced no object, or one that does not validate as `WriterAssessment`; deterministic fallback.
- `ERROR`: any other failure (for example the model endpoint unreachable); deterministic fallback.
