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
| `log_type` | `VARCHAR(32)` | No | - | FortiOS primary log category (`utm`, `traffic`, `event`) |
| `subtype` | `VARCHAR(32)` | Yes | - | FortiOS subsystem subtype (`ips`, `virus`, `waf`, `ssl`, `forward`) |
| `srcip` | `VARCHAR(64)` | No | - | Source IP address (IPv4 or IPv6) |
| `srcport` | `INT` | Yes | - | Source Layer 4 port number |
| `dstip` | `VARCHAR(64)` | Yes | - | Destination IP address (nullable for pure system/auth events) |
| `dstport` | `INT` | Yes | - | Destination Layer 4 port number |
| `proto` | `INT` | Yes | - | IP protocol number (e.g. 6 = TCP, 17 = UDP, 1 = ICMP) |
| `service` | `VARCHAR(64)` | Yes | - | Layer 7 service name identifier (e.g. `HTTPS`, `DNS`, `SSH`) |
| `action_raw` | `VARCHAR(32)` | Yes | - | Exact raw `action` string reported in FortiOS log |
| `action_normalized` | `VARCHAR(32)` | No | - | Normalized enforcement category (`BLOCKED`, `ALLOWED_OR_DETECTED`, `UNKNOWN`) |
| `signature` | `VARCHAR(256)` | Yes | - | Threat signature name, attack identifier, or virus name |
| `raw_message` | `TEXT` | No | - | Untrusted original log message payload |
| `processing_status` | `VARCHAR(16)` | No | `'PENDING'` | Ingest state (`PENDING`, `PROCESSED`, `FAILED`) |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Database record insertion timestamp |

---

### 1.2 `query_checkpoints`
Maintains monotonic log ingestion positions per query profile and Loki stream selector.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `stream_name` | `VARCHAR(256)` | No | - | Primary key: compound selector tag (`<selector>#<profile>@v<version>`) |
| `last_seen_ts_ns` | `BIGINT` | No | - | Monotonically advancing upper boundary nanosecond timestamp from Loki |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Timestamp when the checkpoint was durably advanced |

---

### 1.3 `episodes`
Tracks active and closed attack episodes correlated over 30-minute campaign windows.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(128)` | No | - | Primary key: SHA256 hex digest prefix (`EP-<hash>`) of `vdom\|direction\|src\|dst\|start` |
| `vdom` | `VARCHAR(64)` | No | `'root'` | FortiOS Virtual Domain partition |
| `direction` | `VARCHAR(16)` | No | `'UNKNOWN'` | Traffic direction (`INBOUND`, `OUTBOUND`, `INTERNAL`, `UNKNOWN`) |
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
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Record creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Record modification timestamp |

---

### 1.4 `incidents`
Top-level security incident entities representing actionable operational threats.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(64)` | No | - | Primary key: deterministic incident identifier (`INC-<hash>`) |
| `current_revision` | `INT` | No | `1` | Optimistic concurrency control revision counter |
| `status` | `VARCHAR(32)` | No | `'ACTIVE'` | Incident lifecycle status (`ACTIVE`, `SUPPRESSED`, `CLOSED_TRUE_POSITIVE`, `CLOSED_FALSE_POSITIVE`) |
| `severity` | `VARCHAR(16)` | No | - | Active severity floor (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) |
| `enforcement` | `VARCHAR(32)` | No | - | Primary enforcement state (`ALLOWED_OR_DETECTED`, `BLOCKED`, `MIXED`) |
| `exploitation_assessment` | `VARCHAR(32)` | No | `'INSUFFICIENT_EVIDENCE'` | Analyst/Model verdict (`ATTEMPT_OBSERVED`, `SUSPECTED_SUCCESS`, `BLOCKED`, `BENIGN_SCANNER`) |
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

### 1.5 `incident_revisions`
Immutable audit history of all deterministic and model assessments per incident revision.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | - | Primary key surrogate |
| `incident_id` | `VARCHAR(64)` | No | - | Foreign key referencing `incidents(id)` |
| `revision` | `INT` | No | - | Revision number (1 for initial deterministic, 2+ for investigation) |
| `assessment_source` | `VARCHAR(32)` | No | `'DETERMINISTIC'` | Source of revision (`DETERMINISTIC`, `MODEL_VALIDATED`, `MODEL_FALLBACK`) |
| `rule_ids` | `TEXT[]` | No | `'{}'` | Rules triggering this assessment |
| `severity` | `VARCHAR(16)` | No | - | Assessed severity floor |
| `enforcement` | `VARCHAR(32)` | No | - | Assessed enforcement |
| `assessment_json` | `JSONB` | Yes | - | Full structured output assessment payload |
| `model_name` | `VARCHAR(64)` | Yes | - | Model identifier if assessed by LLM |
| `reasoning_summary` | `TEXT` | Yes | - | Synthesized investigation summary |
| `evidence_ids` | `TEXT[]` | No | `'{}'` | Pinned evidence IDs cited in assessment |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Revision creation timestamp |

---

### 1.6 `jobs`
Asynchronous investigation work queue leased by worker loops.

| Column | Data Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `VARCHAR(64)` | No | - | Primary key (`JOB-<incident_id>-<revision>`) |
| `job_type` | `VARCHAR(64)` | No | - | Type of background job (`INVESTIGATION`, `DIGEST_BATCH`) |
| `payload_json` | `JSONB` | No | - | Serialized job execution parameters and context |
| `priority` | `INT` | No | `10` | Higher integer = higher priority |
| `status` | `VARCHAR(32)` | No | `'PENDING'` | Lifecycle state (`PENDING`, `LEASED`, `COMPLETED`, `FAILED`, `SUPERSEDED`) |
| `attempts` | `INT` | No | `0` | Execution attempt count |
| `max_attempts` | `INT` | No | `3` | Maximum retry threshold before permanent failure |
| `lease_owner` | `VARCHAR(64)` | Yes | - | Unique worker process / task identifier holding the lease |
| `lease_expires_at` | `TIMESTAMPTZ` | Yes | - | Lease expiration deadline |
| `version_token` | `INT` | No | `1` | Monotonic token preventing lost updates during lease renewal |
| `next_run_at` | `TIMESTAMPTZ` | No | `NOW()` | Next eligible execution timestamp (supports exponential backoff) |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Job enqueue timestamp |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Job update timestamp |

---

### 1.7 `model_runs`
Complete audit trail for every LLM interaction, token usage, and schema validation result.

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
| `structured_output_mode` | `VARCHAR(32)` | No | `'json_schema'` | Mode used (`json_schema` or `json_object`) |
| `validation_result` | `VARCHAR(32)` | No | - | Schema check result (`VALID`, `REPAIRED`, `INVALID`, `FALLBACK`) |
| `reason_codes` | `TEXT[]` | Yes | `'{}'` | Guardrail rule violations or validator downgrade reasons |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Audit record creation timestamp |

---

### 1.8 `notification_outbox`
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

## 2. Domain Enumerations

### 2.1 Severity Levels
- `CRITICAL`: Immediate threat to critical asset, verified exploit attempt without perimeter block.
- `HIGH`: Exploit attempt or mixed enforcement pattern requiring analyst investigation.
- `MEDIUM`: Contained threat, blocked port scanner, or known blocked malware download.
- `LOW`: Routine reconnaissance or unmapped log action visibility gap.
- `INFORMATIONAL`: Normal service health or benign network activity.

### 2.2 Enforcement Outcomes
- `BLOCKED`: Traffic or payload definitively dropped or reset by FortiOS.
- `ALLOWED_OR_DETECTED`: Payload observed and permitted through to application backend.
- `MIXED`: Inbound campaign exhibited both dropped probes and allowed sessions.
- `SESSION_CLOSED`: Normal TCP/UDP session termination without policy enforcement.
- `UNKNOWN`: Unrecognized FortiOS action value requiring configuration review.
