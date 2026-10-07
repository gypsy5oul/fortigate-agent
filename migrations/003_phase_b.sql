-- Migration 003: Phase B Model Runs Audit, Persistent Episodes, and Outbox Priorities

-- 1. Model runs audit log
CREATE TABLE IF NOT EXISTS model_runs (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    revision INT NOT NULL,
    model_id VARCHAR(128) NOT NULL,
    server_reported_model VARCHAR(128),
    prompt_version VARCHAR(32) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    rule_pack_version VARCHAR(32) NOT NULL,
    catalog_version VARCHAR(32) NOT NULL,
    action_map_version VARCHAR(32) NOT NULL,
    input_hash VARCHAR(64) NOT NULL,
    input_tokens INT NOT NULL DEFAULT 0,
    output_tokens INT NOT NULL DEFAULT 0,
    latency_ms INT NOT NULL DEFAULT 0,
    structured_output_mode VARCHAR(32) NOT NULL DEFAULT 'json_schema',
    validation_result VARCHAR(32) NOT NULL,
    reason_codes TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_model_runs_inc_rev ON model_runs(incident_id, revision);

-- 2. Persistent security episodes
CREATE TABLE IF NOT EXISTS episodes (
    id VARCHAR(128) PRIMARY KEY,
    vdom VARCHAR(64) NOT NULL DEFAULT 'root',
    direction VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
    source_ip VARCHAR(64) NOT NULL,
    target_ip VARCHAR(64) NOT NULL,
    service VARCHAR(64),
    incident_id VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'OPEN',
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_event_ts_ns BIGINT NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    enforcement VARCHAR(32) NOT NULL,
    evidence_ids TEXT[] DEFAULT '{}',
    session_ids BIGINT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_episodes_open ON episodes(status, vdom, direction, source_ip, target_ip);

-- 3. Checkpoint stream key length expansion for profile tags (<selector>#<profile>@v<version>)
ALTER TABLE query_checkpoints ALTER COLUMN stream_name TYPE VARCHAR(256);

-- 4. Allow nullable dstip in selected_events for event logs without destination IP
ALTER TABLE selected_events ALTER COLUMN dstip DROP NOT NULL;

-- 5. Outbox priority and retry scheduling
ALTER TABLE notification_outbox ADD COLUMN IF NOT EXISTS type_priority INT DEFAULT 50;
ALTER TABLE notification_outbox ADD COLUMN IF NOT EXISTS retry_after_ts TIMESTAMP WITH TIME ZONE;
CREATE INDEX IF NOT EXISTS idx_outbox_prio ON notification_outbox(status, type_priority, id);
