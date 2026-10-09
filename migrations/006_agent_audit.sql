-- Migration 006: Phase C.1 agent audit (ADR 005).
-- agent_runs and agent_events are the trail an analyst reads to see why the ADK investigator said
-- what it said; shadow_assessments holds the ADK result of a shadow-mode run next to its agreement
-- with the legacy assessment. Only the runtime wrapper (src/investigation/agent/audit.py) writes
-- them; no agent, tool or callback writes to any table.

-- ADK's DatabaseSessionService creates its own session tables (sessions, events, app_states,
-- user_states, adk_internal_metadata) in this schema, away from the service's tables.
CREATE SCHEMA IF NOT EXISTS adk;

CREATE TABLE IF NOT EXISTS agent_runs (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    revision INT NOT NULL,
    session_id VARCHAR(160) NOT NULL,
    mode VARCHAR(16) NOT NULL,
    adk_version VARCHAR(32) NOT NULL,
    model_id VARCHAR(128) NOT NULL,
    prompt_versions JSONB NOT NULL DEFAULT '{}',
    total_llm_calls INT NOT NULL DEFAULT 0,
    total_tool_calls INT NOT NULL DEFAULT 0,
    input_tokens INT NOT NULL DEFAULT 0,
    output_tokens INT NOT NULL DEFAULT 0,
    latency_ms INT NOT NULL DEFAULT 0,
    outcome VARCHAR(32) NOT NULL,
    reason_codes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_inc_rev ON agent_runs(incident_id, revision);

CREATE TABLE IF NOT EXISTS agent_events (
    run_id INT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    seq INT NOT NULL,
    agent_name VARCHAR(64) NOT NULL,
    kind VARCHAR(8) NOT NULL,
    tool_name VARCHAR(64),
    args_json JSONB,
    response_bytes INT NOT NULL DEFAULT 0,
    refused BOOLEAN NOT NULL DEFAULT FALSE,
    latency_ms INT NOT NULL DEFAULT 0,
    tokens INT NOT NULL DEFAULT 0,
    request_hash VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (run_id, seq)
);

CREATE TABLE IF NOT EXISTS shadow_assessments (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    revision INT NOT NULL,
    run_id INT REFERENCES agent_runs(id) ON DELETE SET NULL,
    assessment_json JSONB NOT NULL,
    assessment_source VARCHAR(32) NOT NULL,
    validation_reason_codes TEXT[] NOT NULL DEFAULT '{}',
    severity_equal BOOLEAN NOT NULL,
    action_set_equal BOOLEAN NOT NULL,
    exploitation_equal BOOLEAN NOT NULL,
    findings_count INT NOT NULL,
    legacy_findings_count INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_shadow_assessments_inc_rev ON shadow_assessments(incident_id, revision);
