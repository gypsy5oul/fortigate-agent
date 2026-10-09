-- PostgreSQL initial schema for FortiGate Firewall Intelligence Service

CREATE TABLE IF NOT EXISTS query_checkpoints (
    id SERIAL PRIMARY KEY,
    stream_name VARCHAR(128) NOT NULL UNIQUE,
    last_queried_ts_ns BIGINT NOT NULL,
    last_successful_run TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coverage_gaps (
    id SERIAL PRIMARY KEY,
    start_ts_ns BIGINT NOT NULL,
    end_ts_ns BIGINT NOT NULL,
    stream_name VARCHAR(128) NOT NULL,
    reason TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS selected_events (
    id VARCHAR(64) PRIMARY KEY,
    loki_ts_ns BIGINT NOT NULL,
    eventtime_ns BIGINT,
    devid VARCHAR(64),
    vd VARCHAR(64) DEFAULT 'root',
    direction VARCHAR(16) DEFAULT 'UNKNOWN',
    srcintfrole VARCHAR(32),
    dstintfrole VARCHAR(32),
    logid VARCHAR(64),
    log_type VARCHAR(32) NOT NULL,
    subtype VARCHAR(32),
    action_raw VARCHAR(32),
    action_normalized VARCHAR(32) NOT NULL,
    srcip VARCHAR(64) NOT NULL,
    srcport INT,
    dstip VARCHAR(64) NOT NULL,
    dstport INT,
    proto INT,
    service VARCHAR(64),
    policyid INT,
    sessionid BIGINT,
    signature VARCHAR(256),
    url TEXT,
    http_method VARCHAR(16),
    severity_raw VARCHAR(32),
    raw_message TEXT NOT NULL,
    processing_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    processed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_srcip_ts ON selected_events(srcip, created_at);
CREATE INDEX IF NOT EXISTS idx_events_dstip_ts ON selected_events(dstip, created_at);
CREATE INDEX IF NOT EXISTS idx_events_loki_ts ON selected_events(loki_ts_ns);
CREATE INDEX IF NOT EXISTS idx_events_pending ON selected_events(processing_status, loki_ts_ns);

CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(64) PRIMARY KEY,
    current_revision INT NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    severity VARCHAR(16) NOT NULL,
    enforcement VARCHAR(32) NOT NULL,
    exploitation_assessment VARCHAR(32) NOT NULL DEFAULT 'INSUFFICIENT_EVIDENCE',
    vd VARCHAR(64) DEFAULT 'root',
    direction VARCHAR(16) DEFAULT 'INBOUND',
    source_ip VARCHAR(64) NOT NULL,
    target_ip VARCHAR(64) NOT NULL,
    target_port INT,
    target_service VARCHAR(64),
    target_app VARCHAR(128),
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    summary TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_status_updated ON incidents(status, updated_at);

CREATE TABLE IF NOT EXISTS incident_revisions (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    revision INT NOT NULL,
    rule_ids TEXT[] NOT NULL DEFAULT '{}',
    severity VARCHAR(16) NOT NULL,
    enforcement VARCHAR(32) NOT NULL,
    assessment_json JSONB,
    model_name VARCHAR(64),
    reasoning_summary TEXT,
    evidence_ids TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_incident_rev UNIQUE (incident_id, revision)
);

CREATE TABLE IF NOT EXISTS jobs (
    id VARCHAR(64) PRIMARY KEY,
    job_type VARCHAR(64) NOT NULL,
    payload_json JSONB NOT NULL,
    priority INT NOT NULL DEFAULT 10,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    lease_owner VARCHAR(64),
    lease_expires_at TIMESTAMP WITH TIME ZONE,
    version_token INT NOT NULL DEFAULT 1,
    next_run_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs(status, next_run_at, priority);

CREATE TABLE IF NOT EXISTS notification_outbox (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    revision INT NOT NULL,
    notification_type VARCHAR(32) NOT NULL,
    payload_json JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    sent_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_outbox_incident_rev_type UNIQUE (incident_id, revision, notification_type)
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending ON notification_outbox(status, created_at);
