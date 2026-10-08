-- Migration 002: Convert free-text columns to TEXT and add rejected_events and incident audit fields

-- Convert selected_events free-text columns to TEXT
ALTER TABLE selected_events ALTER COLUMN signature TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN action_raw TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN log_type TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN subtype TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN severity_raw TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN service TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN devid TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN vd TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN logid TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN srcintfrole TYPE TEXT;
ALTER TABLE selected_events ALTER COLUMN dstintfrole TYPE TEXT;
ALTER TABLE selected_events ADD COLUMN IF NOT EXISTS utmaction TEXT;
ALTER TABLE selected_events ADD COLUMN IF NOT EXISTS signature_truncated BOOLEAN DEFAULT FALSE;

-- Create rejected_events table for unparseable / constraint-violating rows
CREATE TABLE IF NOT EXISTS rejected_events (
    id VARCHAR(64) PRIMARY KEY,
    reason TEXT NOT NULL,
    raw_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Incidents deterministic tracking and cooldown
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS deterministic_severity VARCHAR(16);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS deterministic_enforcement VARCHAR(32);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS deterministic_rule_ids TEXT[] DEFAULT '{}';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_urgent_at TIMESTAMP WITH TIME ZONE;

-- Revisions source tracking
ALTER TABLE incident_revisions ADD COLUMN IF NOT EXISTS assessment_source VARCHAR(32) DEFAULT 'DETERMINISTIC';
