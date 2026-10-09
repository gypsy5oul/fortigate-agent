-- Migration 004: Phase B.1 fix pack additions
ALTER TABLE model_runs ADD COLUMN IF NOT EXISTS commit_status VARCHAR(32) NOT NULL DEFAULT 'COMMITTED';
ALTER TABLE episodes ADD COLUMN IF NOT EXISTS enforcement_counts JSONB DEFAULT '{}';
ALTER TABLE episodes ADD COLUMN IF NOT EXISTS signatures TEXT[] DEFAULT '{}';
