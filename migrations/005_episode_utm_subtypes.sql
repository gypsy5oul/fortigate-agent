-- Migration 005: persist the UTM log subtypes an episode has seen (ips, waf, virus, ssl, ...).
-- Rule evaluation after a restart uses this together with signatures and enforcement
-- counts, so subtype-specific rules can be re-matched without the original event lines.
ALTER TABLE episodes ADD COLUMN IF NOT EXISTS utm_subtypes TEXT[] DEFAULT '{}';
