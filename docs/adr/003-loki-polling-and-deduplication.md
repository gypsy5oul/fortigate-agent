# ADR 003: Loki Polling, Checkpointing, and Overlap Deduplication

## Status
Accepted (6 October 2026)

## Context
Firewall syslog events forwarded to Grafana Loki can experience variable network and ingestion lag. Strict non-overlapping polling risks missing delayed events. Query intervals that return the max limit (1000 entries) may truncate data silently.

## Decision
1. Bounded range poller queries `/loki/api/v1/query_range` forward in time with a configurable lookback overlap (default 120 seconds).
2. Track durable query checkpoints and coverage intervals in PostgreSQL (`query_checkpoints` table).
3. Deduplicate events in the overlap window using a deterministic SHA-256 fingerprint generated from device ID, stream, nano timestamp, source IP/port, destination IP/port, log ID, and raw message.
4. If a query hits the result limit (`entries == max_entries`), recursively bisect the query time slice down to sub-second windows to guarantee no truncated events.
5. Record explicit coverage gaps in `coverage_gaps` table if unsplittable saturation or gateway errors occur.

## Consequences
- Guaranteed zero missed events within the lookback horizon.
- Resilient recovery after network hiccups or service downtime.
