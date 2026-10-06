# ADR 002: PostgreSQL for State, Leased Queue, and Transactional Outbox

## Status
Accepted (6 October 2026)

## Context
The service must store incident metadata, query coverage checkpoints, leased background jobs, and outgoing notifications durably without losing events across restarts. Introducing external message brokers like RabbitMQ or Kafka in the first release adds unnecessary infrastructure complexity.

## Decision
1. Use PostgreSQL 16 (running as a dedicated container) as the authoritative state store.
2. Raw firewall logs remain in Grafana Loki; only bounded selected-event snapshots and incident summaries are stored in PostgreSQL.
3. Implement a SQL-backed leased job queue (`jobs` table with `lease_owner`, `lease_expires_at`, `status`, and version tokens for fencing).
4. Implement a transactional notification outbox pattern (`notification_outbox` table) to guarantee at-least-once alert dispatch to Google Chat, decoupling alert creation from network webhook delivery.

## Consequences
- Single DB container simplifies operations and backups (`pg_dump`).
- Fenced leases prevent split-brain processing during worker retries or crashes.
- Clean isolation between database transactions and external network HTTP calls (Loki, vLLM, Google Chat).
