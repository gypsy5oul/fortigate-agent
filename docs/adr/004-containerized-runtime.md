# ADR 004: 100% Containerized Runtime Deployment

## Status
Accepted (6 October 2026)

## Context
Per operational policy, no long-running services, background daemons, or databases should run directly on the host operating system. The solution must deploy as isolated containers.

## Decision
1. Package the Python application in a hardened, multi-stage Docker container based on `python:3.12-slim`.
2. Run the application as an unprivileged non-root user (`appuser:10001`, `appgroup:10001`) with read-only root filesystems where possible and isolated `/tmp/scratch` volumes.
3. Deploy PostgreSQL 16 using official `postgres:16-alpine` on an isolated internal Docker bridge network (`forti_net`).
4. Manage both services using `docker-compose.yml`, using named persistent volumes for database data.
5. Expose HTTP health endpoints (`/health/live`, `/health/ready`) and Prometheus metrics on a single unprivileged port (:8000 internally, mapped to :8085 on host).

## Consequences
- Clean lifecycle management (`docker-compose up -d / down`).
- Host OS remains completely clean.
- Consistent reproducibility across staging and production environments.
