# FortiGate 200G Firewall Intelligence Service

A resilient, containerized security service that monitors Grafana Loki for FortiGate 200G firewall and Deep Packet Inspection (DPI) logs, correlates attack sessions across 30-minute campaign windows, enforces deterministic SOC rule severity floors, conducts bounded single-pass investigation using a local **Qwen3.8-27B** model with structured JSON schemas, and dispatches actionable incident cards to **Google Chat**.

---

## 1. Architectural Principles

- **Containerized Hardened Runtime**: Operates in isolated Docker containers (`docker-compose.yml`) deploying the Python intelligence agent with a read-only root filesystem, dropped Linux capabilities (`cap_drop: [ALL]`), `no-new-privileges:true`, and resource limits alongside PostgreSQL 16.
- **Selective, Budgeted Ingest**: Ingests security detections (`type="utm"`) and perimeter denies (`type="traffic" action="deny"`). Routine forward accepted traffic (`action="accept"`, `action="close"`) is filtered at ingest and NOT mirrored to the database to prevent storage bloat. Contextual traffic enrichment is queried on-demand directly from Loki.
- **Monotonic Query Checkpoints**: Loki log cursors advance monotonically in durable PostgreSQL storage only after events are successfully inserted.
- **Fail-Safe Deterministic Severity Floor**: High-impact non-blocked exploits (`action="detected"` or `"passthrough"`) immediately establish a critical severity floor. If the local LLM is offline, degraded, or times out, deterministic alerts are dispatched without disruption.
- **Bounded Structured Model Output**: Uses OpenAI-compatible `response_format={"type": "json_schema"}` with strict Pydantic schemas, defensive delimiters (`<<UNTRUSTED id=...>>`) against prompt injection, a single-repair retry loop, and complete audit persistence in `model_runs`.
- **Firewall-Only Evidence Boundary**: Strictly restricted to `visibility_scope=FIREWALL_ONLY`. Unsupported claims of application compromise are rejected and downgraded to `ATTEMPT_OBSERVED`.
- **Reliable Priority Outbox**: Google Chat Cards v2 alerts are delivered via an outbox worker honoring strict priority ordering (URGENT > INVESTIGATION_UPDATE > DIGEST), exponential backoff with jitter, `Retry-After` rate-limiting, and permanent 4xx dead-lettering.

---

## 2. Directory Structure

```
/opt/firewall-log-analysis-agent/
├── docker-compose.yml              # Hardened orchestration (App + PostgreSQL 16)
├── Dockerfile                      # Multi-stage non-root container with --require-hashes
├── requirements.lock               # Cryptographically pinned dependencies with SHA256 hashes
├── requirements.in                 # Direct runtime dependency declarations
├── requirements.txt                # Pinned production runtime requirements
├── requirements-dev.txt            # Development and testing requirements
├── config/
│   ├── settings.py                 # Pydantic configuration settings
│   ├── rules.yaml                  # Declarative dynamic SOC rules & routing
│   ├── action_map.yaml             # FortiOS action to enforcement mapping
│   ├── action_catalog.yaml         # Allowlisted remediation recommendations
│   ├── assets.yaml                 # Internal VIPs, trusted subnets, scanners
│   └── signatures.yaml             # Local signature metadata and CVE mappings
├── src/
│   ├── sources/
│   │   ├── loki_client.py          # Bounded LogQL range poller
│   │   ├── query_profiles.py       # Named versioned query profiles with line filters
│   │   └── checkpoints.py          # Monotonic checkpoint cursor management
│   ├── parsing/
│   │   ├── fortios_parser.py       # FortiOS syslog key=value lexer and parser
│   │   ├── normalizer.py           # Normalization & accepted traffic filter
│   │   └── redaction.py            # Redaction & untrusted delimiter wrappers
│   ├── context/
│   │   ├── assets.py               # Asset catalog loader & CIDR matcher
│   │   └── signatures.py           # Signature metadata & CVE grounded verifier
│   ├── storage/
│   │   ├── database.py             # Database pool connector (PostgreSQL / SQLite)
│   │   └── repository.py           # Repository for events, episodes, revisions, outbox
│   ├── correlator/
│   │   └── session_aggregator.py   # Campaign & session episode aggregator (30m window)
│   ├── rules/
│   │   └── engine.py               # Zero-code declarative condition evaluator
│   ├── investigation/
│   │   ├── schemas.py              # Pydantic schemas (IncidentPacket & QwenAssessment)
│   │   ├── prompts/                # Versioned prompt templates
│   │   ├── validator.py            # Security guardrails & CVE claim validator
│   │   ├── eligibility.py          # Perimeter action eligibility constraints
│   │   └── single_call_workflow.py # Structured output LLM runner with repair loop
│   ├── notifications/
│   │   ├── gchat_cards.py          # Cards v2 builder with thread keys & digest cards
│   │   └── outbox_worker.py        # Priority outbox worker with retry backoff
│   ├── observability/
│   │   └── metrics.py              # Prometheus metrics & /health/ready probes
│   └── main.py                     # Asynchronous supervisor entrypoint
├── dashboards/
│   ├── alerts.yml                  # Prometheus alert rules for operational health
│   ├── firewall_threat_overview.json # Grafana Dashboard A: Threat Overview (logfmt)
│   └── agent_operations.json         # Grafana Dashboard B: Agent Telemetry & Freshness
├── docs/
│   ├── runbook.md                  # Backup/restore, reprocessing, and recovery runbook
│   ├── data-dictionary.md          # Complete PostgreSQL schema and data dictionary
│   └── adr/                        # Architectural Decision Records
└── tests/                          # Comprehensive test suite (116 tests)
```

---

## 3. Verified Endpoints & Configuration

| Component | Target URL | Settings & Credentials |
| :--- | :--- | :--- |
| **Grafana Loki** | `https://loki.internal/loki/api/v1/query_range` | Selector: `{service_name="forticlient"}`<br>Profile: `security_events` (filters `type="utm"`, `type="event"`, and block/deny actions)<br>Basic Auth via `LOKI_USER` / `LOKI_PASSWORD` |
| **Local Qwen 27B** | `http://vllm.internal:8000/v1` | vLLM OpenAI API, model `qwen3.8-27b` |
| **PostgreSQL 16** | `postgres:5432` | DB: `forti_intelligence`, User: `forti_intel` |
| **Google Chat** | Configured via `GCHAT_WEBHOOK_URL` | Set `GCHAT_DRY_RUN=true` to simulate deliveries |

---

## 4. Operational Setup

### Step 1: Configure Environment Variables
Copy `.env.example` to `.env` and configure credentials:
```bash
cp .env.example .env
```
*(Ensure `CA_BUNDLE_PATH` points to your CA bundle file if custom TLS certificates are needed)*.

### Step 2: Build and Start Containers
```bash
docker compose up -d --build
```

### Step 3: Verify Health Probes
```bash
# Liveness probe (HTTP 200 when supervisor tasks are running)
curl http://localhost:8085/health/live

# Readiness probe (HTTP 200 when DB connected and poller lag < 3x poll interval)
curl http://localhost:8085/health/ready

# Prometheus metrics
curl http://localhost:8085/metrics
```

---

## 5. Testing & Validation

The test suite covers unit tests, PostgreSQL 16 integration tests, and full child-process end-to-end scenarios:

```bash
# Run full test suite against local PostgreSQL 16
TEST_DATABASE_URL="postgresql://forti_intel:<password>@<db-host>:5432/forti_test" pytest -v tests/
```

Refer to [docs/runbook.md](file:///opt/firewall-log-analysis-agent/docs/runbook.md) for backup/restore, reprocessing, and troubleshooting procedures, and [docs/data-dictionary.md](file:///opt/firewall-log-analysis-agent/docs/data-dictionary.md) for schema definitions.
