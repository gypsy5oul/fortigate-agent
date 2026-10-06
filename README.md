# FortiGate 200G Firewall Intelligence Service

A resilient, containerized AI agent service that monitors Grafana Loki for FortiGate 200G firewall and Deep Packet Inspection (DPI) logs, correlates attack sessions, enforces deterministic SOC rule severity floors, conducts bounded investigation using a local **Qwen3.8-27B** model via **Google ADK**, and dispatches actionable incident cards to **Google Chat**.

---

## 1. Architectural Highlights

- **100% Containerized Runtime**: Operates solely within Docker containers (`docker-compose.yml`), deploying the Python intelligence agent alongside an isolated `postgres:16-alpine` database.
- **Upstream Ingestion Preserved**: Bounded consumer of Grafana Loki (`service_name="forticlient"`). No secondary log collectors or mirror databases.
- **Fail-Safe Deterministic Severity Floor**: High-impact non-blocked exploits (`action="detected"` or `"passthrough"`) immediately enqueue critical alerts before model analysis. If the local LLM is offline or times out, deterministic alerts still deliver.
- **Google ADK + Local Qwen 27B**: Employs Google Agent Development Kit (`google-adk`) to execute bounded, single-pass investigations against local vLLM (`http://10.0.6.31:8000/v1`), preventing hallucinations, unconstrained agent swarms, or unauthorized tool executions.
- **Firewall-Only Evidence Boundary**: Strictly restricted to `visibility_scope=FIREWALL_ONLY`. The agent will never falsely claim verified endpoint compromise without backend telemetry.
- **Transactional Outbox & Cards v2**: Google Chat alerts use Cards v2 format with incident threading, rate-limiting, and deep drill-down links to Grafana Explore.

---

## 2. Directory Structure

```
/opt/firewall-log-analysis-agent/
├── docker-compose.yml              # Container orchestration (App + PostgreSQL 16)
├── Dockerfile                      # Hardened multi-stage non-root Python 3.12 image
├── .env.example                    # Configuration template
├── requirements.txt                # Pinned dependencies
├── config/
│   ├── settings.py                 # Pydantic Settings
│   ├── rules.yaml                  # Deterministic security rules & severity floors
│   ├── action_catalog.yaml         # Allowlisted remediation recommendations
│   └── assets.yaml                 # VIP-to-application mapping
├── src/
│   ├── sources/
│   │   ├── loki_client.py          # Bounded LogQL range poller with interval bisection
│   │   └── checkpoints.py          # Checkpoint tracker with overlap deduplication
│   ├── parsing/
│   │   ├── fortios_parser.py       # FortiOS syslog key=value lexer and parser
│   │   └── normalizer.py           # Normalization & SHA-256 fingerprint generator
│   ├── storage/
│   │   ├── schema.sql              # PostgreSQL DDL
│   │   ├── database.py             # Database connector (PostgreSQL / SQLite)
│   │   └── repository.py           # Async repository (leased queue & outbox)
│   ├── correlator/
│   │   └── session_aggregator.py   # Sliding window episode aggregator
│   ├── rules/
│   │   └── engine.py               # Deterministic rule evaluation engine
│   ├── investigation/
│   │   ├── schemas.py              # Pydantic schemas (IncidentPacket & QwenAssessment)
│   │   ├── prompts.py              # Defensive analyst system prompt
│   │   └── adk_workflow.py         # Google ADK agent with local Qwen connector
│   ├── notifications/
│   │   ├── gchat_cards.py          # Cards v2 builder with thread keys
│   │   └── outbox_worker.py        # Rate-limited outbox dispatcher (dry-run safe)
│   ├── observability/
│   │   └── metrics.py              # Prometheus metrics & FastAPI health probes
│   └── main.py                     # Asynchronous supervisor entrypoint
├── dashboards/
│   ├── firewall_threat_overview.json # Grafana Dashboard A: Threat Overview
│   └── agent_operations.json         # Grafana Dashboard B: Agent Telemetry
├── tests/                          # 19 comprehensive unit & integration tests
│   ├── fixtures/fortios_logs.py
│   ├── test_parser.py
│   ├── test_rules.py
│   ├── test_correlator.py
│   ├── test_storage.py
│   ├── test_adk_workflow.py
│   └── test_outbox.py
└── replay.py                       # CLI benchmark & load testing harness
```

---

## 3. Verified Environment Endpoints

| Component | Target URL | Verified Credentials / Settings |
| :--- | :--- | :--- |
| **Grafana Loki** | `https://loki-readonly.6dcorp.internal/loki/api/v1/query_range` | User: `ai-agent` (Basic Auth)<br>IP: `10.0.20.150:443`<br>Selector: `{service_name="forticlient"}` |
| **Local Qwen 27B** | `http://10.0.6.31:8000/v1` | Runtime: vLLM OpenAI API<br>Model ID: `qwen3.8-27b` |
| **PostgreSQL** | `postgres:5432` | DB: `forti_intelligence`, User: `forti_intel` |
| **Google Chat** | Webhook URL configured via `GCHAT_WEBHOOK_URL` | Set `GCHAT_DRY_RUN=true` for testing without posting to rooms |

---

## 4. Setup & Running via Docker Compose

### Step 1: Configure Environment Variables
Copy `.env.example` to `.env` and configure your settings:
```bash
cp .env.example .env
```
*(To enable live Google Chat delivery, set `GCHAT_DRY_RUN=false` and provide your incoming webhook URL in `GCHAT_WEBHOOK_URL`)*.

### Step 2: Build and Start Containers
```bash
docker-compose up -d --build
```

### Step 3: Verify Status and Health
```bash
# Check container status
docker-compose ps

# View service logs
docker-compose logs -f app

# Verify HTTP liveness and readiness
curl http://localhost:8085/health/live
curl http://localhost:8085/health/ready

# View Prometheus metrics
curl http://localhost:8085/metrics
```

---

## 5. Running Tests & Offline Replay Benchmark

The test suite runs with SQLite in-memory without needing PostgreSQL or network access:

```bash
# Run full unit and integration test suite (19 tests)
pytest -v tests/

# Run deterministic replay load benchmark
python replay.py --count 100 --burst 20
```

---

## 6. Grafana Dashboards

Two production dashboards are located in `dashboards/`:
1. **`dashboards/firewall_threat_overview.json`**:
   - Security events rate by UTM subtype and action.
   - Top attacking source IPs and top targeted destination VIPs.
   - Triggered exploit signatures and live log stream drilldown.
2. **`dashboards/agent_operations.json`**:
   - Poller query duration (p95/p50) and lines/sec ingestion rate.
   - Active memory episodes, leased queue processing, and local Qwen inference latency.
   - Google Chat outbox delivery rate and failure counters.
