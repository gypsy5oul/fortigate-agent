# FortiGate 200G Firewall Intelligence Service

A resilient, containerized security service that monitors Grafana Loki for FortiGate 200G firewall and Deep Packet Inspection (DPI) logs, correlates attack sessions across 30-minute campaign windows, enforces deterministic SOC rule severity floors, conducts bounded single-pass investigation using a local **Qwen3.8-27B** model with structured JSON schemas, and dispatches actionable incident cards to **Google Chat**.

---

## 1. Architectural Principles

- **Containerized Hardened Runtime**: Operates in isolated Docker containers (`docker-compose.yml`) deploying the Python intelligence agent with a read-only root filesystem, dropped Linux capabilities (`cap_drop: [ALL]`), `no-new-privileges:true`, and resource limits alongside PostgreSQL 16.
- **Selective, Budgeted Ingest**: The `security_events` query profile (`LOKI_QUERY_PROFILE`) asks Loki only for UTM detections (`type="utm"`), FortiOS event logs (`type="event"`), perimeter denies (`action="deny"`) and UTM blocks (`utmaction="block"`). Routine accepted traffic (`action="accept"`, `action="close"`) is dropped at ingest and never mirrored to the database. A `traffic_context` profile serves on-demand enrichment: only the ADK investigator's read-only `query_traffic_context` tool calls it (shadow and adk modes, section 5).
- **Monotonic Query Checkpoints**: Loki log cursors advance monotonically in durable PostgreSQL storage only after events are successfully inserted.
- **Fail-Safe Deterministic Severity Floor**: High-impact non-blocked exploits (`action="detected"` or `"passthrough"`) immediately establish a critical severity floor. If the local LLM is offline, degraded, or times out, deterministic alerts are dispatched without disruption.
- **Bounded Structured Model Output**: Uses OpenAI-compatible `response_format={"type": "json_schema"}` with strict Pydantic schemas, defensive delimiters (`<<UNTRUSTED id=...>>`) against prompt injection, a single-repair retry loop, and complete audit persistence in `model_runs`.
- **ADK Agent Investigator (shadow mode)**: A Google ADK agent system (a master investigator, two specialist agents with read-only tools, and a schema-bound writer) runs beside the single call when `INVESTIGATOR_MODE=shadow` and is audited in `agent_runs`, `agent_events` and `shadow_assessments` without producing any revision or card (section 5, `docs/adr/005-adk-investigator.md`).
- **Firewall-Only Evidence Boundary**: Strictly restricted to `visibility_scope=FIREWALL_ONLY`. Unsupported claims of application compromise are rejected and downgraded to `ATTEMPT_OBSERVED`.
- **Reliable Priority Outbox**: Google Chat Cards v2 alerts are delivered via an outbox worker honoring strict priority ordering (URGENT > INVESTIGATION_UPDATE > DIGEST), exponential backoff with jitter, `Retry-After` rate-limiting, and permanent 4xx dead-lettering.

---

## 2. Directory Structure

```
<repository root>/
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
│   │   ├── schemas.py              # Pydantic schemas (IncidentPacket, QwenAssessment, WriterAssessment)
│   │   ├── prompts/                # Versioned prompt templates (legacy single call)
│   │   ├── validator.py            # Security guardrails & CVE claim validator
│   │   ├── eligibility.py          # Perimeter action eligibility constraints
│   │   ├── single_call_workflow.py # Structured output LLM runner with repair loop (legacy mode)
│   │   └── agent/                  # ADK investigator (shadow and adk modes, ADR 005)
│   │       ├── agents.py           # Master, two specialists, writer; Workflow root
│   │       ├── tools.py            # Read-only tools bound to the incident in session state
│   │       ├── callbacks.py        # Bounds, redaction/delimiters, model-call ceiling, usage
│   │       ├── runtime.py          # Runner, sessions, budgets, outcome mapping, validator
│   │       ├── audit.py            # Per-run record; writer of agent_runs/agent_events/shadow_assessments
│   │       └── instructions/       # Versioned agent instructions (master, evidence, context, writer)
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
└── tests/                          # Unit, PostgreSQL integration, agent (tests/agent) and real-process e2e tests
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
# Liveness probe (HTTP 200 whenever the HTTP server answers; it does not inspect the supervisor tasks)
curl http://localhost:8085/health/live

# Readiness probe: 503 if the database is unreachable or the last successful poll is older than
# 3x LOKI_POLL_INTERVAL_SECONDS; 200 {"status":"degraded"} after 3 consecutive model failures
# (deterministic rules keep running); 200 {"status":"ready"} otherwise, including before the first poll
curl http://localhost:8085/health/ready

# Prometheus metrics
curl http://localhost:8085/metrics
```

---

## 5. Investigator Modes

`INVESTIGATOR_MODE` selects who writes the investigation revision of an urgent incident. Detection, severity floors, URGENT cards, the outbox and checkpoints are the same in every mode.

| Mode | Investigation revision and card | ADK agent pipeline | Rows written by the agent path |
| :--- | :--- | :--- | :--- |
| `legacy` (default) | one bounded structured call (`single_call_workflow.py`) | not loaded | none |
| `shadow` | the legacy call, unchanged | runs after the legacy revision is committed; never writes a revision or a card; a failure there never fails the job | `agent_runs`, `agent_events`, `shadow_assessments` |
| `adk` | the ADK pipeline's validated assessment (or the deterministic fallback), through the same `record_incident_transition` CAS and job fence | runs instead of the legacy call | `agent_runs`, `agent_events`, plus the usual `model_runs` row |

The pipeline: `incident_investigator` calls `evidence_agent` (tools `get_incident_packet`, `query_traffic_context`) and then `context_agent` (`lookup_asset`, `lookup_signature`, `recent_incidents_for_source`, `get_action_catalog`) as tools, writes investigation notes, and `assessment_writer` turns them into a schema-bound assessment that passes the same validator as the legacy path. Every tool is read-only and bound to the incident in session state; every tool result is redacted and wrapped in `<<UNTRUSTED>>` delimiters. Settings:

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `INVESTIGATOR_MODE` | `legacy` | `legacy`, `shadow` or `adk` |
| `AGENT_MAX_LLM_CALLS` | `8` | model calls per investigation across all four agents; beyond it the run stops with `AGENT_BUDGET_EXHAUSTED` |
| `AGENT_TIMEOUT_SECONDS` | `120` | deadline for one whole investigation; beyond it `AGENT_TIMEOUT` |
| `ADK_SESSION_DB_URL` | derived | ADK session store; unset means `DATABASE_URL` as `postgresql+asyncpg://`, tables in schema `adk` (migration 006) |

The agents use `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `LLM_TIMEOUT_SECONDS` (per model call), `LLM_MAX_INPUT_TOKENS` and `LLM_MAX_OUTPUT_TOKENS`. vLLM must run with `--enable-auto-tool-choice --tool-call-parser hermes` for Qwen tool calling. Operating the modes: [docs/runbook.md](docs/runbook.md) section 5.

---

## 6. Testing & Validation

The test suite covers unit tests, PostgreSQL 16 integration tests, and full child-process end-to-end scenarios:

```bash
# Run full test suite against local PostgreSQL 16
TEST_DATABASE_URL="postgresql://forti_intel:<password>@<db-host>:5432/forti_test" pytest -v tests/
```

The ADK investigator is tested without a live model: `tests/agent/` drives the real ADK with a scripted `BaseLlm` (`tests/agent/fake_llm.py`) and fake Loki, and the e2e suite runs the real process in `shadow` and `adk` modes against a fake vLLM that answers OpenAI-format `tool_calls`.

### Golden set and `adk eval` (model lab, not CI)

`evals/golden/*.test.json` are ADK EvalSets, one per golden case (non-blocked IPS exploit, blocked exploit, mixed enforcement escalation, AV blocked, scanner, injection payload, tool silence), built by `scripts/build_golden_set.py` from the e2e scenarios through the real normalizer, aggregator, rules and eligibility; `tests/agent/test_golden_set.py` fails if a committed file differs from what the script builds. Each case holds the packet the investigator would receive, the tool data the read-only tools may see during evaluation (`eval_fixture`; evaluation never reads Loki or the database and writes nothing), the expected trajectory (`evidence_agent`, then `context_agent`) and a reviewed reference assessment. `evals/test_config.json` sets `tool_trajectory_avg_score` 1.0 (exact order, arguments ignored because they are free text) and `response_match_score` 0.6. CI runs every golden case through the investigator against the scripted fake vLLM (`tests/agent/test_golden_set.py`); the lab runs them against the real model. That needs ADK's eval extras on top of `requirements-dev.txt` (`pip install "google-adk[eval]==2.11.0"`, not part of the image):

```bash
# From the repository root, with the lab vLLM serving the model:
PYTHONPATH=. LLM_BASE_URL=http://<vllm-host>:8000/v1 LLM_MODEL=<served-model> \
  adk eval src/investigation/agent evals/golden/*.test.json \
  --config_file_path evals/test_config.json --print_detailed_results
# Same criteria as a pass/fail pytest run (adk eval itself exits 0 even when cases fail):
RUN_LAB_EVALS=1 LLM_BASE_URL=http://<vllm-host>:8000/v1 LLM_MODEL=<served-model> \
  pytest -m lab -v tests/agent/test_golden_eval_lab.py
```

Add `evals/lab/*.test.json` to the `adk eval` file list once real incidents have been exported there (`evals/lab/README.md`); the pytest run picks them up by itself. `adk eval` writes its results under `src/investigation/agent/.adk/` (ignored by git).

Refer to [docs/runbook.md](docs/runbook.md) for backup/restore, reprocessing, and troubleshooting procedures, and [docs/data-dictionary.md](docs/data-dictionary.md) for schema definitions. Phase reports are generated from a clean checkout with `scripts/make_phase_report.sh`.
