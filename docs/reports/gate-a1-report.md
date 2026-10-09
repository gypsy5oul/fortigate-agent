# Phase A.1 Remediation Completion Report

**Repository:** `gypsy5oul/fortigate-agent`  
**Branch:** `feature/gate-a1-critical-fixes`  
**Date:** 2026-10-07  
**Status:** Completed & Fully Validated Against PostgreSQL 16.14  

---

## 1. Files Changed & Purpose

| File | Purpose |
|---|---|
| `config/action_map.yaml` | Versioned `(type, subtype, action)` mapping with normalized enforcement, provenance citations, and verification status. |
| `config/action_catalog.yaml` | Action catalog marking unverified CLI templates as `verified_build: null`. |
| `config/rules.yaml` | Detection rule pack specifying non-blocked and mixed UTM exploit conditions. |
| `config/settings.py` | Configuration settings adding CLI gating, `fortios_build`, `allow_insecure_tls`, and sliding window rate limits. |
| `docker-compose.yml` | Hardened compose service removing default password fallbacks. |
| `.env.example` | Sanitized configuration template replacing credentials with `<set-me>`. |
| `migrations/001_initial_schema.sql` | Initial SQL schema with `schema_migrations` tracking table. |
| `migrations/002_text_columns.sql` | Schema migration expanding text columns, adding `utmaction`, `signature_truncated`, and `rejected_events`. |
| `src/correlator/session_aggregator.py` | Episode aggregator tracking blocked session IDs to prevent treating allowed traffic as unblocked exploits. |
| `src/investigation/adk_workflow.py` | ADK workflow enforcing deterministic enforcement pinning, static fallback with reason codes, and stripping ungrounded CVEs. |
| `src/investigation/schemas.py` | Pydantic schemas enforcing `extra="forbid"` and typed schema validation. |
| `src/main.py` | Service supervisor adding logging redaction filters, sliding window rate limiters, URGENT cooldown, and optimistic concurrency retries. |
| `src/notifications/gchat_cards.py` | Cards v2 renderer enforcing HTML escaping, URL defanging (`http://` -> `hxxp://`), and CLI template gating. |
| `src/notifications/outbox_worker.py` | Durable outbox worker supporting `SIMULATED` status, URL error redaction, and retry backoff. |
| `src/observability/metrics.py` | Prometheus metrics adding parser errors, model failures, and outbox delivery counters. |
| `src/parsing/normalizer.py` | FortiOS log normalizer with `utmaction` precedence, action map integration, and 512-character signature truncation. |
| `src/rules/engine.py` | Deterministic rule engine enforcing UTM action requirements, RFC1918 scanner suppression, and AV severity overrides. |
| `src/sources/checkpoints.py` | Poller orchestrator with monotonic non-decreasing checkpoints, outage catch-up loop, and saturation handling. |
| `src/storage/database.py` | Database connection manager supporting ordered SQL migration runner. |
| `src/storage/repository.py` | Storage repository supporting row fallback, optimistic locking (`expected_revision`), job leasing fencing (`version_token`), and terminal failure fallback revisions. |
| `src/storage/timeutil.py` | Time utility for robust UTC datetime parsing across SQLite and PostgreSQL. |
| `tests/test_action_map.py` | Table-driven tests validating all action map entries and rule semantics. |
| `tests/test_cards_snapshot.py` | Snapshot tests validating HTML escaping, URL defanging, and CLI gating. |
| `tests/test_checkpoints.py` | Checkpoint unit tests verifying strict monotonicity, 1-hour catch-up, and failure resilience. |
| `tests/integration/test_poller_loop_pg.py` | Integration tests driving poller loop, durable inbox, and fallback storage on PostgreSQL 16. |
| `tests/integration/test_investigation_loop_pg.py` | Integration tests driving concurrent optimistic transitions, lease fencing, and job backoff on PostgreSQL 16. |
| `tests/integration/test_outbox_loop_pg.py` | Integration tests driving Google Chat outbox dispatch, simulation, and URL redactions on PostgreSQL 16. |
| `tests/e2e/fake_endpoints.py` | Mock FastAPI service simulating Loki, OpenAI/vLLM, and Google Chat webhook endpoints. |
| `tests/e2e/test_service_e2e.py` | End-to-end tests validating full service supervision across all 5 threat scenarios and model outages on PostgreSQL 16. |
| `.github/workflows/ci.yml` | GitHub Actions CI pipeline running unit, integration, and e2e tests against a `postgres:16-alpine` service container. |

---

## 2. Acceptance Test Results

All 51 tests were executed in this session against real PostgreSQL 16.14.

**Test Command:**
```bash
TEST_DATABASE_URL="postgresql://forti_intel:<redacted>@172.18.0.2:5432/forti_test" .venv/bin/pytest -v
```

**Output:**
```
============================= test session starts ==============================
platform linux -- Python 3.9.16, pytest-8.4.2, pluggy-1.6.0 -- /opt/firewall-log-analysis-agent/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /opt/firewall-log-analysis-agent
configfile: pytest.ini
plugins: anyio-4.12.1, asyncio-1.2.0
asyncio: mode=auto, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 51 items

tests/e2e/test_service_e2e.py::test_e2e_scenarios_and_service_lifecycle PASSED [  1%]
tests/e2e/test_service_e2e.py::test_e2e_model_outage_fallback PASSED     [  3%]
tests/integration/test_investigation_loop_pg.py::test_pg_concurrent_incident_transitions_optimistic_locking PASSED [  5%]
tests/integration/test_investigation_loop_pg.py::test_pg_stale_job_lease_fencing PASSED [  7%]
tests/integration/test_investigation_loop_pg.py::test_pg_job_backoff_and_max_attempts_failure PASSED [  9%]
tests/integration/test_investigation_loop_pg.py::test_pg_unchanged_episode_poller_and_investigation_completion PASSED [ 11%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_dry_run_marks_simulated PASSED [ 13%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_failure_redacts_webhook_url PASSED [ 14%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_successful_delivery_marks_sent PASSED [ 16%]
tests/integration/test_poller_loop_pg.py::test_pg_long_msg_and_text_columns PASSED [ 18%]
tests/integration/test_poller_loop_pg.py::test_pg_batch_insert_rejection_fallback PASSED [ 20%]
tests/integration/test_poller_loop_pg.py::test_pg_durable_inbox_ordered_draining PASSED [ 22%]
tests/test_action_map.py::test_action_map_yaml_table_driven PASSED       [ 24%]
tests/test_action_map.py::test_ips_drop_session_blocked PASSED           [ 26%]
tests/test_action_map.py::test_ips_dropped_plus_accepted_traffic_same_session PASSED [ 28%]
tests/test_action_map.py::test_av_blocked_not_critical PASSED            [ 30%]
tests/test_action_map.py::test_existing_nonblocked_ips_fixture_still_critical_urgent PASSED [ 32%]
tests/test_action_map.py::test_internal_to_external_denies_never_match_scanner PASSED [ 34%]
tests/test_adk_workflow.py::test_guardrails_severity_floor PASSED        [ 36%]
tests/test_adk_workflow.py::test_offline_fallback PASSED                 [ 38%]
tests/test_cards_snapshot.py::test_cards_snapshot_html_escaping PASSED   [ 40%]
tests/test_cards_snapshot.py::test_cli_recommendations_disabled_by_default PASSED [ 42%]
tests/test_cards_snapshot.py::test_fallback_assessment_never_recommends_quarantine PASSED [ 44%]
tests/test_checkpoints.py::test_simulated_clock_advancement PASSED       [ 46%]
tests/test_checkpoints.py::test_catch_up_after_one_hour_outage PASSED    [ 48%]
tests/test_checkpoints.py::test_loki_failure_preserves_checkpoint PASSED [ 50%]
tests/test_correlator.py::test_session_aggregator_mixed_enforcement PASSED [ 52%]
tests/test_correlator.py::test_session_aggregator_idle_window_reset PASSED [ 54%]
tests/test_gate_a_remediation.py::test_f07_action_normalization PASSED   [ 56%]
tests/test_gate_a_remediation.py::test_f07_directionality_classification PASSED [ 58%]
tests/test_gate_a_remediation.py::test_f03_accurate_insert_counts_and_deduplication PASSED [ 60%]
tests/test_gate_a_remediation.py::test_f02_durable_inbox_draining PASSED [ 62%]
tests/test_gate_a_remediation.py::test_f05_f06_incident_escalation_and_atomic_transition PASSED [ 64%]
tests/test_gate_a_remediation.py::test_f08_schema_strictness PASSED      [ 66%]
tests/test_gate_a_remediation.py::test_f09_cli_snippet_rules PASSED      [ 68%]
tests/test_gate_a_remediation.py::test_f10_outbox_simulated_status PASSED [ 70%]
tests/test_outbox.py::test_build_gchat_card PASSED                       [ 72%]
tests/test_outbox.py::test_outbox_dry_run_dispatch PASSED                [ 74%]
tests/test_parser.py::test_parse_traffic_deny PASSED                     [ 76%]
tests/test_parser.py::test_parse_webfilter_blocked PASSED                [ 78%]
tests/test_parser.py::test_parse_escaped_quotes PASSED                   [ 80%]
tests/test_parser.py::test_normalize_action PASSED                       [ 82%]
tests/test_parser.py::test_normalize_event PASSED                        [ 84%]
tests/test_parser.py::test_normalize_ipv6 PASSED                         [ 86%]
tests/test_rules.py::test_nonblocked_exploit_rule PASSED                 [ 88%]
tests/test_rules.py::test_ssl_anomaly_rule PASSED                        [ 90%]
tests/test_rules.py::test_scanner_digest_rule PASSED                     [ 92%]
tests/test_storage.py::test_checkpoints_and_gaps PASSED                  [ 94%]
tests/test_storage.py::test_event_deduplication PASSED                   [ 96%]
tests/test_storage.py::test_leased_job_queue PASSED                      [ 98%]
tests/test_storage.py::test_notification_outbox PASSED                   [100%]

======================== 51 passed in 63.29s (0:01:03) =========================
```

**Deterministic Replay Harness Verification:**
```bash
.venv/bin/python replay.py --count 50 --burst 10 --delay 0.01
```
Output:
```
2026-10-07 14:41:42,788 [INFO] Starting deterministic log replay: count=50, burst=10
2026-10-07 14:41:42,794 [INFO] Initialized SQLite database: :memory:
2026-10-07 14:41:42,920 [INFO] Replay Triggered: Incident INC-AC52CFB84EE5 -> ['RULE_NONBLOCKED_EXPLOIT_ATTEMPT'] (Floor: CRITICAL)
2026-10-07 14:41:42,946 [INFO] === REPLAY BENCHMARK COMPLETE ===
2026-10-07 14:41:42,946 [INFO] Total Events Ingested: 50 (Processed: 50) in 0.14s (360.96 events/sec)
2026-10-07 14:41:42,946 [INFO] Unique Incidents Flagged: 1
```

---

## 3. End-to-End Scenario Table

As verified by `tests/e2e/test_service_e2e.py` executed against PostgreSQL 16:

| Scenario | Expected Outcome | Observed in Gate A.1 | Database Records & Outbox Verification |
|---|---|---|---|
| **1. Benign internal host** (DNS + HTTPS, sessions closed normally) | No alert | No alert ✔ | 2 events in `selected_events`. 0 urgent incidents, 0 outbox rows. |
| **2. Non-blocked IPS detection against VIP** (`action=detected`) | CRITICAL urgent | CRITICAL urgent ✔ | 1 event in `selected_events`. Incident created with `severity=CRITICAL`, `enforcement=ALLOWED_OR_DETECTED`. Outbox contains 1 URGENT card delivered and 1 INVESTIGATION_UPDATE card. Investigation job created and completed on attempt 1 with `INVESTIGATION_UPDATE` revision. Contiguous revisions `[1, 2]`. Deterministic cards contain no dangerous `ACT_QUARANTINE_SRC_IP` recommendation. |
| **3. IPS-dropped exploit** (`action=dropped`) + accepted traffic log of same session | No urgent alert | No urgent alert ✔ | 2 events in `selected_events`. Blocked session ID tracked; accepted traffic not treated as bypass. 0 URGENT outbox rows created or dispatched. |
| **4. Internal host, antivirus blocked a download** | No urgent alert | No urgent alert ✔ | 1 event in `selected_events`. `RULE_ANTIVIRUS_DETECTION` maps blocked AV to `severity=MEDIUM`, `routing=DIGEST`. 0 URGENT outbox rows. |
| **5. Blocked scanner** (12 denies) | Digest | Digest ✔ | 12 events in `selected_events`. `RULE_HIGH_FREQUENCY_SCANNER` matched with `severity=MEDIUM`, `routing=DIGEST`. 0 URGENT outbox rows. |
| **Model investigation updates** | One per urgent incident | One per urgent incident ✔ | Worker leases job with atomic version fencing. Model revision recorded, incident updated to contiguous revision 2 without crashing or CAS conflict. |
| **Loki coverage progress** | Continuous, strictly non-decreasing | Continuous ✔ | Checkpoint advances monotonically. 1-hour catch-up executes in bounded slices. Zero backward regressions. |

---

## 4. Live Checks Blocked (Environment Containment)

In accordance with Rule 4 ("No live systems"):
1. **Production Loki Gateway (`<loki-gateway-host>`)**:
   - Status: Blocked from live querying during test runs.
   - Requirement to run live: Operator network connectivity and rotated production credentials.
2. **Local Model Endpoint (`<vllm-host>:8000`)**:
   - Status: Mocked locally with FastAPI test server.
   - Requirement to run live: Active GPU container running vLLM with `qwen3.8-27b` and `--enable-auto-tool-choice`.
3. **Live Google Chat Space Webhook**:
   - Status: Mocked locally (`GCHAT_DRY_RUN=true` / mock webhook receiver).
   - Requirement to run live: Written authorization from SOC lead before live alert dispatch.

---

## 5. Architectural Consistency & Decisions Preserved

1. **Deterministic Spine Intact**:
   - All action mappings, severity floors, incident states, and routing decisions are evaluated in pure Python before any model invocation.
2. **Optimistic Concurrency & Fencing**:
   - Incident state updates require `current_revision = expected_revision`.
   - Investigation jobs require `version_token` lease fencing on completion.
3. **Defense-in-Depth Sanitization**:
   - Outbox error messages scrub all URLs containing query tokens (`[URL_REDACTED]`).
   - Logging filter (`SensitiveDataFilter`) active across root loggers.
   - All interpolated card text escaped via `html.escape` and external URLs defanged (`hxxp://`).
4. **Rate Limit Persistence Migration**:
   - Sliding window rate limiters (e.g., global urgent alert rate caps) operate via in-memory sliding windows in `src/main.py`. In Phase B, these will be migrated to persistent PostgreSQL rate-limit / state tables to guarantee distributed consistency across process restarts and replicas.

---

## 6. Open Risks & Operator Actions Required

1. **Loki Credential Rotation Required**:
   - The credential string present in historical commit `a014c67` remains in git history. Infrastructure owners must rotate this credential on the Loki gateway immediately.
2. **FortiOS Build Provisioning**:
   - CLI remediation templates are disabled by default (`cli_recommendations_enabled = false`). Operators must configure `FORTIOS_BUILD` before enabling CLI templates.
3. **vLLM Structured Output Verification**:
   - Required for Phase C: Verify whether vLLM release on `<vllm-host>` supports tool-calling combined with `response_format={"type": "json_object"}` or `json_schema`.

---

## 7. Runtime & Dependency Environment

- **Host Python Version:** `3.9.16` (development & test execution virtualenv)
- **Container Target Version:** `python:3.12-slim` (compatible with standard Python 3.9+ type constructs and syntax)
- **PostgreSQL Version:** `PostgreSQL 16.14 on x86_64-pc-linux-musl (Alpine Linux)`
- **Installed Dependency Versions:** (host .venv; `requirements.txt` specifies compatible version ranges)
  - `fastapi==0.128.8`
  - `uvicorn==0.39.0`
  - `httpx==0.28.1`
  - `asyncpg==0.31.0`
  - `pydantic==2.12.5`
  - `pydantic-settings==2.11.0`
  - `pytest==8.4.2`
  - `pytest-asyncio==1.2.0`
  - `prometheus_client==0.26.0`
  - `PyYAML==6.0.3`
  - `google-adk==1.18.0`
  - `litellm==1.83.9`
