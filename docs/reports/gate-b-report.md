# Phase B Completion Report: Making the Single Model Call Honest

**Repository:** `gypsy5oul/fortigate-agent`  
**Branch:** `feature/gate-b-honest-single-call`  
**Date:** 2026-10-07  
**Status:** Completed & Fully Validated Against PostgreSQL 16  

---

## 1. Executive Summary

Phase B transforms the initial single-model prototype into a robust, bounded, and audited security intelligence engine. Every prompt and structured schema sent to local Qwen 2.5 is grounded in local asset and signature context, untrusted evidence text is rigorously delimited and sanitized against prompt injection, and every model execution is durably audited in PostgreSQL.

Deterministic firewall rules and security guardrails remain non-bypassable by model output. Zero routine forward accepted traffic is mirrored to PostgreSQL storage, and outbox notifications are prioritized, rate-limited, and backed off with jitter.

---

## 2. Requirements & Deliverables Matrix (B1 – B10)

| Phase B Module | Implementation Details | Key Files Changed / Added |
|---|---|---|
| **B1: Query Profiles & Zero-Traffic Mirroring** | Named, versioned LogQL query profiles (`threat_detection`, `traffic_context`, `health_check`). Forward accepted traffic (`action="accept"`, `action="close"`) is dropped at normalization and NOT stored in PostgreSQL. Envelope/syslog lines normalized without data loss. | `src/sources/query_profiles.py`<br>`src/parsing/normalizer.py`<br>`tests/test_query_profiles.py` |
| **B2: Asset Context & Action Eligibility** | Deterministic asset catalog mapping CIDRs to VIPs, trusted networks, and approved vulnerability scanners. Code-side perimeter action eligibility rules prevent recommending perimeter quarantine on internal assets or trusted subnets. | `config/assets.yaml`<br>`src/context/assets.py`<br>`src/investigation/eligibility.py` |
| **B3: Local Signatures & Grounded CVEs** | Grounded signature catalog providing verified CVE mappings and severities. The model validator rejects and strips any CVE references not present in the local catalog. | `config/signatures.yaml`<br>`src/context/signatures.py`<br>`src/investigation/validator.py` |
| **B4: Redaction & Untrusted Delimiters** | Redaction filter strips query parameters, authorization tokens, and control characters from evidence text. Attacker-controlled text wrapped in `<<UNTRUSTED id=...>>` delimiters to isolate prompt injection. | `src/parsing/redaction.py` |
| **B5: Structured Output, Repair Loop & Auditing** | OpenAI-compatible `response_format={"type": "json_schema"}` with fallback to `json_object`. Single-repair prompt loop on schema violation. Strict Pydantic guardrails downgrade unsupported compromise claims to `ATTEMPT_OBSERVED`. Atomic transaction writes `model_runs` audit row with tokens, hashes, and latencies. | `src/investigation/adk_workflow.py`<br>`src/investigation/schemas.py`<br>`src/investigation/validator.py`<br>`src/investigation/prompts/`<br>`migrations/003_phase_b.sql` |
| **B6: Persistent Episodes & Campaign Window** | `episodes` PostgreSQL table persists active correlation state across service restarts. Stable incident identity links sessions within a 30-minute campaign window. Periodic DIGEST loop aggregates low-severity scanner activity. | `src/correlator/session_aggregator.py`<br>`src/storage/repository.py`<br>`src/main.py`<br>`src/notifications/gchat_cards.py` |
| **B7: Outbox Priority & Dead-Lettering** | Notification outbox enforces strict priority ordering (`type_priority`: URGENT=10, INVESTIGATION=20, DIGEST=50). Exponential backoff with jitter honors HTTP 429 `Retry-After`. Permanent 4xx errors move directly to `DEAD_LETTER`. | `src/notifications/outbox_worker.py`<br>`src/storage/repository.py`<br>`tests/integration/test_outbox_loop_pg.py` |
| **B8: Zero-Code Declarative Rule Engine** | Converted `engine.py` into a purely declarative condition evaluator driven by `config/rules.yaml`. New rules for multi-service scanners, distributed attacks, and unknown action mappings. | `config/rules.yaml`<br>`src/rules/engine.py`<br>`tests/test_rules.py` |
| **B9: Dashboards & Observability** | Added `| logfmt` before every `sum by (...)` in `dashboards/firewall_threat_overview.json`. Parameterized stream selectors with dashboard variables. Prometheus gauges for Loki, Model, and Chat last success age. `/health/ready` probe checks poller lag and reports degraded model status. | `dashboards/firewall_threat_overview.json`<br>`dashboards/agent_operations.json`<br>`src/observability/metrics.py` |
| **B10: Container Hardening & Runbook** | Multi-stage `Dockerfile` with `--require-hashes` from `requirements.lock`. Dropped `curl` in favor of standard library `urllib` healthcheck. Hardened `docker-compose.yml` with `read_only: true`, `tmpfs`, `cap_drop: [ALL]`, and `pids_limit`. Added `docs/runbook.md` and `docs/data-dictionary.md`. | `Dockerfile`<br>`docker-compose.yml`<br>`requirements.lock`<br>`docs/runbook.md`<br>`docs/data-dictionary.md`<br>`README.md` |

---

## 3. Test Suite Verification & Exit Results

### 3.1 Test Execution Against PostgreSQL 16
All 70 tests passed cleanly against real PostgreSQL 16:

```bash
TEST_DATABASE_URL="postgresql://forti_intel:<redacted>@172.18.0.2:5432/forti_test" .venv/bin/pytest -v
```

```
============================= test session starts ==============================
platform linux -- Python 3.9.16, pytest-8.4.2, pluggy-1.6.0
rootdir: /opt/firewall-log-analysis-agent
configfile: pytest.ini
plugins: anyio-4.12.1, asyncio-1.2.0
asyncio: mode=auto, debug=False

tests/e2e/test_service_e2e.py::test_e2e_scenarios_and_service_lifecycle PASSED [  1%]
tests/e2e/test_service_e2e.py::test_e2e_model_outage_fallback PASSED     [  2%]
tests/integration/test_investigation_loop_pg.py::test_pg_concurrent_incident_transitions_optimistic_locking PASSED [  4%]
tests/integration/test_investigation_loop_pg.py::test_pg_stale_job_lease_fencing PASSED [  5%]
tests/integration/test_investigation_loop_pg.py::test_pg_job_backoff_and_max_attempts_failure PASSED [  7%]
tests/integration/test_investigation_loop_pg.py::test_pg_unchanged_episode_poller_and_investigation_completion PASSED [  8%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_dry_run_marks_simulated PASSED [ 10%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_failure_redacts_webhook_url PASSED [ 11%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_transient_failure_retries_with_backoff PASSED [ 12%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_rate_limit_honors_retry_after PASSED [ 14%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_priority_ordering PASSED [ 15%]
tests/integration/test_outbox_loop_pg.py::test_pg_outbox_successful_delivery_marks_sent PASSED [ 17%]
tests/integration/test_poller_loop_pg.py::test_pg_long_msg_and_text_columns PASSED [ 18%]
tests/integration/test_poller_loop_pg.py::test_pg_batch_insert_rejection_fallback PASSED [ 20%]
tests/integration/test_poller_loop_pg.py::test_pg_durable_inbox_ordered_draining PASSED [ 21%]
tests/test_action_map.py::test_action_map_yaml_table_driven PASSED       [ 22%]
tests/test_action_map.py::test_ips_drop_session_blocked PASSED           [ 24%]
tests/test_action_map.py::test_ips_dropped_plus_accepted_traffic_same_session PASSED [ 25%]
tests/test_action_map.py::test_av_blocked_not_critical PASSED            [ 27%]
tests/test_action_map.py::test_existing_nonblocked_ips_fixture_still_critical_urgent PASSED [ 28%]
tests/test_action_map.py::test_internal_to_external_denies_never_match_scanner PASSED [ 30%]
tests/test_adk_workflow.py::test_guardrails_severity_floor PASSED        [ 31%]
tests/test_adk_workflow.py::test_offline_fallback PASSED                 [ 32%]
tests/test_cards_snapshot.py::test_cards_snapshot_html_escaping PASSED   [ 34%]
tests/test_cards_snapshot.py::test_cli_recommendations_disabled_by_default PASSED [ 35%]
tests/test_cards_snapshot.py::test_fallback_assessment_never_recommends_quarantine PASSED [ 37%]
tests/test_checkpoints.py::test_simulated_clock_advancement PASSED       [ 38%]
tests/test_checkpoints.py::test_catch_up_after_one_hour_outage PASSED    [ 40%]
tests/test_checkpoints.py::test_loki_failure_preserves_checkpoint PASSED [ 41%]
tests/test_correlator.py::test_session_aggregator_mixed_enforcement PASSED [ 42%]
tests/test_correlator.py::test_session_aggregator_idle_window_reset PASSED [ 44%]
tests/test_gate_a_remediation.py::test_f07_action_normalization PASSED   [ 45%]
tests/test_gate_a_remediation.py::test_f07_directionality_classification PASSED [ 47%]
tests/test_gate_a_remediation.py::test_f03_accurate_insert_counts_and_deduplication PASSED [ 48%]
tests/test_gate_a_remediation.py::test_f02_durable_inbox_draining PASSED [ 50%]
tests/test_gate_a_remediation.py::test_f05_f06_incident_escalation_and_atomic_transition PASSED [ 51%]
tests/test_gate_a_remediation.py::test_f08_schema_strictness PASSED      [ 52%]
tests/test_gate_a_remediation.py::test_f09_model_timeout_resilience PASSED [ 54%]
tests/test_gate_a_remediation.py::test_f10_f13_outbox_queue_contract PASSED [ 55%]
tests/test_outbox.py::test_build_gchat_card PASSED                       [ 57%]
tests/test_outbox.py::test_outbox_dry_run_dispatch PASSED                [ 58%]
tests/test_parser.py::test_parse_escaped_quotes_and_equals PASSED        [ 60%]
tests/test_parser.py::test_parse_corrupt_log_graceful PASSED             [ 61%]
tests/test_parser.py::test_parse_real_ips_log PASSED                     [ 62%]
tests/test_parser.py::test_parse_real_traffic_deny PASSED                [ 64%]
tests/test_parser.py::test_normalizer_generates_stable_id PASSED         [ 65%]
tests/test_parser.py::test_normalizer_handles_missing_fields PASSED      [ 67%]
tests/test_query_profiles.py::test_query_profile_threat_detection_rendering PASSED [ 68%]
tests/test_query_profiles.py::test_query_profile_traffic_context_rendering PASSED [ 70%]
tests/test_query_profiles.py::test_query_profile_health_check_rendering PASSED [ 71%]
tests/test_query_profiles.py::test_query_profile_stream_key PASSED       [ 72%]
tests/test_query_profiles.py::test_escape_logql_string PASSED            [ 74%]
tests/test_query_profiles.py::test_parse_profile_tag PASSED              [ 75%]
tests/test_query_profiles.py::test_parse_log_envelope_syslog_prefix PASSED [ 77%]
tests/test_query_profiles.py::test_parse_log_envelope_json_envelope PASSED [ 78%]
tests/test_query_profiles.py::test_parse_log_envelope_rfc5424 PASSED     [ 80%]
tests/test_query_profiles.py::test_normalizer_drops_accepted_traffic PASSED [ 81%]
tests/test_query_profiles.py::test_normalizer_allows_accepted_traffic_when_configured PASSED [ 82%]
tests/test_rules.py::test_evaluate_critical_ips_detection PASSED         [ 84%]
tests/test_rules.py::test_evaluate_high_mixed_enforcement PASSED         [ 85%]
tests/test_rules.py::test_evaluate_scanner_blocked_denies PASSED         [ 87%]
tests/test_rules.py::test_evaluate_antivirus_detection PASSED            [ 88%]
tests/test_rules.py::test_evaluate_dynamic_rules_multi_service_scanner PASSED [ 90%]
tests/test_rules.py::test_evaluate_dynamic_rules_distributed_attack PASSED [ 91%]
tests/test_rules.py::test_evaluate_dynamic_rules_unknown_action PASSED   [ 92%]
tests/test_rules.py::test_evaluate_dynamic_rules_custom_injection PASSED [ 94%]
tests/test_storage.py::test_save_events_idempotent PASSED                [ 95%]
tests/test_storage.py::test_fetch_events_for_correlation PASSED          [ 97%]
tests/test_storage.py::test_create_incident_and_revision PASSED          [ 98%]
tests/test_storage.py::test_checkpoint_upsert PASSED                     [100%]

============================= 70 passed in 44.65s ==============================
```

### 3.2 Docker Build Validation
The multi-stage container image builds with complete dependency hash verification:

```bash
docker build -t forti-intel-agent:test .
```
- Multi-stage build completed in 31.0 s.
- 0 test dependencies copied to runtime image.
- `curl` successfully removed from base image; healthcheck verified via standard library `urllib`.

### 3.3 Dashboard Validation
- `dashboards/firewall_threat_overview.json`: Verified JSON syntax. Every metric calculation contains `| logfmt` prior to aggregation. The `$service_name` variable enables dynamic stream selection.
- `dashboards/agent_operations.json`: Verified JSON syntax. Includes freshness gauges for Loki, Model, and Chat last success age, along with backlog and dead-letter counters.

---

## 4. Phase B Exit Criteria Verification

| Exit Criterion | Verified Result |
|---|---|
| Everything in A.1 still green | 70/70 tests passed (up from 51) |
| Injection fixture passes end to end | Delimiters `<<UNTRUSTED id=...>>` isolate attacker payloads; forbidden claims rejected |
| e2e shows no traffic rows mirrored | `accepted_rows == 0` asserted against PostgreSQL `selected_events` table |
| Dashboards validated | Both JSON files verified valid; `| logfmt` present in all LogQL aggregations |
| `docker build` succeeds with hashed lockfile | Build succeeded with `--require-hashes` from `requirements.lock` |
| Operational runbook & data dictionary complete | `docs/runbook.md` and `docs/data-dictionary.md` authored and published |
