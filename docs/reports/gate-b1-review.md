# Phase B.1 review: `feature/gate-b1-fix-pack` (commit `72bd8c3`)

> **Resolution (2026-10-08).** Every item below, including the documentation appendix, is
> implemented in commit `6cf6cfa` on `claude/gifted-galileo-xx27sj` (a merge of `72bd8c3` plus
> the follow-up). The generated verification report is `docs/reports/gate-b1-report.md`; the
> three Defect A acceptance tests and the restart e2e all fail at `72bd8c3` and pass at
> `6cf6cfa`. Phase C.0 starts from that branch.

Reviewer: Claude (Fable 5.1), 2026-10-08. Branch is based on `b552e02` (Phase B). Plan reference:
`docs/GEMINI-PHASE-B1-AND-PHASE-C-ADK-PLAN.md` section 1.

**Verdict: close, but not ready to exit B.1.** Five of the seven blocking defects are fixed and
verified by execution, including the two that mattered most (the container now ships its
migrations, and SIGTERM exits cleanly in under half a second). Two things block the exit: the
restored-episode logic demotes a CRITICAL incident to MEDIUM after a restart (observed in a real
two-phase run), and the report's transcripts still do not come from the pushed commit. Four
"done" items are also broken in ways that make them inert: the metrics updater queries tables
that do not exist, every alert rule references a metric that does not exist, the compose smoke
script addresses services that are not in the compose file, and the ADK naming was aliased rather
than removed. All are small. One follow-up commit should close B.1.

## How this was verified

| Check | Method | Result |
|---|---|---|
| Full suite | `pytest` in a clean worktree at `72bd8c3`, PostgreSQL 16.15, fresh UTF-8 database | 116 passed in 17.4 s |
| Two-phase real process | Phase 1: 45 s run of `python -m src.main` against fake Loki/vLLM/Chat (5 scenarios + 400-event burst, escalation wave, injection payload, model switched to "obey the injection"), then SIGTERM. Phase 2: restart on the same database with two new blocked probes from sources whose episodes were restored, 30 s, SIGTERM. The fake Loki records the rendered LogQL; `/metrics` and `/health/ready` scraped in both phases | Table below |
| Aggregator probes | Two targets from one source; same target rejoining after an idle gap; restored episode plus one new event through the rule engine | D2 fixed; D5 regression found |
| Metrics updater SQL | The updater's two queries run directly against the e2e database | Both fail: relation does not exist |
| Report transcript | Test IDs in `gate-b1-report.md` compared with `pytest --collect-only` at `72bd8c3`; Docker transcript compared with the committed Dockerfile; version manifest compared with `requirements.txt` | Mismatches (Defect B) |
| Docs | README, runbook, data dictionary, ADR and report checked against code for the M7 list | See M7 |
| Docker build | Not verifiable here (no daemon); image contents verified by reading the Dockerfile | D1 fix confirmed by reading |

### Two-phase real-process run on `72bd8c3`

| Signal | Observed |
|---|---|
| Shutdown | SIGTERM, exit code 0, 0.32 s (phase 1) and 0.26 s (phase 2); "Service terminated gracefully"; no tracebacks, no `[ERROR]` lines |
| Rendered LogQL | `{service_name="forticlient"} \|~ "type=\"utm\"\|type=\"event\"\|action=\"deny\"\|utmaction=\"block\""` on all 27 windows; windows monotonic; checkpoint key `...#security_events@v1` |
| Migrations | `001`, `002`, `003_phase_b`, `004_phase_b1` applied on an empty database |
| Phase 1 outcome | 4 incidents; revisions contiguous; 2 of 2 jobs `COMPLETED` on attempt 1; 4 outbox rows `SENT` with priorities 10/20; `model_runs` rows `COMMITTED`; injected quarantine stripped and `DEFAULT_ACTION_APPLIED`; cards clean |
| Restore | Phase 2 log: "Restored 6 open episodes"; episode `event_count` continued (1 to 2, 13 to 14) |
| **Regression** | Incident `198.51.100.99` was `CRITICAL / MIXED` at revision 3 (`MODEL_VALIDATED`). After the restart and one blocked probe it got revision 4 `MEDIUM` (`DETERMINISTIC`, rule `RULE_PORT_SCAN_MULTI_SERVICE` only) and `incidents.severity` is now `MEDIUM` |
| Gauges | Loki, model and chat ages are set and age correctly; backlog and oldest-job gauges never set (updater SQL fails) |
| Readiness | 200 `ready` in both phases |
| Episodes table | All 6 rows still `OPEN` after both phases (nothing idled out within the run; closing paths exist and are unit-tested, not exercised here) |

## Status per plan item

| Item | Status | Evidence |
|---|---|---|
| D1 migrations in image, hard fail, CI smoke job | **Fixed** in Dockerfile, `database.py`, `ci.yml`; `schema.sql` deleted. **Smoke script broken** (Finding 3) |
| D2 campaign keying | **Fixed.** Probe: two targets give two incidents; same target rejoins after an idle gap with a new episode id; closed ids are popped |
| D3 profile wired, carry-over | **Fixed.** Rendered LogQL carries the filter; carry-over code present (not exercised, no bare checkpoint existed) |
| D4 cooperative shutdown | **Fixed** in code and observed. **Acceptance test not added**: the branch e2e still calls `proc.kill()` and asserts nothing about the exit code |
| D5 episode persistence | **Partly fixed.** Close and restore paths exist with PostgreSQL tests; counts and signatures restored. **Restored evidence is ignored once a new event arrives, which demotes incidents** (Defect A) |
| D6 real transcript | **Not fixed** (Defect B) |
| D7 tests for security modules | **Fixed.** validator 16 tests (13 reason codes), redaction 7, eligibility 8, signatures 5, single-call workflow 4 (400 fallback, one repair, repair failure, metadata), persistence 3, digest 1, model_runs 2, aggregator 2. `_apply_guardrails` and its test removed |
| M1 unreachable rules | **Fixed** in `rules.yaml`. **`alerts.yml` inert** (Finding 2) |
| M2 freshness gauges, degraded | **Partly fixed.** Three ages work; backlog and jobs gauges never set (Finding 1); degraded flag now set after 3 consecutive failures |
| M3 default action | **Fixed** and observed (`DEFAULT_ACTION_APPLIED`) |
| M4 model_runs before transition | **Fixed.** `PENDING` then `COMMITTED`/`CONFLICT`/`FAILED`; two `COMMITTED` rows observed |
| M5 digest filter | **Fixed** (routing derived from the latest revision or rule ids; URGENT incidents excluded) |
| M6 build gate | **Fixed** (`configured_build` required and equal) |
| M7 docs and naming | **Partly fixed.** Internal hosts removed from settings defaults; ADR renamed. **ADK alias retained** (Finding 4); remaining doc errors listed under M7 below |
| L items | `http_method` cleaned; 408 retryable; HTTP-date `Retry-After`; event logs store `dstip` NULL and key on `*`; `attacker is` removed from the forbidden pattern |

## Blocking

### Defect A: a restart plus one blocked probe demotes a CRITICAL incident

`RuleEngine._evaluate_condition` uses the restored `signatures` and `enforcement_counts` only
when `episode["restored"]` is true **and** `events` is empty. The moment one new event arrives,
evaluation falls back to the live event list, which for a restored episode contains only the new
event. In the real run, the escalated incident (13 events, IPS `detected` plus denies, `CRITICAL
/ MIXED`, model-validated) received one more deny after the restart; only
`RULE_PORT_SCAN_MULTI_SERVICE` matched, and the poller wrote revision 4 with severity `MEDIUM`,
overwriting `incidents.severity` and `deterministic_severity`. Direct probe: a restored
non-blocked exploit episode plus one deny evaluates to no rules at all (`severity_floor LOW`).

Two fixes, both required:
1. Engine: when `restored` is true, always merge the stored `signatures` and `enforcement_counts`
   into the evaluation (treat them as evidence of UTM presence and enforcement mix) regardless of
   whether new events exist.
2. Poller: severity on an incident is monotonic. A deterministic re-evaluation may add rules or
   raise severity; it must never write `severity` or `deterministic_severity` below the incident's
   current value. Lowering severity is a Phase D analyst action, not a side effect of a restart.

Acceptance tests: (a) PostgreSQL round trip: persist a CRITICAL MIXED episode, restore, add one
deny, evaluate; rules still include `RULE_NONBLOCKED_EXPLOIT_ATTEMPT` and the floor is CRITICAL.
(b) Poller unit test: existing incident CRITICAL, rule evaluation returns MEDIUM; the transition
writes no revision and leaves severity CRITICAL. (c) Extend the branch e2e to the two-phase shape
used here (SIGTERM, restart on the same database, new events) and assert no incident's severity
decreased across the restart.

### Defect B: the report's transcripts are still not from the pushed commit

- Test listing: 5 IDs that do not exist at `72bd8c3` (four in
  `tests/integration/test_health_routes_pg.py`, a file not in the commit, and
  `test_model_run_recorded_and_committed_pg`) and 6 real tests missing (four investigation-loop
  tests, `test_model_run_committed_on_successful_transition_pg`,
  `test_url_query_values_stripped_and_keys_kept`). The count of 116 matches; the content does not.
- Docker transcript shows `pip install --no-deps --require-hashes`; the committed Dockerfile has
  `--no-cache-dir --require-hashes`.
- Version manifest lists pydantic 2.7.4, FastAPI 0.111.0, uvicorn 0.30.1, asyncpg 0.29.0,
  httpx 0.27.0: those are the lower bounds of the pre-Phase-B range specs. `requirements.txt`
  pins 2.12.5, 0.128.8, 0.39.0, 0.31.0, 0.28.1.

This is the third report in a row where the evidence came from a tree other than the one pushed.
Fix the process, not just the text: add `scripts/make_phase_report.sh` that runs the suite and
the e2e from a clean checkout of `HEAD`, writes the transcript and `pip freeze` into the report
file, and records `git rev-parse HEAD` at the top. Reports are generated, never typed.

## Findings that make "done" items inert

1. **Metrics updater queries non-existent tables.** `_run_metrics_updater` selects from
   `normalized_events` and `investigation_jobs`; the tables are `selected_events`
   (`processing_status = 'PENDING'`) and `jobs`. Both queries raise `UndefinedTableError` every
   5 s, caught and logged at DEBUG, so `forti_backlog_pending_events` and
   `forti_jobs_oldest_pending_seconds` are never set. Add a unit test that calls the updater once
   against PostgreSQL and asserts both gauges change.
2. **Every alert in `dashboards/alerts.yml` references a metric that does not exist.** The rules
   use `forti_intel_parser_errors_total`, `forti_intel_loki_last_success_age_seconds`,
   `forti_intel_coverage_gaps_total`, `forti_intel_backlog_pending_events` and
   `forti_intel_model_consecutive_failures`. Registered names use the prefix `forti_`, and no
   consecutive-failures metric exists (add `forti_model_consecutive_failures` as a gauge set from
   `_consecutive_model_failures`, or alert on `forti_model_last_success_age_seconds`). Add a test
   that parses `alerts.yml` and asserts every metric name in every `expr` is registered.
3. **`scripts/compose_smoke.sh` cannot run.** It calls `docker compose build forti-intel`,
   `docker compose exec forti-postgres` and `-d forti_intel`; the compose services are `app` and
   `postgres` and the database defaults to `forti_intelligence`. The CI job is correct; the
   operator script is not.
4. **ADK naming was aliased, not removed.** `src/investigation/adk_workflow.py` is a re-export
   shim, `single_call_workflow.py` ends with `ADKInvestigationWorkflow =
   SingleCallInvestigationWorkflow`, `main.py` still imports `ADKInvestigationWorkflow`, stores
   it as `self.adk_workflow`, and its loop docstring still reads "using Google ADK and local
   Qwen"; the metric help text says "ADK local Qwen investigation"; `schemas.py` says "bounded
   ADK investigation". Delete the shim and the alias, rename the attribute, fix the three strings.
5. **D4 acceptance test missing.** The branch e2e still calls `proc.kill()` after a 5 s wait and
   asserts nothing about the exit code. Replace with `proc.wait(timeout=5)` and
   `assert proc.returncode == 0`, no `kill()`.

## M7: documentation (what remains)

The documentation audit (appendix below) checked every M7 item from the Phase B review against
the code at `72bd8c3`. The simple items are fixed: the Loki env var name, the checkpoint column
name, the `selected_events` column list, the runtime ADK claim in the ADR, and the internal
hosts in the README and ADR. More than half of the list is still wrong, and the report's own
claim that M7 is done "with all internal IPs sanitized" is contradicted by the report itself.

Two items are repo hygiene, not prose, and belong in the follow-up commit:

- `.env.example` (lines 10, 23, 37) still carries an internal Loki hostname, an internal vLLM
  IP and an internal Grafana hostname, and the README tells operators to copy it. The same
  Grafana hostname is the code default at `config/settings.py:76`. Replace all four with
  placeholders such as `https://loki.example.internal`.
- `docs/reports/gate-b1-report.md` (lines 6 and 188) prints a container-network IP, and
  lines 54 and 56 print host-specific `/opt/...` paths. The generated-report script from
  Defect B should run from a clean checkout so neither can appear.

## Low

- `forti_model_last_success_age_seconds` reads 0 on a fresh process until the first model call;
  export nothing (or NaN) until a success exists so dashboards do not show a false "fresh".
- The `security_events` filter does not include traffic `action="dropped"`; harmless today
  (normalizer treats it as BLOCKED only if it arrives), worth adding for completeness.
- `last_urgent_at` for the escalated incident was NULL after phase 1 although an URGENT card was
  sent at revision 2, and set after phase 2; the cooldown bookkeeping is not consistent between
  the poller path and the investigation path.

## To exit B.1

One follow-up commit:
1. Defect A (engine merge + monotonic severity guard + the three tests).
2. Defect B (generated report from the pushed commit; `scripts/make_phase_report.sh`).
3. Findings 1 to 5.
4. Remaining M7 doc items from the appendix.

Then I re-run the same checks (suite, two-phase real-process run, probes, transcript diff).

## Operator actions (unchanged)

Rotate the Loki credential from `a014c67` and the dev Postgres password. The current branch can
be deployed to a lab database but not to production until Defect A is fixed.

## Appendix: documentation audit at `72bd8c3`

Every M7 item from the Phase B review, checked against the code in a fresh worktree of
`72bd8c3`. Line numbers refer to that commit. Internal hostnames and IPs are not reproduced
here; the lines are cited instead.

### README.md

| Item | State | Evidence |
|---|---|---|
| Loki env var name | FIXED | `LOKI_USER` |
| Ingest claim (line 10) | STILL WRONG | Names only `type="utm"` and traffic `action="deny"`. The wired profile (`src/sources/query_profiles.py:96`, default at `config/settings.py:68`, applied at `src/main.py:117`) also matches `type="event"` and `utmaction="block"`. Line 84 describes it correctly; line 10 does not |
| "Contextual traffic enrichment is queried on-demand directly from Loki" (line 10) | STILL WRONG | `TRAFFIC_CONTEXT_PROFILE` is defined and registered (`query_profiles.py:120`, `:138`) and nothing in `src/` calls it |
| Liveness "200 when supervisor tasks are running" (line 107) | STILL WRONG | `src/observability/metrics.py:127` returns `{"status":"alive"}` unconditionally |
| Readiness semantics (line 110) | FIXED, incomplete | Matches the lag check. Not mentioned: a poller that has never succeeded skips the lag check and reports ready (`metrics.py:143`), and a degraded model still returns 200 (`metrics.py:148`) |
| `file:///opt/...` links (line 128) and host path as tree root (line 22) | STILL WRONG | Unchanged |
| Internal hosts, IPs, passwords | FIXED in the README; NOT FIXED in what it points to | README line 125 uses placeholders. Lines 94 to 96 tell operators to copy `.env.example`, which still carries an internal Loki hostname (line 10), an internal vLLM IP (line 23) and an internal Grafana hostname (line 37). The Grafana hostname is also the code default at `config/settings.py:76` |

### docs/runbook.md

| Item | State | Evidence |
|---|---|---|
| Slice setting (line 56) | PARTLY | Name corrected to `LOKI_SLICE_SECONDS`; default stated as 15 s, code default is 30 (`config/settings.py:43`) |
| Bootstrap lookback (line 57) | PARTLY | Old env name gone; default stated as 600 s, but `src/main.py:113` passes `default_bootstrap_seconds=60`. The report's own log line (`gate-b1-report.md:193`) shows 60 |
| Checkpoint column in SQL | FIXED | `last_queried_ts_ns` |
| Rewind SQL (line 72) | STILL WRONG | `WHERE stream_name LIKE '%utm_detections%'` matches nothing; the live key is `<selector>#security_events@v1` (`query_profiles.py:39`, `settings.py:68`) |
| Stream key format (line 55) | FIXED | |
| Dead-letter "after 10 attempts" (line 102) | OFF BY ONE | `CASE WHEN attempts >= 10` at `src/storage/repository.py:1134` and `:1147` tests the pre-increment value, so the row dead-letters on the 11th failure |
| 429 and 408 handling (line 101) | STILL WRONG | Says a missing `Retry-After` falls back to exponential backoff with jitter; code uses a fixed 3.0 s (`src/notifications/outbox_worker.py:126`, `:138`). Says 408 honours `Retry-After`; code sends 408 to the exponential branch without reading the header (`:141` to `:145`) |
| `MODEL_FALLBACK` (line 94) | STILL WRONG | The written value is `MODEL_REJECTED_FALLBACK` (`single_call_workflow.py:294`, `:300`; `repository.py:1034`) |
| Degraded readiness (line 95) | FIXED, wrong body | Reachable now (`src/main.py:505` to `:508`, `:579` to `:581`). Documented body `{"status":"degraded","model":"degraded"}`; actual body `{"status":"degraded","database":"connected","note":...}` (`metrics.py:149`) |
| 503 body says `poller_lagging` (line 85) | WRONG (new) | Actual body is `"Poller lag exceeded 3x interval"` (`metrics.py:145`) |
| Poller "backs off with exponential jitter" (line 86) | WRONG (new) | Retries at a fixed `loki_poll_interval_seconds` (`src/main.py:453`); no backoff in `loki_client.py` or `checkpoints.py` |
| "Qwen 2.5" (line 9) | WRONG (new) | Configured model default is `qwen3.8-27b` (`settings.py:53`) |
| Internal hostnames | FIXED | |

### docs/data-dictionary.md

| Item | State | Evidence |
|---|---|---|
| `selected_events` columns and types | FIXED | All 31 columns match migrations 001 to 003 (`utmaction`, `signature_truncated`, nullable `dstip`) |
| `direction` enum (lines 19, 95) | STILL WRONG | Lists `INTERNAL`; code emits INBOUND, OUTBOUND, LATERAL, EXTERNAL, UNKNOWN (`src/parsing/normalizer.py:128` to `:153`) |
| `processing_status` lists `FAILED` (line 42) | MINOR | Only PENDING and PROCESSED are written (`repository.py:220`, `:232`, `:237`) |
| `query_checkpoints` | FIXED, omission | Columns and primary key correct; the UNIQUE constraint on `stream_name` (migration 001 line 5), which is the upsert key (`repository.py:48`, `:56`), is not mentioned |
| Incident `status` (line 122) | STILL WRONG | Lists SUPPRESSED and two CLOSED_* values; only `ACTIVE` is ever written (`src/main.py:313`, `:537`) |
| `exploitation_assessment` | FIXED | Matches the Literal at `schemas.py:9` |
| `assessment_source` (line 154, section 2.3) | STILL WRONG | Omits `RATE_LIMITED`, written at `src/main.py:389`. Marked not-null; migration 002 line 33 makes it nullable |
| `job_type` (line 172) | STILL WRONG | Lists `INVESTIGATION` and `DIGEST_BATCH`; the only value written is `INVESTIGATE_INCIDENT` (`src/main.py:402`). Job status `SUPERSEDED` (line 175) is never written |
| `model_runs.validation_result` (line 207) | STILL WRONG | Lists VALID, REPAIRED, INVALID, FALLBACK; code writes VALID, REPAIRED, REJECTED, TIMEOUT, ERROR (`single_call_workflow.py:173`, `:287`, `:291`, `:301`) |
| `commit_status` | FIXED | |
| `coverage_gaps`, `rejected_events`, `episodes`, `model_runs` tables | FIXED, one phantom | All documented. `coverage_gaps.resolved` is described as set by a "backfill worker"; no such worker exists and nothing sets the column |
| `schema_migrations` | MISSING | Created at `src/storage/database.py:301` to `:304`, not documented |

### docs/adr/001-bounded-single-call-workflow.md

| Item | State | Evidence |
|---|---|---|
| Runtime ADK claim | FIXED in the ADR | Scoped to Phase C (line 12). Code comments still say "using Google ADK" (`src/main.py:456`) and "ADK local Qwen" (`metrics.py:58`); see Finding 4 |
| Latency bound (line 19) | PARTLY | The 90 s claim is gone, replaced by "60 s timeout per call with up to one repair attempt". The workflow can make three sequential 60 s calls: the `json_schema` call (`single_call_workflow.py:199`), the `json_object` re-call on HTTP 400 (`:205`, `:211`), and the repair call (`:266`). Worst case is about 180 s, which exceeds the 90 s job lease at `src/main.py:461`. Either document 180 s and lengthen the lease, or share one deadline across the three calls |
| Internal IPs | FIXED | |

### docs/reports/gate-b1-report.md

| Item | State | Evidence |
|---|---|---|
| Internal IPs | STILL WRONG | A container-network IP is printed at lines 6 and 188, while line 45 claims "all internal IPs/passwords sanitized" |
| Host paths | STILL WRONG | `/opt/firewall-log-analysis-agent/.venv/bin/python3` (line 54) and `rootdir: /opt/firewall-log-analysis-agent` (line 56) |
| Credential strings | FIXED | None in the docs. The CI-only password in `.github/workflows/ci.yml` and `tests/integration/` is a test fixture, acceptable |
| Metric names cited at line 22 | FIXED | Both exist (`metrics.py:93`, `:98`) |
| `dashboards/alerts.yml` | STILL WRONG | All five expressions use `forti_intel_*` names (lines 5, 14, 23, 32, 41); registered names use `forti_` (`metrics.py:42`, `:47`, `:93`, `:108`). `forti_intel_model_consecutive_failures` exists under no prefix: the count lives in `self._consecutive_model_failures` (`src/main.py:152`, `:506`) and is never exported. `forti_coverage_gaps_total` is never incremented (no `.inc()` caller), so that alert cannot fire even with the right name. The report marks M1 and M2 done with `alerts.yml` in scope (lines 39, 40). See Finding 2 |
| Commit cited (line 4) | WRONG | Cites `5512a46`, which does not exist on the branch; HEAD is `72bd8c3`. Consistent with Defect B |
| Version manifest (lines 234 to 241) | WRONG | Python 3.9.16, Pydantic 2.7.4, FastAPI 0.111.0 and so on contradict the pins in `requirements.in` and the Dockerfile's `python:3.12-slim`. Consistent with Defect B |

### What the follow-up commit must change for M7

1. `.env.example` and `config/settings.py:76`: placeholders only.
2. README lines 10, 22, 107, 110, 128.
3. Runbook lines 9, 56, 57, 72, 85, 86, 94, 95, 101, 102.
4. Data dictionary: `direction`, incident `status`, `assessment_source`, `job_type`, job
   `status`, `validation_result`, `processing_status`, the `stream_name` UNIQUE constraint, the
   `coverage_gaps.resolved` sentence, and a `schema_migrations` entry.
5. ADR line 19: state the real worst case and fix the lease, or bound the three calls by one
   shared deadline (the latter is the better fix and is two lines in the workflow).
6. The report: regenerate per Defect B; the IPs and host paths disappear with it.
