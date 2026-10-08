# Phase B.1 review: `feature/gate-b1-fix-pack` (commit `72bd8c3`)

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

Items from the Phase B review that are still wrong at `72bd8c3` are listed in the appendix
below (filled from the documentation audit). The ADR and settings defaults no longer carry
internal hostnames or IPs.

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
