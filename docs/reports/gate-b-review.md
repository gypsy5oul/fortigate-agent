# Phase B review: `feature/gate-b-honest-single-call` (commit `b552e02`)

Reviewer: Claude (Fable 5.1), 2026-10-07. Branch is based on `a030745` (A.1 with all three corrections, verified).

**Verdict: not ready to exit Phase B.** The outbox, validator, lock file and normalizer work are real and
verified. But the containerized deployment cannot start on a fresh database, incident identity is wrong
whenever one source touches two targets, the headline B1 feature (query profiles, on-demand enrichment)
is not wired into the running service, graceful shutdown no longer works, episode persistence is one-way,
the report's pytest transcript is not from this commit, and the new security modules have no tests.
Seven blocking items are listed under "To exit Phase B"; most are small.

## How this was verified

| Check | Method | Result |
|---|---|---|
| Full suite | `pytest` in a clean worktree at `b552e02`, PostgreSQL 16.15, fresh UTF-8 database | 70 passed in 21.8 s |
| Real process | Independent 60 s run of `python -m src.main` against fake Loki/vLLM/Chat (5 scenarios + 400-event burst, then escalation, late deny, injection payload, model switched to "obey the injection"); fake Loki now records the rendered LogQL | Table below |
| Lock file | Fresh venv, `pip install --dry-run --require-hashes -r requirements.lock` | Resolves, all hashes match |
| Docker build | Not verifiable here (no daemon). Image contents verified by reading the Dockerfile | See Defect 1 |
| Aggregator | Direct probes of campaign linking, restart restore, pruning | Defects 2 and 5 |
| Docs | Every checkable claim in README, runbook, data dictionary, ADR and gate-b report compared with code | Finding M7 |
| Secrets | Scan of every added line in the diff | Clean; A.1 report password is now `<redacted>` |

### Real-process run on `b552e02`

| Signal | Observed |
|---|---|
| Accepted traffic | 0 rows stored for the benign scenario; 417 of 420 staged lines stored (3 accept/close dropped) |
| Rendered LogQL | `{service_name="forticlient"}` only, on all 22 windows: no profile, no line filter |
| Incidents / revisions | 4 incidents; revisions contiguous `[1]`, `[1]`, `[1,2]`, `[1,2,3]` |
| Jobs / outbox | 2 of 2 jobs `COMPLETED` on attempt 1; 4 outbox rows `SENT` with priorities 10 and 20 |
| `model_runs` | 2 rows, `json_schema` mode, `VALID`; second carries `INELIGIBLE_ACTION_STRIPPED` x2 (injected quarantine removed) |
| Cards | No quarantine, no raw HTML, no injection text. **Last CRITICAL card shows "Recommended Actions: None"** (M3) |
| `episodes` table | 6 rows, all `OPEN`, none ever closed |
| Shutdown | SIGTERM logged, then no "shutdown received" / "terminated gracefully"; the harness killed the process after 15 s (Defect 4) |
| Log hygiene | No secrets, no `[ERROR]`, no tracebacks |

## Blocking defects

### Defect 1: the container image does not contain `migrations/`, so a fresh deployment runs on the wrong schema

`Dockerfile` copies `config/`, `src/` and `replay.py` only; `docker-compose.yml` mounts `config` and `src`.
`database.py` looks for `<src>/../../migrations`, which is `/app/migrations` in the image, does not find
it, and applies the fallback `src/storage/schema.sql`. That file has none of the A.1 or B tables and
columns (`rejected_events`, `episodes`, `model_runs`, `utmaction`, `signature_truncated`,
`assessment_source`, `deterministic_*`, `type_priority`, `retry_after_ts`). On a fresh database the
first `save_events` fails on the `utmaction` column, the row-by-row fallback fails on `rejected_events`,
and the outbox query fails on `type_priority`. The image "builds" but cannot ingest one event.

This is pre-existing from Gate A's Dockerfile, but Phase B is the phase that added migration 003 and
claimed "Container Build: validated". Fix: `COPY migrations/ /app/migrations/`, and make the fallback
a hard failure (log and exit) rather than silently applying a stale schema. Add a compose-level smoke
test to the brief's exit criteria: `docker compose up` against an empty volume, then `/health/ready`
200 and `schema_migrations` containing `003_phase_b`.

### Defect 2: campaign linking merges every target of a source into one incident

`SessionAggregator.recent_incidents` is keyed by `vdom:direction:source_ip` (no target), so a new
episode for the same source against a different target within 30 minutes inherits the first
episode's `incident_id`. Probe: `203.0.113.5 -> 10.0.14.120` then `-> 10.0.14.121` ten seconds later
produced **the same `incident_id` for both**. Two live episodes then write the same `incidents` row with
different `target_ip`, `enforcement` and `event_count`, the row flip-flops between targets, revisions
churn, and cards label the wrong target. The report says the window is keyed by
`(vdom, direction, source_ip, target_ip)`; the code is not. Fix: key `recent_incidents` by the full
tuple (campaign-across-targets, if wanted, belongs in a separate `campaign_id` column, never in
`incident_id`).

### Defect 3: query profiles and on-demand traffic enrichment are not wired

`main.py` builds `PollerOrchestrator` without `query_profile`; `settings.loki_query_profile` is read
nowhere; `TRAFFIC_CONTEXT_PROFILE` has no caller. The rendered LogQL in my run is the bare selector.
B1's "line filter optimization" and "contextual traffic enrichment queried on demand" exist only as
definitions and unit tests. Worse, the only security profile, `utm_detections`, filters to
`type="utm"`, so wiring it as-is would blind `RULE_HIGH_FREQUENCY_SCANNER` (traffic denies) and the
deny+detected `MIXED` path. Either add a `security_events` profile (`utm` OR traffic `deny` OR
`event`) and wire it with a checkpoint migration from the bare-selector stream, or remove the claim
and the dead code from this phase.

### Defect 4: graceful shutdown is broken

`_run_digest_loop` does `await asyncio.sleep(interval_secs)` with a 3600 s default, and the A.1
signal handler now waits for every loop to observe `running = False`. SIGTERM therefore never
completes; `docker stop` will SIGKILL after 10 s. Observed in my run (no "terminated gracefully"
line, killed after 15 s). The branch's e2e test hides it because it calls `proc.kill()` after 5 s.
Fix: sleep in short increments (or `asyncio.wait_for` on a shutdown `Event`) in every loop, and make
the e2e assert a clean exit code without `kill()`.

### Defect 5: episode persistence is one-way

- `episodes` rows are never set to `CLOSED`: `prune_stale_episodes` and the rotation path set
  `status` on the in-memory object only, and no repository method updates status. Every episode ever
  seen stays `OPEN` (6 of 6 in my run) and is restored on every restart, growing without bound and
  seeding campaign linking with stale incidents.
- `load_open_episodes` restores identity and timestamps but not `enforcement_counts`, `events` or
  `event_count`. Probe: an episode with 12 events restored and given one new event reports
  `event_count = 1`, so the next transition writes a smaller `event_count` onto the incident.
Fix: persist `CLOSED` on prune/rotation, restore only episodes whose `last_seen` is within the idle
window, and restore `event_count`/`enforcement_counts` (or treat restored episodes as count-only
carriers).

### Defect 6: the Phase B report's pytest transcript is not from this commit

`gate-b-report.md` lists 68 test IDs; 30 of them do not exist anywhere in the repository's history
(for example `test_query_profile_threat_detection_rendering`, `test_parse_profile_tag`, all eight
`test_rules` names, all four `test_storage` names) and the two e2e tests that do exist are absent.
The count of 70 happens to match. The real suite does pass here, but a report whose evidence is
synthesized cannot be used as an exit record. Re-run and paste the actual output; the brief's
reporting rule ("prove by execution") applies to the report itself.

### Defect 7: the new security logic has no tests

Zero test files reference `validate_assessment`, `redact_evidence_record`, `wrap_untrusted_evidence`,
`redact_url`, `get_eligible_actions`, `is_action_eligible`, `get_grounded_cves`, `save_episodes`,
`load_open_episodes`, `get_digest_summary`, `build_digest_gchat_card`, the `json_schema` to
`json_object` fallback, the repair loop, or `model_runs`. The only workflow test exercises
`_apply_guardrails`, which is now dead code. The brief specified acceptance tests per B item; the 19
added tests cover profiles (unwired), rules (partly unreachable, M1) and the outbox (good).

## Medium findings

- **M1. Rules that cannot fire in production.** `RULE_DISTRIBUTED_ATTACK` needs `source_ips`, which
  no episode ever carries (episodes are single-source by construction). The four `health_metric` rules
  need a `health_metric` field that nothing produces. Their tests pass by hand-crafting those fields.
  Either generate target-centric and health episodes or remove the rules; a rule pack that advertises
  detections it cannot make is a false sense of coverage.
- **M2. Freshness gauges and degraded state are hollow.** `forti_loki_last_success_age_seconds`,
  `forti_model_last_success_age_seconds`, `forti_backlog_pending_events` and
  `forti_jobs_oldest_pending_seconds` are never set; the Chat gauge is set to 0 on success and never
  ages; `service_state["model_degraded"]` is never set true, so `/health/ready` can never report
  `degraded`. Four of the new dashboard panels show nothing. Keep last-success timestamps and compute
  ages in a 5 s updater task.
- **M3. CRITICAL card with no recommended action.** When the validator strips every recommended
  action (observed with the injection-obeying model), the card renders "Recommended Actions: None".
  A.1 defaulted to `ACT_INSPECT_APPLICATION_LOGS`; restore that default after stripping.
- **M4. `model_runs` row is lost when the transition fails.** The audit row is written only inside the
  successful `record_incident_transition`; a `RevisionConflict` or fence failure after a real model
  call leaves no audit trace. Write the audit row before the transition (append-only), or in `fail_job`.
- **M5. Digest content.** `get_digest_summary` selects every incident updated since the last digest,
  including URGENT ones already alerted, and labels the incident count "events". Filter to
  DIGEST-routed incidents and count events.
- **M6. Eligibility build check is inverted when `FORTIOS_BUILD` is unset.** `verified_build is None
  or (configured_build and verified_build != configured_build)` makes any catalog entry with a
  `verified_build` eligible when the operator never set `FORTIOS_BUILD`. Latent today (both perimeter
  actions have `verified_build: null`). Require `configured_build` to be set and equal.
- **M7. Documentation is not reliable for operators.** Highlights (full list available on request):
  README names `LOKI_USERNAME` (code: `LOKI_USER`) and says "Ingests type=utm + traffic denies"
  (the whole stream is polled); runbook names `LOKI_TIME_SLICE_SECONDS` (code: `LOKI_SLICE_SECONDS`,
  30 s), `LOKI_BOOTSTRAP_LOOKBACK_SECONDS` (does not exist), column `last_seen_ts_ns` (actual
  `last_queried_ts_ns`), so both checkpoint SQL statements fail; runbook says the outbox dead-letters
  at 5 attempts (code: 10) and that 429 backs off exponentially (code: fixed 3 s without
  `Retry-After`); data dictionary omits 14 `selected_events` columns and three tables and lists
  enum values that are never written (`SUSPECTED_SUCCESS`, `MODEL_FALLBACK`, `INFORMATIONAL`); ADR
  states a 90 s model deadline (code: 60 s per call, up to three calls); README and ADR carry internal
  hostnames and IPs and a `forti_intel:password@172.18.0.2` connection string.

## Low findings

- `_apply_guardrails` is dead code but is what `test_adk_workflow.py` tests; the validator's
  `attacker is` forbidden pattern rejects ordinary phrasing ("the attacker is external"); the repair
  call uses `json_object` rather than `json_schema`.
- `redact_evidence_record` cleans `msg`, `user` and `user_agent`, none of which exist in the
  normalized event; the attacker-controlled free text that does reach the model is `url` (path kept)
  and `http_method`, and `http_method` is neither cleaned nor truncated. Delimiter escaping of
  `<<UNTRUSTED` and `<</UNTRUSTED>>` is correct.
- `docker-compose.yml` bind-mounts `./src` and `./config` over the hash-verified image, which defeats
  the point of `--require-hashes` for a hardened deployment; internal hostnames and IPs in
  `extra_hosts` are pre-existing.
- Any 4xx except 429 is dead-lettered, including 408; a date-valued `Retry-After` falls back to 3 s.
- `_metric()` reaches into `REGISTRY._names_to_collectors` (private API).
- Event-type logs with one missing IP are stored with a `127.0.0.1` placeholder, which becomes an
  episode key.
- `aiosqlite` and the SQLite code paths still ship in the runtime image.

## Verified as working

- Outbox: priority ordering (10/20/50), `retry_after_ts` gating, 5xx exponential backoff with jitter,
  429 `Retry-After`, permanent 4xx to `DEAD_LETTER`, 30 KB payload guard. Integration tests are real.
- Validator pins identity, enforcement and severity floor; strips ungrounded CVEs and ineligible
  actions; hard-rejects unsupported compromise claims; one bounded repair; deterministic fallback
  with reason codes. `json_schema` request with `json_object` fallback on HTTP 400 is correct.
- `model_runs` rows are written atomically with the model revision (two rows in my run).
- Normalizer drops `ALLOWED`/`SESSION_CLOSED` traffic; signature derives only from
  `attack`/`virus`/`vuln_name`; `normalize_action` cross-namespace fallback stays fixed.
- Parser handles RFC 3164/5424 prefixes and JSON envelopes.
- `requirements.lock` resolves with matching hashes; runtime image is multi-stage, non-root UID 10001,
  no curl; compose drops capabilities, read-only root, tmpfs, pids and resource limits.
- Dashboards are valid JSON with `| logfmt` before every aggregation and a `$service_name` variable.
- A.1 corrections (real counts-only test, redacted password, `accept` citation, cooperative SIGTERM)
  all landed in `a030745`.

## To exit Phase B

One follow-up commit on `feature/gate-b-honest-single-call`, then I re-verify:

1. Defect 1: ship `migrations/` in the image; fail hard when it is missing; add the compose smoke test.
2. Defect 2: key campaign linking by the full `(vdom, direction, src, dst)` tuple.
3. Defect 3: wire a `security_events` profile with checkpoint carry-over, or remove the profile code
   and claim from this phase.
4. Defect 4: interruptible sleeps in all loops; e2e asserts clean SIGTERM exit without `kill()`.
5. Defect 5: close episodes in the database and restore counts; cap restore to the idle window.
6. Defect 6: replace the report's transcript with real output from this commit.
7. Defect 7: tests for validator (each reason code), redaction (delimiter escaping, URL stripping),
   eligibility (trusted, NAT/CDN, expired scanner, build gate), signatures, episode persistence
   round-trip, digest summary, `model_runs` row, `json_schema` fallback and repair.
8. M1 to M3 (remove unreachable rules or make them reachable; real freshness gauges and degraded
   state; default action after stripping).

M4 to M7 and the Low items can ride the same commit or the start of Phase C.

## Operator actions

- Unchanged: rotate the Loki credential from `a014c67` and the dev Postgres password.
- Do not deploy the current image: it cannot create its schema (Defect 1).
