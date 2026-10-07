# Phase A.1 review: `feature/gate-a1-critical-fixes` (commit `e8c2e3e`)

**Verdict: not ready to exit A.1 — one blocking defect, verified fix attached.**

Phase A.1 fixed what it set out to fix: the checkpoint advances, the investigation worker no longer crashes on PostgreSQL, enforcement is pinned to deterministic facts, secrets stay out of logs, cards are escaped, and the FortiOS action semantics are right for every scenario in the brief. All 50 tests pass here against PostgreSQL 16 (`50 passed in 18.75s`). But the new revision handling introduced a defect that stops most model investigations from ever completing, and the in-repo end-to-end test does not assert the thing that would have caught it. Fix that, add the missing assertion, and A.1 is done.

## How this was verified

- Full suite in a clean worktree against a local PostgreSQL 16 (`TEST_DATABASE_URL`), not SQLite.
- An independent 60-second run of the real `python -m src.main` process (not in-process) against the branch's own fake Loki/vLLM/Chat endpoints, with the five brief scenarios plus a 400-event burst in wave 1, then an escalation (non-blocked IPS from the scanner source, with a prompt-injection payload in `msg`), a late-arriving 30-second-old event, and the fake model switched to `injection_obeying` in wave 2. The webhook URL carried a fake `key=`/`token=` to check for leaks. Every Loki query window was recorded by a middleware to check checkpoint monotonicity.
- Targeted probes for the revision defect on both SQLite and PostgreSQL.

## Verified status per item

| Item | Status | Evidence (executed) |
|---|---|---|
| A1.1 checkpoint | **Fixed** | 22 query windows, end timestamps strictly non-decreasing, lag 6.4 s at end of run; `save_checkpoint` uses `GREATEST`/`MAX` plus an assertion; catch-up capped at 10 slices; saturation records a gap and cannot livelock |
| A1.2 worker crash | **Fixed** | No `DataError`; `to_utc_datetime` applied; `fail_job` with 30 s×2ⁿ backoff; lease predicate has `attempts < max_attempts`; FAILED jobs write a `MODEL_REJECTED_FALLBACK` revision |
| A1.3 model-controlled enforcement | **Fixed** | Fake model returned `enforcement=BLOCKED`; stored incident and revision say `MIXED`, `model_reported_enforcement=BLOCKED`; material change computed from deterministic facts; cooldown and per-source/target rate limits present |
| A1.4 revision CAS / fencing | **Implemented, but see defect 1** | `UPDATE … WHERE current_revision = $expected RETURNING`, job fence in the same transaction, `FOR UPDATE` on the incident row |
| A1.5 over-length values | **Fixed** | Migration `002_text_columns.sql` converts free-text columns to `TEXT`; signature truncated at 512 with a flag; batch failure falls back row-by-row into `rejected_events`; ordered migration runner with `schema_migrations` |
| A1.6 secrets and logging | **Fixed** | `httpx`/`httpcore` at WARNING, `SensitiveDataFilter` on root handlers, outbox errors URL-redacted; `SECRETKEY123`/`SECRETTOKEN456` absent from the run log; `.env.example` `GCHAT_DRY_RUN=true`; compose `:?` guard; default password removed from `settings.py`; startup validation present |
| A1.7 card escaping | **Fixed** | `html.escape` on every field; injected `<a href>` and "ignore previous instructions" never appeared in any card; static fallback summary; SSL reason static; external icon removed |
| A1.8 quarantine / CLI | **Partial** | CLI never rendered (`cli_recommendations_enabled=false`); model path and fallback no longer recommend quarantine. **But** the deterministic URGENT card still lists `Manual review: ACT_QUARANTINE_SRC_IP` for every HIGH/CRITICAL incident (`src/main.py:284`) — 2 of 3 cards in the run, including one for a MIXED source. The brief said to remove it from both places |
| A1.9 action semantics | **Fixed (semantics); Partial (provenance)** | IPS `dropped`+accepted traffic → no incident; `drop_session` → BLOCKED; AV blocked → MEDIUM/DIGEST; MIXED needs UTM on both sides and routes INVESTIGATE; scanner needs INBOUND and untrusted source; benign host → nothing. **But** every entry in `config/action_map.yaml` says `verified: true` with a generic provenance string ("FortiOS Log Reference - …"); none cites a document version, section, or sample fixture. The brief asked for `verified: false` on anything not actually cited |
| A1.10 tests / CI | **Partial** | Unit, integration and e2e tests exist and pass on PostgreSQL; CI has a `postgres:16` service. **But** the e2e test runs `IntelligenceService` in-process rather than `python -m src.main`, and asserts nothing about revision contiguity or job completion, which is why defect 1 passed CI |

End-to-end scenario table from the independent run (before the fix below):

| Scenario | Expected | Observed |
|---|---|---|
| Benign internal host | no alert | no incident ✔ |
| Non-blocked IPS vs VIP | CRITICAL urgent + model update | CRITICAL urgent ✔; **model update never delivered** (job failed with `RevisionConflict`, see defect 1) ✘ |
| IPS-dropped exploit + accepted traffic | no urgent | no incident ✔ |
| Internal AV-blocked download | no urgent | MEDIUM/DIGEST, no card ✔ |
| 12-deny scanner | digest | MEDIUM/DIGEST, no card ✔ |
| Scanner source escalates to non-blocked IPS | new URGENT, enforcement pinned | URGENT at CRITICAL/MIXED, model's `BLOCKED` overridden ✔ (job completed only because it was leased within 3 s) |
| 400-event burst, late arrival | all ingested | 400/400 and 1/1 ingested, 0 pending, 0 rejected ✔ |
| Checkpoint | monotonic | monotonic, 22 windows ✔ |
| Secrets in log | none | none ✔ |

## Defect 1 (blocking): every poll advances `current_revision`, so investigation jobs conflict and fail

**Where.** `src/storage/repository.py:459` allocates `new_rev = current_rev + 1` on every call to `record_incident_transition`, whether or not a `revision` row is being written. `src/main.py:343` calls it on every poll for every active episode with a matched rule, and `SessionAggregator.process_events` returns every active episode, not only those that received events. Investigation jobs commit with `expected_revision=trigger_rev` (`src/main.py:490`).

**Proof.**
- Probe (SQLite and PostgreSQL, identical): one incident, three no-change transitions → `incidents.current_revision` 1→2→3→4 with revision rows `[1]`; a job commit with `expected_revision=1` then raises `RevisionConflict`.
- Real-process run: after 60 s with a 3 s poll, incidents sat at revisions 6–7 with 1–3 revision rows each. The scenario-2 job logged `Incident INC-F5C99EAC57D2 current revision is 5, expected 1`, was backed off 60 s, and never completed. The model had already been called, so each retry costs a full inference.

**Impact.** In production (15 s poll) any incident whose episode is still receiving events when the worker leases its job will conflict; after three backed-off retries the job is marked FAILED and the incident gets a `MODEL_REJECTED_FALLBACK` revision. Most investigations will end that way, after three wasted model calls each. The report's claim "Model investigation updates: one per urgent incident ✔" is not true and is not covered by any test.

**Verified fix** (applied to a scratch copy; 50/50 tests pass; revisions contiguous; both jobs COMPLETED; four outbox rows SENT; the full diff is at the end of this file):
1. `repository.py`: `new_rev = current_rev + 1 if revision is not None else current_rev`. A counts-only update must not allocate a revision.
2. `main.py`: build `touched = {(vd, direction, srcip, dstip) for ev in pending_events}` and skip episodes not in it, so untouched incidents are not rewritten every poll.
3. `main.py:284`: deterministic card recommends `ACT_INSPECT_APPLICATION_LOGS` only (closes A1.8).
4. `main.py:246`: add `"rule_ids": matched_rules` to `inc_data` so deterministic cards are titled with the rule instead of "Perimeter Detection".

**Required acceptance tests** (add to `tests/integration/test_investigation_loop_pg.py` and `tests/e2e/test_service_e2e.py`):
- Drive `_run_poller_loop` five times over an unchanged episode: `current_revision` unchanged, exactly one revision row.
- Then run `_run_investigation_loop` once with a valid mock model: job `COMPLETED` on the first attempt, exactly one `INVESTIGATION_UPDATE`, `current_revision` incremented by exactly one, revision numbers contiguous.
- E2e: assert for scenario 2 that the job is `COMPLETED`, an `INVESTIGATION_UPDATE` row exists, and `incident_revisions` numbers are contiguous; assert no card payload contains `ACT_QUARANTINE_SRC_IP`.

## Other findings

**Medium**
- `config/action_map.yaml`: replace the generic provenance strings with real citations (FortiOS Log Reference version and section, or the fixture file that shows the value) and set `verified: false` where you cannot. The semantics are right; the registry's claims are not yet.
- Rate-limit counters (`main.py:88-89`) are in memory, so a restart resets them. Acceptable for A.1; note it in the report and move the counters to the incident table in Phase B.
- Report accuracy: it names `migrations/002_a1_remediation.sql` (the file is `002_text_columns.sql`); it lists "Key Pinned Dependencies" but `requirements.txt` still uses `>=` ranges; it says Python 3.9.16 and CI uses 3.9 while the `Dockerfile` runs `python:3.12-slim`. Test on the runtime Python, or document why not.
- The e2e test should run the real process (`python -m src.main`) as the brief asked; signal handling, logging configuration and the startup validation are only exercised that way.

**Low**
- `OUTBOX_DELIVERED_TOTAL` is incremented twice per delivery (`outbox_worker.py:61` and `main.py:511`).
- `.env.example` has `LLM_MAX_OUTPUT_TOKENS=3500` while `settings.py` defaults to 1500.
- `normalize_action` (`normalizer.py:78-86`) falls back to scanning every namespace, so a traffic log could be resolved through the UTM table. Restrict the fallback to the type's `default` block.
- `README.md` and `docs/adr/001`, `004` still describe a multi-stage image, "<3 s" investigations, "zero risk" and ADK 1.18 in use. Scheduled for B10; fine to leave until then.
- `prune_stale_episodes` compares wall clock to event time; scheduled for B6.

## Operator actions (unchanged)
- Rotate the Loki credential leaked in commit `a014c67`.
- Supply the FortiOS build before enabling CLI rendering.
- Confirm vLLM structured-output support before Phase C.

## To exit A.1
1. Apply the fix below (or equivalent) on `feature/gate-a1-critical-fixes`.
2. Add the acceptance tests listed under defect 1.
3. Correct the action-map provenance and the report inaccuracies.
4. Re-run the suite against PostgreSQL and the real-process e2e; update `docs/reports/gate-a1-report.md` with the actual scenario table, including job and revision outcomes.

Then proceed to Phase B.

## Verified patch (scratch copy of `e8c2e3e`)

```diff
diff --git a/src/main.py b/src/main.py
index 6ad2839..0436f0d 100644
--- a/src/main.py
+++ b/src/main.py
@@ -195,8 +195,12 @@ class IntelligenceService:
                     episodes = self.aggregator.process_events(pending_events)
                     INCIDENTS_ACTIVE.set(len(episodes))
                     pending_ids = [ev["id"] for ev in pending_events]
+                    touched = {(ev.get("vd", "root"), ev.get("direction", "INBOUND"), ev["srcip"], ev["dstip"]) for ev in pending_events}
 
                     for ep in episodes:
+                        # Only episodes that received events in this batch can change
+                        if (ep.get("vdom", "root"), ep.get("direction", "INBOUND"), ep["source_ip"], ep["target_ip"]) not in touched:
+                            continue
                         rule_eval = self.rule_engine.evaluate_episode(ep)
                         matched_rules = rule_eval["matched_rule_ids"]
                         if not matched_rules:
@@ -260,6 +264,7 @@ class IntelligenceService:
                             "last_seen": ep["last_seen"],
                             "event_count": ep["event_count"],
                             "summary": "; ".join(rule_eval["reasons"]),
+                            "rule_ids": matched_rules,
                             "deterministic_severity": sev_floor,
                             "deterministic_enforcement": ep["enforcement"],
                             "deterministic_rule_ids": matched_rules,
@@ -281,7 +286,7 @@ class IntelligenceService:
                                     "severity": sev_floor,
                                     "enforcement": ep["enforcement"],
                                     "summary": f"[DETERMINISTIC PERIMETER ALERT - REV {next_rev}] {'; '.join(rule_eval['reasons'])}",
-                                    "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS", "ACT_QUARANTINE_SRC_IP"] if sev_floor in ("CRITICAL", "HIGH") else ["ACT_MONITOR_AND_DIGEST"],
+                                    "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"] if sev_floor in ("CRITICAL", "HIGH") else ["ACT_MONITOR_AND_DIGEST"],
                                 },
                                 "model_name": None,
                                 "reasoning_summary": "; ".join(rule_eval["reasons"]),
diff --git a/src/storage/repository.py b/src/storage/repository.py
index b2bee86..9a33b04 100644
--- a/src/storage/repository.py
+++ b/src/storage/repository.py
@@ -456,7 +456,9 @@ class Repository:
                     raise RevisionConflict(
                         f"Incident {incident['id']} current revision is {current_rev}, expected {expected_revision}"
                     )
-                new_rev = current_rev + 1
+                # Allocate a new revision only when a revision row is being written;
+                # a counts-only update must not advance current_revision.
+                new_rev = current_rev + 1 if revision is not None else current_rev
             else:
                 if expected_revision is not None and expected_revision > 0:
                     raise RevisionConflict(
```

_Note: the one traceback left in the fixed run is the uvicorn lifespan `CancelledError` on SIGTERM — shutdown noise, not a defect; cancel the uvicorn server task gracefully (`server.should_exit = True`) in `IntelligenceService.stop()` to silence it._
