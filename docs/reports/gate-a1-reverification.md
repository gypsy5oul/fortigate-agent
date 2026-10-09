# Phase A.1 re-verification: `feature/gate-a1-critical-fixes` (commit `2574e23`)

Reviewer: Claude (Fable 5.1), 2026-10-07. Follows `gate-a1-review.md` (review of `e8c2e3e`).

**Verdict: the blocking defect is fixed and verified. Phase A.1 may exit once three small
corrections land in one follow-up commit (listed under "To exit A.1"). No further review round
is needed from me for A.1; green CI on that commit is enough. Phase B may start.**

## How this was verified

Nothing in this report is taken from `gate-a1-report.md`; every claim below was reproduced here.

| Check | Method | Result |
|---|---|---|
| Full suite | `pytest` in a clean worktree at `2574e23`, PostgreSQL 16.15, fresh UTF-8 database | 51 passed in 20.8 s |
| Repository fix | Direct probe: 3 counts-only transitions (`revision=None`) after revision 1, then a job commit with `expected_revision=1` | `current_revision` stays 1, one revision row, job commit OK |
| Real process | Independent 60 s run of `python -m src.main` against fake Loki/vLLM/Chat (same harness as the previous review: 5 scenarios + 400-event burst, then a second wave with an escalation, a late-arriving deny, an injection payload, and the fake model switched to "obey the injection") | See table below |
| Mutation check | Reverted the one-line repository fix in the worktree and re-ran the two new tests | **Both still pass** (Finding 1) |

### Real-process run on `2574e23`

| Signal | Observed |
|---|---|
| Events stored vs. staged | 420 / 420 wave 1, 2 / 2 wave 2; 0 pending, 0 rejected, 0 coverage gaps |
| Incidents | 4; scanner escalation ends `CRITICAL / MIXED` at revision 3; main exploit `CRITICAL / ALLOWED_OR_DETECTED` at revision 2 |
| Revision rows | Contiguous per incident: `[1]`, `[1]`, `[1, 2]`, `[1, 2, 3]`; model revisions are `MODEL_VALIDATED` |
| Investigation jobs | 2 of 2 `COMPLETED`, `attempts = 1` each |
| Outbox | 4 rows, all `SENT`: URGENT + INVESTIGATION_UPDATE for each urgent incident |
| Cards | Titled with the matched rule; no `ACT_QUARANTINE_SRC_IP`; recommended action is `ACT_INSPECT_APPLICATION_LOGS` only; injected `<a href>` and "ignore previous instructions" never reach a card |
| Loki windows | 22 queries, strictly monotonic, lag 6.4 s at shutdown |
| Log hygiene | Webhook `key=`/`token=` never logged; no `[ERROR]` lines; one traceback (Finding 4) |

Compared with `e8c2e3e`, the difference is exactly what the fix was for: the scenario-2 job that
previously died on `RevisionConflict` after three model calls now completes on the first attempt.

## Status of the items from the previous review

| Item | Status on `2574e23` |
|---|---|
| Defect 1: `current_revision` advanced on every poll | **Fixed.** `repository.py` allocates a revision only when a revision row is written; `main.py` transitions only episodes that received events in the batch. Verified by probe and by the real-process run. |
| A1.8: deterministic card recommended quarantine | **Fixed.** `main.py` deterministic card now recommends `ACT_INSPECT_APPLICATION_LOGS` only; asserted in the e2e test and observed in my run. |
| A1.9: action-map provenance | **Mostly fixed.** Aliases are now `verified: false`; six entries cite fixtures by name. One citation is wrong (Finding 3). |
| A1.10: e2e runs in-process, no revision/job assertions | **Fixed.** `test_e2e_scenarios_and_service_lifecycle` spawns the real process with SIGTERM lifecycle and asserts job `COMPLETED`, `INVESTIGATION_UPDATE` row, revisions `[1, 2]`, and no quarantine. The outage test is still in-process, which is acceptable for its purpose. |
| `OUTBOX_DELIVERED_TOTAL` double increment | **Fixed** (import left behind, Finding 5). |
| `LLM_MAX_OUTPUT_TOKENS` mismatch | **Fixed** (settings default now 3500, matching `.env.example`). |
| `normalize_action` cross-namespace fallback | **Fixed.** Cross-namespace scan now only when no `type` is supplied. |
| Report inaccuracies | **Partly fixed.** Migration filename and Python-version wording corrected; "Key Pinned Dependencies" still lists installed versions while `requirements.txt` has ranges (Finding 6). |
| uvicorn `CancelledError` on SIGTERM | **Not fixed** by the change made (Finding 4). |

## Findings

### Finding 1 (Medium, fix before merge): the new integration test does not exercise the repository fix

`test_pg_unchanged_episode_poller_and_investigation_completion` step 3 builds `touched = set()`
and then skips every episode that is not in it, so `record_incident_transition(..., revision=None)`
is never called. The "five poller cycles" assertion is vacuous. The e2e test does not pin the
repository half either: with the `touched` filter in `main.py`, a single-batch scenario never
takes the counts-only path, so the revision bug in `repository.py` is invisible to it.

Proof: with the repository line reverted to `new_rev = current_rev + 1`, both new tests pass.

The verified replacement for step 3 is in the patch at the end of this report. With it, the
test passes on `2574e23` (0.6 s) and fails with the fix reverted (`assert 6 == 1`).

### Finding 2 (fix before merge): a database password is committed in the report

`docs/reports/gate-a1-report.md` line 53 records the test command with a full connection string
including a password for the Postgres container at `172.18.0.2`. The same string has been in the
repository since `a014c67`, so treat it as burned: rotate that container's password and replace
the string in the report with a placeholder (`<redacted>`). The brief's "no secrets" rule applies
to reports as much as to code. The CI password (`forti_ci_test_password`) is fine: it only ever
exists in an ephemeral CI service container and is already public by design.

### Finding 3 (fix before merge): one action-map citation is wrong

`config/action_map.yaml` `traffic.default.accept` cites "Observed sample SAMPLE_ESCAPED_QUOTES".
That fixture has no `action=` field at all, and no fixture in `tests/fixtures/fortios_logs.py`
contains `action="accept"`. The only observed `accept` is in the e2e scenario generator
(`tests/e2e/fake_endpoints.py`, benign scenario). Cite that, or add an `accept` sample to the
fixtures and cite it. The other five fixture citations check out (deny, ips/detected,
webfilter/blocked, waf/passthrough, ssl/fail).

### Finding 4 (Low, Phase B): the SIGTERM traceback is still there

`stop()` now sets `should_exit`, but it runs in the `finally` after `gather` has already been
cancelled by `_sig_handler`, which cancels every task including the uvicorn server task. The
lifespan task therefore still logs `asyncio.exceptions.CancelledError`. Harmless, but it is a
traceback on every clean shutdown, and the A1.10 "no tracebacks" standard is cleaner without it.
Fix in `_sig_handler`: stop the loops and the server cooperatively instead of cancelling tasks:

```python
def _sig_handler():
    logger.info("Received termination signal.")
    service.running = False
    server = getattr(service, "_server", None)
    if server is not None:
        server.should_exit = True
```

The supervised loops exit on their next `running` check (at most one poll interval later).

### Finding 5 (trivial): unused import

`src/main.py` still imports `OUTBOX_DELIVERED_TOTAL` after the double-increment removal.

### Finding 6 (Low): report still says "pinned"

Section 7 lists `fastapi==0.128.8` etc. under "Key Pinned Dependencies". Those are the versions
installed in the author's virtualenv; `requirements.txt` still uses ranges. Either say "installed
versions" or add a lock file (Phase B item).

### Finding 7 (Low, Phase B): `verified: false` has no runtime effect

The normalizer maps unverified aliases exactly like verified ones. That is acceptable for A.1
because every unverified alias maps to `BLOCKED` or `ALLOWED_OR_DETECTED` in the direction one
would expect, but an unverified `BLOCKED` alias is a silent alert suppressor if it is ever wrong.
Phase B should at least count hits on unverified entries (a labelled metric and a one-time log
line per entry) so a real FortiOS build can confirm or retire them.

## To exit A.1

One commit on `feature/gate-a1-critical-fixes`:

1. Apply the test patch below (Finding 1).
2. Replace the connection string in `gate-a1-report.md` with a placeholder and rotate the
   container password (Finding 2).
3. Fix the `accept` citation (Finding 3).

Optionally fold in Findings 4 to 6; they are each a few lines. Then merge and open the Phase B
branch per the brief.

## Operator actions (unchanged from the previous review)

- Rotate the Loki credential leaked in commit `a014c67`.
- Rotate the dev Postgres password from the same commit (Finding 2).
- Keep `GCHAT_DRY_RUN=true` everywhere except the one production deployment.

## Verified patch for Finding 1 (applies to `2574e23`)

```diff
--- a/tests/integration/test_investigation_loop_pg.py
+++ b/tests/integration/test_investigation_loop_pg.py
@@ -359,16 +359,18 @@ async def test_pg_unchanged_episode_poller_and_investigation_completion(pg_repo,
     revs_initial = await service.repo.db.fetch_all("SELECT * FROM incident_revisions WHERE incident_id = $1", inc_id)
     assert len(revs_initial) == 1
 
-    # 3. Drive poller loop five times over the unchanged active episode
+    # 3. Five counts-only poller transitions over the unchanged active episode.
+    # This is the exact call main.py makes on the "no material change" path
+    # (revision=None, expected_revision=<revision it just read>); it must not
+    # advance current_revision or write a revision row.
     for cycle in range(5):
         pending = await service.repo.fetch_pending_events(limit=100)
         assert len(pending) == 0
-        touched = set()
-        active_episodes = service.aggregator.process_events([])
-        for active_ep in active_episodes:
-            if (active_ep.get("vdom", "root"), active_ep.get("direction", "INBOUND"), active_ep["source_ip"], active_ep["target_ip"]) not in touched:
-                continue
-            await service.repo.record_incident_transition(incident=inc_data, revision=None)
+        current = (await service.repo.get_incident(inc_id))["current_revision"]
+        counts_only = dict(inc_data, current_revision=current, event_count=inc_data["event_count"])
+        await service.repo.record_incident_transition(
+            incident=counts_only, revision=None, expected_revision=current
+        )
 
     # Assert current_revision unchanged, exactly one revision row
     inc_after_polls = await service.repo.get_incident(inc_id)
```
