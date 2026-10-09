# ADR 005: ADK agent investigator, in shadow mode

## Status
Accepted for shadow mode (9 October 2026, Phase C.1). `INVESTIGATOR_MODE=adk` exists and is tested end to end against a scripted model, but making it the default and deleting the legacy single call is Phase C.3, after the C.2 promotion criteria are met on the golden set and on real shadow runs. The plan (`docs/GEMINI-PHASE-B1-AND-PHASE-C-ADK-PLAN.md`) calls this record `002-adk-investigator.md`; ADRs 001 to 004 already exist, so it is 005.

## Context
The deterministic spine (poller, rules, aggregator, outbox, checkpoints) decides whether an incident exists and whether it is urgent. The investigation of an urgent incident was one bounded model call (ADR 001, `src/investigation/single_call_workflow.py`). Phase C replaces that call with a Google ADK agent system: a master investigator that asks two specialist agents for data through read-only tools, and a writer that turns the master's notes into a schema-bound assessment, which the unchanged validator then gates. Phase C.0 (`docs/reports/gate-c0-spike-report.md`) proved the ADK plumbing against a scripted fake and recorded the facts this design depends on.

## Decision

### 1. Topology (plan C1.1)
```
Workflow "investigation": START -> incident_investigator -> assessment_writer

incident_investigator  tools: AgentTool(evidence_agent), AgentTool(context_agent)   output_key investigation_notes
evidence_agent         tools: get_incident_packet, query_traffic_context            output_key evidence_notes, include_contents none
context_agent          tools: lookup_asset, lookup_signature,
                              recent_incidents_for_source, get_action_catalog       output_key context_notes, include_contents none
assessment_writer      output_schema WriterAssessment, no tools                      output_key assessment_json, include_contents none
```
Every agent uses one model instance and disallows transfer to parent and peers. Instructions are versioned files (`src/investigation/agent/instructions/*.txt`, `# Version: 1.0.0`, from plan Appendix C). Code: `src/investigation/agent/{agents,tools,callbacks,runtime,audit}.py`.

### 2. Model class: ADK's native OpenAI-compatible model, not LiteLlm
`google-adk` 2.11.0 ships `google.adk.integrations.openai.OpenAILlm`, which talks to any OpenAI-compatible `/v1/chat/completions` endpoint and needs only the `openai` client. With `LiteLlm` swapped for it, the C.0 spike's own step 1 and step 2 functions (`scripts/adk_spike.py`) passed 20 of 20 assertions against `scripts/adk_spike_fake_vllm.py`: one tool call whose result reached the answer, and a writer whose request carried `response_format` `json_schema` (strict) and whose answer validated. `tests/agent/test_agent_openai_model.py` repeats both checks in every environment that installs `requirements.txt`, CI included. The instance is built once (`agents.build_model`) on an `AsyncOpenAI` client with `timeout=LLM_TIMEOUT_SECONDS` and `max_retries=0`; generation uses temperature 0.1 and `max_output_tokens=LLM_MAX_OUTPUT_TOKENS`.

### 3. Dependencies and size
`requirements.in` gains the slim set: `google-adk==2.11.0` (no `[extensions]`), `openai==2.54.0`, `google-genai==2.29.0`, `sqlalchemy[asyncio]==2.1.4`, `opentelemetry-api==1.42.1`, `opentelemetry-sdk==1.42.1`; the runtime pins move to `fastapi==0.141.1`, `starlette==1.7.0`, `pydantic-settings==2.15.0`; `pydantic==2.12.5` and `pydantic-core==2.41.5` stay (the slim set resolves with them). `litellm` is not installed. `requirements.txt` and the hashed `requirements.lock` are compiled with pip-tools 7.6.2 under Python 3.12.3, and the lock was proven with `pip install --dry-run --require-hashes -r requirements.lock` in a fresh Python 3.12 venv (56 distributions). `requirements-agent.in` remains as the C.0 spike's record.

Measured installed site-packages on Python 3.12.3 (`du -sk`, includes `.pyc`):

| Set | KB | Delta |
|---|---|---|
| previous lock (no ADK) | 49,608 | |
| this lock (slim set, no litellm) | 187,664 | +138,056 KB (134.8 MiB) |
| this lock plus `litellm==1.104.2` | 440,332 | +390,724 KB (381.6 MiB) |

Leaving litellm out saves 252,668 KB. The architect accepted growth of roughly 400 MB for C.1; the measured growth is about a third of that. The real image size will come from CI's container-smoke job (no Docker daemon was available here).

### 4. Root composition: `Workflow`
`SequentialAgent` is deprecated in ADK 2.11.0 in favour of `Workflow`. A probe with a scripted model showed that `Workflow(edges=[(START, incident_investigator, assessment_writer)])` runs the two in sequence with one shared session state (the writer reads `{investigation_notes}` written by the master's `output_key`), with the master's `AgentTool` calls, the callbacks, `DatabaseSessionService` and the budget signals all working (the pipeline tests run on it). So the root is a `Workflow`. Two behaviours differ from `SequentialAgent`: ADK runs both nodes in `single_turn` mode, which drops the "You are an agent. Your internal name is ..." system line for them, and it hands the writer the master's output as its user message in addition to the `{investigation_notes}` instruction text. Neither changes what the writer may do; the instructions do not depend on the user message.

### 5. Tools and callbacks (plan C1.2, C1.3)
Tools are plain functions taking a `ToolContext`. Identity (`incident_id`, `revision`, `source_ip`, `target_ip`, `window_start_ns`, `window_end_ns`) comes from session state only; bounds are in code; refusals return `{"status": "refused", "reason": ...}`; no tool raises. The only database access is `tools._select`, which refuses anything but `SELECT`. `query_traffic_context` renders the `traffic_context` query profile with the incident's IPs only, clamps `minutes_before` to 1..30, asks the existing Loki client for at most 200 lines, parses them with the normalizer (`allow_accepted_traffic=True`), re-filters on the exact IP (LogQL `|=` is a substring match), and returns counts by action and port, first and last seen, and at most 20 redacted samples.

`before_tool_callback` (`enforce_tool_bounds`) applies an allowlist per agent, 3 calls per tool per run (the fourth is refused), drops undeclared arguments and clamps `minutes_before` in place. `after_tool_callback` (`redact_and_delimit`) strips control characters from every string, runs log-derived records through `redact_evidence_record` and wraps each in `<<UNTRUSTED id=...>>` (forged delimiters inside are escaped), wraps log-derived text fields (`signatures`, `signature`, `target_app`), caps the serialized result at 6 KB and records the call. `before_model_callback` (`budget_and_truncate`) enforces the run-wide model-call ceiling, blanks the oldest tool results when the request exceeds `LLM_MAX_INPUT_TOKENS` (the tool message stays, so OpenAI's call/result pairing holds) with a system note, and records the request hash. `after_model_callback` records tokens and latency and never alters content. `on_model_error_callback` records and returns `None`.

The callbacks keep their counters in a per-run `AgentRunRecord` bound through a `ContextVar` by the runtime wrapper, so the counter is shared by all four agents, including the specialists' calls inside `AgentTool` runs. This is the authoritative ceiling: C.0 showed that `RunConfig(max_llm_calls)` does not count calls made through `AgentTool`. `tests/agent/test_agent_pipeline_pg.py::test_specialist_call_via_agent_tool_trips_the_run_wide_budget` proves the ceiling trips on `context_agent`'s call inside an `AgentTool` run.

### 6. Runtime (plan C1.4)
`AgentInvestigator.investigate(packet, mode)`: `DatabaseSessionService` on `ADK_SESSION_DB_URL`, or on `DATABASE_URL` rewritten to `postgresql+asyncpg://` with `search_path=adk` (schema created by migration 006); `InMemorySessionService` only in tests. `Runner(app_name="forti-investigator")`, `user_id="system"`, `session_id=f"{incident_id}:{revision}"` (a retried job replaces the session). Initial state: the identity fields and the redacted packet. `RunConfig(max_llm_calls=AGENT_MAX_LLM_CALLS)` (default 8) plus the callbacks' ceiling; the whole run under `asyncio.wait_for(AGENT_TIMEOUT_SECONDS)` (default 120). The writer's object is validated as `WriterAssessment`, mapped to `QwenAssessment` (service-owned fields set by the runtime) and passed through `validate_assessment` exactly as the legacy path does.

| Outcome (`agent_runs.outcome`) | Cause | Assessment | Reason codes |
|---|---|---|---|
| `VALID` | validator passed | `MODEL_VALIDATED` | the validator's codes |
| `REJECTED` | validator hard reject | fallback | `AGENT_VALIDATION_REJECTED` + the validator's codes |
| `BUDGET_EXHAUSTED` | `AgentBudgetExceeded` from the callback, or ADK's `LlmCallsLimitExceededError` (also when wrapped), or the record's budget flag | fallback | `AGENT_BUDGET_EXHAUSTED` |
| `TIMEOUT` | `asyncio.wait_for` expired | fallback | `AGENT_TIMEOUT` |
| `SCHEMA_INVALID` | no writer output, or it fails `WriterAssessment` | fallback | `AGENT_SCHEMA_INVALID` |
| `ERROR` | anything else (e.g. endpoint unreachable) | fallback | `AGENT_ERROR` + exception class or ADK error code |

The fallback is the deterministic assessment the legacy path uses (`MODEL_REJECTED_FALLBACK`, severity at the deterministic floor), with the AGENT_* code in its summary. A final-flagged error event is never taken for an answer (C.0 finding).

### 7. Audit (plan C1.5, migration `006_agent_audit.sql`)
`agent_runs` (one row per run), `agent_events` (one row per model or tool call, ordered by `seq`) and `shadow_assessments`, documented in `docs/data-dictionary.md`. Only `audit.write_run` and `audit.write_shadow_assessment` write them, called by the runtime wrapper and by `src/main.py`, never by an agent, tool or callback. Metrics `forti_agent_runs_total{mode,outcome}`, `forti_agent_llm_calls_total{agent}`, `forti_agent_tool_calls_total{tool,outcome}`, `forti_agent_run_duration_seconds`, `forti_agent_tokens_total{direction}` and `forti_agent_budget_exhausted_total` are incremented by the runtime after each run and shown on `dashboards/agent_operations.json`.

### 8. Modes (plan C1.7)
- `legacy` (default): exactly the previous code path; ADK is not imported.
- `shadow`: the legacy call writes the revision and the card through `record_incident_transition`; after that commit, the ADK pipeline runs and writes `agent_runs`, `agent_events` and one `shadow_assessments` row with the agreement fields (severity equal, action set equal, exploitation assessment equal, findings counts). No revision, no card. Any failure there is logged and never fails the job or the legacy write.
- `adk`: the ADK result is the revision, committed through the same `record_incident_transition` with the same `expected_revision` CAS and job fence, with a `model_runs` row (`structured_output_mode=adk_json_schema`, `validation_result` = the run outcome) kept for backward compatibility.

In shadow and adk modes a run in progress is abandoned when the service starts stopping, so the SIGTERM contract (exit 0 within the stop timeout) holds; in adk mode the job is then left to its lease and retried.

## Consequences
- Agents never write: enforced by `_select`, by the tool contract tests (a database spy records every statement and asserts none writes) and by the pipeline test (no service table changes during a run).
- Shadow runs execute after the legacy commit in the same investigation loop, so each investigated revision costs up to `AGENT_TIMEOUT_SECONDS` more loop time in shadow mode. Investigation jobs queue behind it; detection and URGENT cards do not (they come from the poller).
- The `adk` schema accumulates one session per investigated revision. Nothing prunes it in C.1 (runbook section 5.4 has the manual statement).
- The image grows by about 135 MiB of site-packages.

## Deviations from the plan
1. ADR number 005 and migration `006_agent_audit.sql`, not 002 and 004: those numbers were taken.
2. `OpenAILlm` instead of `LiteLlm` (section 2), per the architect's decision rule; `litellm` is not in the image.
3. Root is a `Workflow`, not a `SequentialAgent` (section 4), per the architect's decision rule.
4. `AgentTool(..., skip_summarization=False)` instead of `True`. Probe: with `True`, ADK marks the specialist's function response as the master's final response, so the master's turn ends after the first specialist answers; it can neither call the second specialist nor write `investigation_notes` (the specialist's text lands in `investigation_notes` instead). With `False` the master keeps control and receives each answer as a tool result, which is what C1.1 describes.
5. The packet is in session state under `packet`, not `temp:packet`. `AgentTool` runs the specialist in a fresh session created with `create_session(state=...)`, which drops every `temp:` key, so the specialists' tools would never see it. The packet in state is the redacted view (`raw_message` dropped, URL query values redacted), so ADK's `sessions` row holds no raw log line.
6. The writer's `output_schema` is `WriterAssessment` (only the fields the model decides), mapped to `QwenAssessment` before the validator: ADK's strict schema makes every property required, including the service-owned ones (C.0 finding, the architect's instruction).
7. Outcomes `REJECTED` and `ERROR` with reason codes `AGENT_VALIDATION_REJECTED` and `AGENT_ERROR` exist in addition to the three the plan names, so every run gets exactly one outcome.
8. `agent_events` has a `request_hash` column (C1.3 asks for the request hash to be recorded; C1.5's column list has nowhere to put it). `shadow_assessments` has `run_id`, `assessment_source` and `legacy_findings_count` besides the plan's fields.
9. Tool callbacks are also set on the master (its `AgentTool` calls are allowlisted, capped at 3 and recorded) and model callbacks on all four agents (the skeleton shows them on the master only); the run-wide counter requires the latter.
10. `recent_incidents_for_source` looks back 24 hours from the incident's `last_seen`, not from the wall clock, so a replayed incident sees the same history.
11. The context specialist learns the incident's IPs and signatures from the master's request, not from instruction templating: putting log-derived values into a system instruction would carry untrusted text outside the delimiters. `lookup_asset` and `lookup_signature` refuse anything that is not the incident's.
12. Tools reach the Loki client and the database through a module-level `ToolDeps` set by the runtime (`tools.configure_tools`); the plan does not say how the tools get their clients.
13. In `adk` mode the existing `forti_model_inference_duration_seconds` histogram also observes the ADK run.
14. `requirements.txt` is now the compiled pin set without hashes (it was a copy of `requirements.in`), so CI installs exactly the lock's versions.
15. `scripts/make_phase_report.sh` strips pip extras before `pip show` in its version manifest (`sqlalchemy[asyncio]`).
16. An `adk`-mode end-to-end test was added besides the required shadow one. Both stop the service when the database shows the result (30 s ceiling) rather than after a fixed 8 s, through an optional readiness check added to the shared e2e helper; the existing tests call it unchanged.

## Not proven here
- The real model. Everything above ran against scripted fakes (`tests/agent/fake_llm.py` in process, `tests/e2e/fake_endpoints.py` over HTTP, `scripts/adk_spike_fake_vllm.py`). Whether a Qwen model served by vLLM (`--enable-auto-tool-choice --tool-call-parser hermes`) follows the instructions, calls the specialists in order, stays within 8 model calls and produces a good `WriterAssessment` is Phase C.2's lab work. `OpenAILlm` sends `tools`, `tool_choice` and `response_format` as `null` when unused; vLLM's request model declares them optional, but that was not run against vLLM here.
- `adk eval` against a `Workflow` root (`agents.root_agent` is provided for it): not run.
- The container image size and the image build: CI's container-smoke job.
