This section is the only hand-written part of this report. Everything outside it (the header table, "Result by step" and the transcript) is output of `scripts/adk_spike.py`, regenerated with:

```
SPIKE_DATABASE_URL=postgresql+asyncpg://postgres@127.0.0.1:55432/c0_spike \
  python scripts/adk_spike.py --fake --notes docs/reports/gate-c0-spike-notes.md --report docs/reports/gate-c0-spike-report.md
```

### What this run is, and what it proves

This ran against a **scripted fake** (`scripts/adk_spike_fake_vllm.py`), not against vLLM and not against a Qwen model. The fake is deterministic: it returns a tool call, then a text answer that quotes the tool result, then schema-shaped JSON, depending on what the request contains. It has no inference time and estimates token counts as characters divided by four.

Proven by this run (real Google ADK, real LiteLlm, real PostgreSQL 16, real HTTP to an OpenAI-compatible endpoint on 127.0.0.1):

- ADK 2.11.0 and litellm 1.104.2 import and run on Python 3.13 (this transcript) and on Python 3.12.3, the interpreter family of the runtime image and CI: in a venv built from `requirements-agent.in` alone, every assertion of the spike and all six tests of `tests/test_adk_spike_fake.py` passed on 3.12 as well. The transcript of that run is not part of this file.
- `LiteLlm(model="openai/<name>", api_base=..., api_key="EMPTY")` talks to an OpenAI-compatible `/v1/chat/completions` endpoint. The tool declaration goes out as an OpenAI function tool, the `tool` role message comes back on the second request, and `usage` is mapped into ADK's `usage_metadata` (the totals match what the endpoint returned).
- Plain-function tool round trip: one tool call, one execution, the result reaches the answer.
- `output_schema=QwenAssessment` with `include_contents='none'` is sent as `response_format` of type `json_schema`, the note from session state reaches the model through the instruction, and the output validates.
- `SequentialAgent` through `Runner` with `DatabaseSessionService` on PostgreSQL via `asyncpg`: ADK creates its own five tables, the session row and every event are persisted, a second service instance reloads them, and the row counts of the tables that already existed (the service's own, which a test-suite run had created in the scratch database) did not change.
- Budget behaviour of `RunConfig(max_llm_calls=N)`, including in the `SequentialAgent` topology and with `AgentTool` (see "Findings" below).

**Not proven** (needs the lab vLLM, see the command at the end):

- That the real Qwen model calls the tool exactly once with the right argument, and stops afterwards.
- That vLLM's `hermes` tool-call parser and the Qwen chat template handle the `system`, `user`, `assistant` (with `tool_calls`) and `tool` messages ADK sends.
- That vLLM's guided decoding accepts the strict JSON schema ADK generates for `QwenAssessment` (15 required properties, a `$defs` reference, `const`, `anyOf` with null) and that the model's JSON is good, not merely schema-valid.
- Real latency, real token counts, and any streaming behaviour (ADK sent non-streaming requests in this run).
- vLLM's version and the flags it was started with. The client cannot read them. There is no go/no-go on the model in this report.

### Dependencies and size

Pins are in `requirements-agent.in` (self-contained; `requirements.in`, `requirements.txt`, `requirements.lock` and the Dockerfile are unchanged, and the file is not installed in the image until the C.1 size decision). A fresh Python 3.13 venv built from that file alone reproduced the tested environment package for package (`pip check` clean).

| Set | Added to site-packages (`du -sk`, includes `.pyc`) |
|---|---|
| `google-adk[extensions]==2.11.0` + `litellm==1.104.2` (the plan's C0.1 wording) | 73,940 KB to 965,032 KB: **+891,092 KB, 870 MiB, 912 MB** |
| `google-adk==2.11.0` + `litellm==1.104.2` + `sqlalchemy[asyncio]==2.1.4`, no `[extensions]` | 49,652 KB to 440,252 KB: **+390,600 KB, 381 MiB, 400 MB** |

The plan's line is "more than 400 MB: report it and propose a slimmer path". The full set is over it by more than a factor of two. The slim set sits on the line. Docker is not available in this environment, so the real image size was **not measured**; site-packages size is the proxy. The slim set also passed all assertions of the spike (Python 3.13). The largest directories in the full set are `litellm` (157 MiB), `kubernetes` (118), `pandas` (75), `google` (54), `numpy` (42 plus 26 of libs), `botocore` (30), `llama_index` (29), `sqlalchemy` (27), `anthropic` (25), `openai` (20); `kubernetes`, `pandas`, `numpy`, `llama_index`, `anthropic` and `langgraph` come in only through the `[extensions]` extra. Proposed path: drop `[extensions]`. What is left is mostly the LiteLlm route: the 29 distributions that only litellm needs (not ADK, not the runtime pins) add 225 MiB by file size, 138 MiB of it litellm itself, then `botocore` 21, `tokenizers` 11, `openai` 11, `hf-xet` 11, `aiohttp` 8. Replacing LiteLlm with a thin custom model adapter would save most of that but means owning tool-call conversion code, which the plan wants to avoid, so that is a decision for the product owner and is not recommended here.

Resolution facts that matter for the lock file (the transcript shows the versions that ran):

- `google-adk` 2.11.0 does not resolve against the runtime pins. `fastapi` has to move from 0.128.8 (ADK needs `>=0.133`), `pydantic-settings` from 2.11.0 (litellm needs `>=2.14.1`) and `starlette` to 1.7.0 (ADK needs `>=1.3.1`). The `[extensions]` extra additionally moves `pydantic` to 2.14.0. The full suite (the 126 existing tests plus the 6 new ones) passed on the slim resolution and on the `[extensions]` resolution, and on the unchanged runtime pins with the ADK test skipped (131 passed, 1 skipped). On the `[extensions]` resolution one of two full runs had a single failure in `tests/e2e/test_service_e2e.py::test_e2e_restart_never_lowers_incident_severity` (3 events where 4 were expected); the identical rerun and a run of that test alone passed, and the report commit's message records it. It was not reproduced, so it is treated as timing-dependent, but it was not root-caused.
- `sqlalchemy` is not a base requirement of `google-adk` 2.11.0 (it is in the `db` extra); `[extensions]` happens to pull it in through another package. State it explicitly.
- `DatabaseSessionService` needs the async driver URL (`postgresql+asyncpg://`), as the plan says. App names containing hyphens work.

### Findings that change the C.1 and C.2 design

1. **The budget is reported differently depending on the topology** (step 4). In both cases `Runner.run_async` raises `google.adk.agents.invocation_context.LlmCallsLimitExceededError` ("Max number of llm calls limit of `N` exceeded"). For a bare `LlmAgent` ADK also yields a final-flagged event whose `error_code` is `LlmCallsLimitExceededError`; for a `SequentialAgent` it does not. The exception is the only signal present in both, so the C.2 wrapper must catch it around the `async for`. Tool calls that ran before the cut-off are not undone, and the events yielded before it are persisted.
2. **`max_llm_calls` does not bound a master that delegates through `AgentTool`** (extra probe). Four model calls ran under `max_llm_calls=2` without tripping; the calls inside the `AgentTool` are not added to the caller's count. A total-call ceiling needs its own counter (for example in a `before_model_callback` that increments a value in state), as well as `RunConfig`.
3. **`SequentialAgent` is deprecated in ADK 2.11.0**: `DeprecationWarning: SequentialAgent is deprecated in favor of Workflow and will be removed in a future version. Workflow cannot yet be used as an LlmAgent sub-agent.` The plan's root agent is a `SequentialAgent`. It works today (steps 3 and 4), but C.1 should decide whether to build on it or on `Workflow`; this spike did not evaluate `Workflow`.
4. **ADK's strict schema makes every property required**, including the service-owned `assessment_source` and `model_reported_enforcement`. The writer would be forced to emit them. Either trim the writer's schema or overwrite those fields after parsing.
5. **`include_contents='none'` still sends a user message** (the run's input text), so the endpoint receives `system` + `user`, not a bare system message. That is the safe shape for chat templates that insist on a user turn.
6. `LiteLlm(...).capabilities` reports `output_schema_and_tools=True` for an `openai/<name>` model. It is computed client-side from the model string, so it says nothing about vLLM or Qwen; keep the separate writer agent.

### What the operator runs against the lab vLLM

vLLM must have been started with `--enable-auto-tool-choice --tool-call-parser hermes` for a Qwen model. Use a scratch database whose name contains `spike`; the spike refuses other names and creates only ADK's own session tables. Placeholders only below; substitute the real values in your shell, not in this file:

```
LLM_BASE_URL=http://<vllm-host>:8000/v1 \
LLM_MODEL=<served-name> \
SPIKE_DATABASE_URL=postgresql+asyncpg://<user>:<password>@<db-host>:5432/<scratch-spike-db> \
python scripts/adk_spike.py --report docs/reports/gate-c0-spike-lab-report.md
```

If vLLM was started with `--api-key`, also set `LLM_API_KEY` (it defaults to `EMPTY` and is never printed). The report masks the endpoint host, the database host, the database password and the API key. Write the lab run to a new file; do not overwrite this one. If step 1 or step 2 fails there, stop: per the plan the fix is on the vLLM side (parser flag, chat template, model choice), not in this repository. Record the vLLM version and the exact launch command next to that report by hand, because the client cannot see them.
