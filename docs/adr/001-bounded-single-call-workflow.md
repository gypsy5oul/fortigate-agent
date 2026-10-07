# ADR 001: Bounded Investigation Workflow & Structured Output

## Status
Accepted (6 October 2026; updated Phase B, 7 October 2026)

## Context
We need automated investigation of security incidents derived from FortiGate 200G firewall logs. Raw firewall volume is too high for direct LLM ingestion, and arbitrary agent autonomy (unconstrained swarms, shell execution, database manipulation) poses security and reliability risks. The runtime investigation model is a local Qwen3.8-27B served via vLLM (`http://vllm.internal:8000/v1`).

## Decision
1. Implement a bounded, single-pass investigation workflow:
   `Deterministic Packet Assembly & Redaction` -> `Structured LLM Analysis` -> `Pydantic Schema & Security Guardrail Validation` -> `Transactional DB & Outbox Commit`.
2. Do not install unconstrained agent swarms, arbitrary tool loops, or unverified agent runtimes. In Phase B, the model is invoked via structured JSON schema (`response_format={"type": "json_schema", ...}`) with a 1-repair prompt loop and deterministic fallback. Full Google ADK tool-calling agent is scoped for Phase C following a formal compatibility spike.
3. Integrate with the local vLLM OpenAI-compatible endpoint with temperature 0.1 and strict per-request token limits.
4. Strictly enforce `visibility_scope=FIREWALL_ONLY` and prevent unsupported claims of application or endpoint compromise (`CONFIRMED_COMPROMISE` is strictly rejected; downgraded to `ATTEMPT_OBSERVED`).
5. Deterministic rule evaluation sets a severity floor that the model cannot lower. If the model fails or times out, deterministic alerts are dispatched without disruption.
6. Untrusted attacker text (URLs, headers, payloads) is delimited with `<<UNTRUSTED id=...>>` to contain prompt injection.

## Consequences
- Bounded execution latency governed by strict network deadlines (60 s timeout per call with up to one repair attempt) and deterministic fallback.
- All model runs are audited in the `model_runs` table with token counts, prompt versions, schema versions, and hashes.
- External model outages degrade gracefully: deterministic severity floors deliver without interruption.
- No external cloud dependencies or third-party telemetry leaks.
