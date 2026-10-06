# ADR 001: Google ADK for Bounded Investigation Workflow

## Status
Accepted (6 October 2026)

## Context
We need an AI agent to investigate security events from FortiGate 200G firewall logs. Raw firewall volume is too high for direct LLM ingestion, and arbitrary agent autonomy (unconstrained swarms, shell execution, database manipulation) poses security and reliability risks. The runtime investigation model is a local Qwen3.8-27B served via vLLM.

## Decision
1. Use Google ADK (`google-adk 1.18.0`) to define a bounded, deterministic investigation workflow:
   `Deterministic Packet Assembly` -> `ADK Qwen Analysis` -> `Pydantic Schema Validation` -> `DB Outbox Commit`.
2. Do not install or use LangChain Deep Agents, unconstrained agent swarms, critic loops, or arbitrary tool-execution agents.
3. Integrate with the local vLLM endpoint (`http://10.0.6.31:8000/v1`) using an OpenAI-compatible adapter.
4. Strictly enforce `visibility_scope=FIREWALL_ONLY` and prevent hallucinations of application compromise (`CONFIRMED_COMPROMISE` is forbidden in v1 schema).
5. Deterministic rule evaluation sets a severity floor that Qwen cannot lower. If Qwen fails or times out, deterministic alerts are dispatched without disruption.

## Consequences
- Predictable execution latency (< 3s total investigation time).
- No cloud dependencies or telemetry leaks.
- Zero risk of hallucinated actions or uncontrolled tool loops.
