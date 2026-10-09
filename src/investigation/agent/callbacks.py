"""Enforcement callbacks of the ADK investigator (plan C1.3).

The model never sees a tool result that did not pass ``redact_and_delimit``, never calls a tool that
``enforce_tool_bounds`` refused, and never gets a model call past ``budget_and_truncate`` once the
run's ceiling is reached. These callbacks keep their counters in the ``AgentRunRecord`` bound by the
runtime wrapper (audit.current_run) and write nothing anywhere else.
"""

import hashlib
import json
import re
from typing import Any, Dict, Optional

from src.investigation.agent.audit import (
    TOOL_CALL_CAP,
    TOOL_RESPONSE_MAX_BYTES,
    AgentBudgetExceeded,
    current_run,
)
from src.investigation.agent.tools import DIRECTIONS, MINUTES_MAX, MINUTES_MIN, refused
from src.parsing.redaction import CONTROL_CHARS_PATTERN, redact_evidence_record, wrap_untrusted_evidence

# Which tools each agent may call (defense in depth: ADK only offers an agent its own tools).
ALLOWED_TOOLS = {
    "incident_investigator": {"evidence_agent", "context_agent"},
    "evidence_agent": {"get_incident_packet", "query_traffic_context"},
    "context_agent": {"lookup_asset", "lookup_signature", "recent_incidents_for_source", "get_action_catalog"},
}
# The arguments each tool declares; anything else the model sends is dropped before the call.
TOOL_ARGS = {
    "evidence_agent": ("request",),
    "context_agent": ("request",),
    "get_incident_packet": (),
    "query_traffic_context": ("direction", "minutes_before"),
    "lookup_asset": ("ip",),
    "lookup_signature": ("signature",),
    "recent_incidents_for_source": (),
    "get_action_catalog": (),
}
# Log-derived content: records under these keys are redacted and wrapped whole; strings under the
# text keys are wrapped one by one. Everything else is service-generated or reviewed configuration.
UNTRUSTED_RECORD_KEYS = ("evidence", "samples")
UNTRUSTED_TEXT_KEYS = ("target_app", "signature", "signatures")
MAX_STRING_CHARS = 2000
TRUNCATION_NOTE = "Older evidence truncated: some earlier tool results were removed to fit the input budget."
_ID_CHARS = re.compile(r"[^A-Za-z0-9_.:-]")


# --------------------------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------------------------


def enforce_tool_bounds(tool, args: Dict[str, Any], tool_context) -> Optional[dict]:
    """before_tool_callback: allowlist, per-run cap, argument validation and clamping.

    Returning a dict skips the tool and hands that dict to the model as the result.
    """
    run = current_run()
    if run is None:
        return refused("no active investigation run")
    run.start(("tool", tool_context.function_call_id))
    name, agent = tool.name, tool_context.agent_name
    if name not in ALLOWED_TOOLS.get(agent, ()):
        return refused(f"tool {name} is not allowed for {agent}")
    count = run.tool_counts.get(name, 0) + 1
    run.tool_counts[name] = count
    if count > TOOL_CALL_CAP:
        return refused(f"per-run cap of {TOOL_CALL_CAP} calls to {name} reached")
    for key in [k for k in args if k not in TOOL_ARGS.get(name, ())]:
        args.pop(key)
    if name == "query_traffic_context":
        if args.get("direction") not in DIRECTIONS:
            return refused(f"direction must be one of {list(DIRECTIONS)}")
        try:
            args["minutes_before"] = min(MINUTES_MAX, max(MINUTES_MIN, int(args.get("minutes_before"))))
        except (TypeError, ValueError):
            return refused("minutes_before must be an integer")
    return None


def _clean(text: str) -> str:
    return CONTROL_CHARS_PATTERN.sub("", text)[:MAX_STRING_CHARS]


def _wrap_record(item: Any) -> Any:
    if not isinstance(item, dict):
        return wrap_untrusted_evidence("item", _clean(json.dumps(item, default=str)))
    record = redact_evidence_record(item)
    rid = _ID_CHARS.sub("", str(record.get("id", "unknown")))[:64] or "unknown"
    body = {k: (_clean(v) if isinstance(v, str) else v) for k, v in record.items() if k != "id"}
    return {"id": rid, "data": wrap_untrusted_evidence(rid, json.dumps(body, sort_keys=True, default=str))}


def _wrap_text(key: str, value: Any) -> Any:
    if isinstance(value, list):
        return [_wrap_text(key, v) for v in value]
    if isinstance(value, str):
        return wrap_untrusted_evidence(key, _clean(value))
    return value


def sanitize_tool_response(value: Any) -> Any:
    """Clean every string; redact and delimit everything that came from a log line."""
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if key in UNTRUSTED_RECORD_KEYS and isinstance(val, list):
                out[key] = [_wrap_record(item) for item in val]
            elif key in UNTRUSTED_TEXT_KEYS:
                out[key] = _wrap_text(key, val)
            else:
                out[key] = sanitize_tool_response(val)
        return out
    if isinstance(value, list):
        return [sanitize_tool_response(v) for v in value]
    if isinstance(value, str):
        return _clean(value)
    return value


def _size(value: Any) -> int:
    return len(json.dumps(value, default=str).encode("utf-8"))


def cap_tool_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the serialized response within TOOL_RESPONSE_MAX_BYTES, dropping list tails first."""
    if _size(response) <= TOOL_RESPONSE_MAX_BYTES:
        return response
    out = dict(response, truncated=True)
    for key in ("samples", "evidence", "incidents", "eligible_actions", "evidence_ids"):
        while isinstance(out.get(key), list) and out[key] and _size(out) > TOOL_RESPONSE_MAX_BYTES:
            out[key] = out[key][:-1]
    if _size(out) <= TOOL_RESPONSE_MAX_BYTES:
        return out
    text = json.dumps(response, default=str)[: TOOL_RESPONSE_MAX_BYTES // 2]
    return {"status": response.get("status", "success"), "truncated": True, "partial": wrap_untrusted_evidence("truncated", text)}


def redact_and_delimit(tool, args: Dict[str, Any], tool_context, tool_response: Any) -> dict:
    """after_tool_callback: sanitize, delimit and cap the result, and record the call."""
    response = tool_response if isinstance(tool_response, dict) else {"result": tool_response}
    result = cap_tool_response(sanitize_tool_response(response))
    run = current_run()
    if run is not None:
        latency_ms, _ = run.finish(("tool", tool_context.function_call_id))
        run.tool_calls += 1
        run.add_event(
            agent_name=tool_context.agent_name,
            kind="tool",
            tool_name=tool.name,
            args=dict(args),
            response_bytes=_size(result),
            refused=result.get("status") == "refused",
            latency_ms=latency_ms,
            outcome=str(result.get("status", "success")),
        )
    return result


# --------------------------------------------------------------------------------------------
# Model calls
# --------------------------------------------------------------------------------------------


def estimate_tokens(text: str) -> int:
    """Conservative estimate (about 3.5 characters per token), the same rule as the legacy path."""
    return max(1, int(len(text) / 3.5))


def _request_text(llm_request) -> str:
    parts = [str(getattr(llm_request.config, "system_instruction", "") or "")]
    for content in llm_request.contents or []:
        for part in content.parts or []:
            if part.text:
                parts.append(part.text)
            if part.function_call:
                parts.append(json.dumps({"call": part.function_call.name, "args": part.function_call.args}, default=str))
            if part.function_response:
                parts.append(json.dumps({"result": part.function_response.name, "response": part.function_response.response}, default=str))
    return "\n".join(parts)


def truncate_for_budget(llm_request, max_input_tokens: int) -> bool:
    """Blank the oldest tool results until the request fits; True if anything was removed.

    The function_response part stays (OpenAI requires a tool message for every tool call); only its
    payload is replaced. The newest tool result is never blanked.
    """
    if estimate_tokens(_request_text(llm_request)) <= max_input_tokens:
        return False
    responses = [
        part.function_response
        for content in llm_request.contents or []
        for part in content.parts or []
        if part.function_response is not None
    ]
    removed = False
    for fr in responses[:-1]:
        if estimate_tokens(_request_text(llm_request)) <= max_input_tokens:
            break
        if fr.response != {"status": "truncated"}:
            fr.response = {"status": "truncated"}
            removed = True
    if removed:
        llm_request.append_instructions([TRUNCATION_NOTE])
    return removed


def budget_and_truncate(callback_context, llm_request):
    """before_model_callback: the run-wide model-call ceiling, input truncation, request hash.

    RunConfig(max_llm_calls) does not count calls made inside an AgentTool (C.0 finding), so this
    counter, shared by all four agents through the bound run record, is the authoritative ceiling.
    """
    run = current_run()
    if run is None:
        raise AgentBudgetExceeded("no active investigation run")
    if run.llm_calls >= run.max_llm_calls:
        run.budget_exhausted = True
        run.add_event(agent_name=callback_context.agent_name, kind="llm", refused=True, args={"error": "AgentBudgetExceeded"})
        raise AgentBudgetExceeded(
            f"model call {run.llm_calls + 1} by {callback_context.agent_name} exceeds AGENT_MAX_LLM_CALLS={run.max_llm_calls}"
        )
    run.llm_calls += 1
    truncate_for_budget(llm_request, run.max_input_tokens)
    request_hash = hashlib.sha256(_request_text(llm_request).encode("utf-8")).hexdigest()
    run.start(("llm", callback_context.invocation_id, callback_context.agent_name), request_hash)
    return None


def record_usage(callback_context, llm_response):
    """after_model_callback: record tokens and latency; never alters the response."""
    run = current_run()
    if run is None or getattr(llm_response, "partial", False):
        return None
    latency_ms, request_hash = run.finish(("llm", callback_context.invocation_id, callback_context.agent_name))
    usage = llm_response.usage_metadata
    prompt = (usage.prompt_token_count or 0) if usage else 0
    completion = (usage.candidates_token_count or 0) if usage else 0
    run.input_tokens += prompt
    run.output_tokens += completion
    content = llm_response.content.model_dump(mode="json", exclude_none=True) if llm_response.content else None
    run.add_event(
        agent_name=callback_context.agent_name,
        kind="llm",
        response_bytes=_size(content) if content is not None else 0,
        latency_ms=latency_ms,
        tokens=prompt + completion,
        request_hash=request_hash,
    )
    return None


def record_model_error(callback_context, llm_request, error: Exception):
    """on_model_error_callback: record the failed call and let the error propagate (return None)."""
    run = current_run()
    if run is not None:
        latency_ms, request_hash = run.finish(("llm", callback_context.invocation_id, callback_context.agent_name))
        run.add_event(
            agent_name=callback_context.agent_name,
            kind="llm",
            args={"error": type(error).__name__},
            latency_ms=latency_ms,
            request_hash=request_hash,
        )
    return None
