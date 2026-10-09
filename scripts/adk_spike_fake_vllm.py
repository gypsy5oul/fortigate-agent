#!/usr/bin/env python3
"""Scripted fake of a vLLM OpenAI-compatible server for the Phase C.0 ADK spike.

This is a deterministic stand-in, not a model. It exists so the ADK plumbing
(LiteLlm -> OpenAI-compatible endpoint, tool round trip, structured output,
session persistence, budget behaviour) can be exercised without a GPU server.
It proves nothing about the quality of any real model.

Behaviour of POST /v1/chat/completions, first matching rule wins:

  1. The request carries ``response_format`` of type ``json_schema`` or
     ``json_object``: reply with a JSON object that validates as the service's
     ``QwenAssessment`` (identity, evidence ids and enforcement are lifted from
     the prompt text when present, so a note passed through ADK session state is
     visibly honoured).
  2. The conversation already contains a ``tool`` role message: reply with a
     final text answer that quotes the most recent tool result verbatim.
  3. The request carries ``tools``: reply with one ``tool_calls`` entry calling
     ``echo_evidence`` with ``{"evidence_id": "EVID-1"}`` (finish_reason
     ``tool_calls``). If ``echo_evidence`` is not among the declared tools (for example
     an agent wrapped in AgentTool), the first declared tool is called with every
     string parameter set to "EVID-1".
  4. Otherwise: reply with a short plain text message.

Every request is recorded in memory (messages, tools, response_format, and the
other top-level keys that were sent) and exposed through GET /capture.
Responses always carry ``usage`` token counts (a rough characters/4 estimate).

Other routes: GET /v1/models, GET /version, GET /health, POST /reset.
Binds to 127.0.0.1 by default. Usage:

    python scripts/adk_spike_fake_vllm.py --port 18995 --model spike-fake-qwen
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request

DEFAULT_MODEL = "spike-fake-qwen"
FAKE_VERSION = "scripted-fake (not vLLM)"


def _content_text(content: Any) -> str:
    """Flatten an OpenAI message ``content`` (string or list of parts) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for part in content:
            if isinstance(part, dict):
                parts.append(str(part.get("text", "")))
            else:
                parts.append(str(part))
        return "\n".join(p for p in parts if p)
    return str(content)


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _first(pattern: str, text: str, default: str) -> str:
    match = re.search(pattern, text)
    return match.group(1) if match else default


def build_assessment(prompt_text: str) -> Dict[str, Any]:
    """Return a dict that validates as ``QwenAssessment``, shaped from the prompt."""
    # A key is only honoured when followed by ':' or '=' (so prose like "incident_id and ..." is ignored).
    incident_id = _first(r'incident_id"?\s*[:=]\s*"?([^\s",}]+)', prompt_text, "INC-FAKE-DEFAULT")
    revision = int(_first(r'incident_revision"?\s*[:=]\s*"?(\d+)', prompt_text, "1"))
    enforcement = _first(
        r'enforcement"?\s*[:=]\s*"?(BLOCKED|ALLOWED_OR_DETECTED|MIXED|UNKNOWN)', prompt_text, "ALLOWED_OR_DETECTED"
    )
    severity = _first(
        r'(?:deterministic_severity_floor|severity)"?\s*[:=]\s*"?(LOW|MEDIUM|HIGH|CRITICAL)', prompt_text, "HIGH"
    )
    evidence_id = _first(r"\b(EVID-\d+)\b", prompt_text, "EVID-1")
    return {
        "incident_id": incident_id,
        "incident_revision": revision,
        "visibility_scope": "FIREWALL_ONLY",
        "severity": severity,
        "attack_category": "EXPLOITATION_ATTEMPT",
        "exploitation_assessment": "ATTEMPT_OBSERVED",
        "enforcement": enforcement,
        "summary": "Scripted fake assessment: an exploit signature was observed against the protected host.",
        "findings": [
            {
                "kind": "OBSERVATION",
                "statement": "The firewall logged an IPS signature match for the incident.",
                "evidence_ids": [evidence_id],
            }
        ],
        "cve_references": [],
        "visibility_gaps": ["No endpoint telemetry is available to this assessment."],
        "recommended_action_ids": [],
        "analyst_follow_up": ["Confirm the application patch level on the target."],
    }


def _pick_tool_call(tools: List[Dict[str, Any]]) -> tuple:
    """Choose the scripted tool call: echo_evidence when declared, else the first declared tool.

    The fallback exists so the spike can also drive an agent whose only tool is another agent
    wrapped in AgentTool (a single string parameter), without changing the scripted behaviour
    for the plain echo_evidence case.
    """
    declared = {t.get("function", {}).get("name"): t.get("function", {}) for t in tools}
    if "echo_evidence" in declared:
        return "echo_evidence", {"evidence_id": "EVID-1"}
    name, function = next(iter(declared.items()))
    properties = (function.get("parameters") or {}).get("properties") or {}
    return name, {key: "EVID-1" for key, spec in properties.items() if (spec or {}).get("type") == "string"}


class FakeState:
    def __init__(self, model: str) -> None:
        self.model = model
        self.requests: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

    def reset(self) -> None:
        with self.lock:
            self.requests.clear()


def create_app(model: str = DEFAULT_MODEL) -> FastAPI:
    state = FakeState(model)
    app = FastAPI(title="Scripted fake vLLM (ADK spike)")
    app.state.fake = state

    @app.get("/v1/models")
    async def list_models() -> Dict[str, Any]:
        return {
            "object": "list",
            "data": [
                {
                    "id": state.model,
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "scripted-fake",
                    "max_model_len": 32768,
                }
            ],
        }

    @app.get("/version")
    async def version() -> Dict[str, str]:
        return {"version": FAKE_VERSION}

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/capture")
    async def capture() -> Dict[str, Any]:
        with state.lock:
            return {"model": state.model, "count": len(state.requests), "requests": list(state.requests)}

    @app.post("/reset")
    async def reset() -> Dict[str, str]:
        state.reset()
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Dict[str, Any]:
        body = await request.json()
        messages: List[Dict[str, Any]] = body.get("messages") or []
        tools = body.get("tools") or []
        response_format = body.get("response_format")

        record: Dict[str, Any] = {
            "model": body.get("model"),
            "messages": messages,
            "tools": tools,
            "tool_choice": body.get("tool_choice"),
            "response_format": response_format,
            "stream": body.get("stream"),
            "request_keys": sorted(body.keys()),
        }
        with state.lock:
            record["index"] = len(state.requests)
            state.requests.append(record)
            call_number = len(state.requests)

        prompt_text = "\n".join(_content_text(m.get("content")) for m in messages)
        prompt_tokens = _estimate_tokens(prompt_text + json.dumps(tools))

        rf_type = response_format.get("type") if isinstance(response_format, dict) else None
        tool_messages = [m for m in messages if m.get("role") == "tool"]

        message: Dict[str, Any]
        finish_reason = "stop"
        kind = "plain_text"
        if rf_type in ("json_schema", "json_object"):
            kind = "structured_json"
            message = {"role": "assistant", "content": json.dumps(build_assessment(prompt_text))}
        elif tool_messages:
            kind = "final_text_after_tool"
            tool_result = _content_text(tool_messages[-1].get("content"))
            message = {
                "role": "assistant",
                "content": f"The echo_evidence tool returned {tool_result} and evidence EVID-1 is confirmed.",
            }
        elif tools:
            kind = "tool_call"
            name, arguments = _pick_tool_call(tools)
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_fake_{call_number}",
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(arguments)},
                    }
                ],
            }
            finish_reason = "tool_calls"
        else:
            message = {"role": "assistant", "content": "Scripted fake reply with no tools and no schema."}

        completion_text = message["content"] or json.dumps(message.get("tool_calls"))
        completion_tokens = _estimate_tokens(completion_text)
        usage = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
        # The capture shows what the server decided and returned, not only what it received.
        record["response_kind"] = kind
        record["usage"] = usage
        return {
            "id": f"chatcmpl-fake-{call_number}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": state.model,
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
            "usage": usage,
        }

    return app


def main(argv: Optional[List[str]] = None) -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18995)
    parser.add_argument("--model", default=DEFAULT_MODEL, help="model name listed by /v1/models")
    args = parser.parse_args(argv)
    uvicorn.run(create_app(args.model), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
