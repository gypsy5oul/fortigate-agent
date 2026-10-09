"""A scripted stand-in model for the ADK investigator tests (plan C1.6).

``FakeLlm`` is a ``BaseLlm`` that replays a list of responses per agent name. The agent is read from
the request itself: ADK's identity instruction when present, otherwise the tools the request declares
(under Workflow, the master and the writer run in single_turn mode without the identity line), with a
response schema meaning the writer. Every request that reaches it is recorded, so a test can assert
what each agent was sent; a request the budget callback refused never reaches it.
"""

import asyncio
import json
import re
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Union

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import PrivateAttr

Step = Union[LlmResponse, Callable[[LlmRequest], LlmResponse]]

_TOOL_OWNERS = {
    "evidence_agent": "incident_investigator",
    "context_agent": "incident_investigator",
    "get_incident_packet": "evidence_agent",
    "query_traffic_context": "evidence_agent",
    "lookup_asset": "context_agent",
    "lookup_signature": "context_agent",
    "recent_incidents_for_source": "context_agent",
    "get_action_catalog": "context_agent",
}


def _usage(prompt: int = 100, completion: int = 20) -> types.GenerateContentResponseUsageMetadata:
    return types.GenerateContentResponseUsageMetadata(
        prompt_token_count=prompt, candidates_token_count=completion, total_token_count=prompt + completion
    )


def call(*calls: tuple) -> LlmResponse:
    """One model turn requesting one or more tool calls: call(("tool", {"arg": 1}), ...)."""
    parts = [types.Part.from_function_call(name=name, args=args or {}) for name, args in calls]
    return LlmResponse(content=types.Content(role="model", parts=parts), usage_metadata=_usage())


def text(value: str) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=value)]), usage_metadata=_usage())


def json_answer(obj: Dict[str, Any]) -> LlmResponse:
    return text(json.dumps(obj))


def agent_of(request: LlmRequest) -> str:
    instruction = str(getattr(request.config, "system_instruction", "") or "")
    match = re.search(r'internal name is "([^"]+)"', instruction)
    if match:
        return match.group(1)
    for tool in request.config.tools or []:
        for decl in tool.function_declarations or []:
            if decl.name in _TOOL_OWNERS:
                return _TOOL_OWNERS[decl.name]
    if request.config.response_schema is not None or request.config.response_json_schema is not None:
        return "assessment_writer"
    return "unknown"


class FakeLlm(BaseLlm):
    model: str = "scripted-fake"
    _script: Dict[str, List[Step]] = PrivateAttr(default_factory=dict)
    _delays: Dict[str, float] = PrivateAttr(default_factory=dict)
    requests: List[Dict[str, Any]] = []

    def __init__(self, script: Dict[str, List[Step]], delays: Optional[Dict[str, float]] = None, **kw):
        super().__init__(**kw)
        self._script = {k: list(v) for k, v in script.items()}
        self._delays = dict(delays or {})
        self.requests = []

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        agent = agent_of(llm_request)
        self.requests.append({"agent": agent, "request": llm_request})
        if self._delays.get(agent):
            await asyncio.sleep(self._delays[agent])
        steps = self._script.get(agent) or []
        if not steps:
            raise AssertionError(f"FakeLlm: no scripted response left for {agent}")
        step = steps.pop(0)
        yield step(llm_request) if callable(step) else step

    def agents_called(self) -> List[str]:
        return [r["agent"] for r in self.requests]

    def tool_results_seen(self, agent: str) -> List[Dict[str, Any]]:
        """Every function_response payload in the requests sent on behalf of ``agent``."""
        seen = []
        for r in self.requests:
            if r["agent"] != agent:
                continue
            for content in r["request"].contents or []:
                for part in content.parts or []:
                    if part.function_response is not None:
                        seen.append({"name": part.function_response.name, "response": part.function_response.response})
        return seen
