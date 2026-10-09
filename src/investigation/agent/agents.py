"""The four agents of the ADK investigator and their composition (plan C1.1, ADR 005).

    incident_investigator (master LlmAgent)
      tools: AgentTool(evidence_agent), AgentTool(context_agent)      output_key investigation_notes
    evidence_agent (specialist): get_incident_packet, query_traffic_context   output_key evidence_notes
    context_agent (specialist): lookup_asset, lookup_signature,
                                recent_incidents_for_source, get_action_catalog  output_key context_notes
    assessment_writer: output_schema WriterAssessment, no tools       output_key assessment_json
    root: Workflow "investigation", START -> incident_investigator -> assessment_writer

Every agent uses the one model instance passed in (ADK's native OpenAI-compatible OpenAILlm), every
agent disallows transfer, every model call goes through the run-wide budget callback, and every
tool call goes through the bounds and redaction callbacks. Instructions are versioned text files in
``instructions/``; changing behaviour should mean editing those, not this module.
"""

from pathlib import Path
from typing import Dict, Tuple

from google.adk.agents import LlmAgent
from google.adk.integrations.openai import OpenAILlm
from google.adk.tools.agent_tool import AgentTool
from google.adk.workflow import START, Workflow
from google.genai import types
from openai import AsyncOpenAI

from src.investigation.agent.callbacks import (
    budget_and_truncate,
    enforce_tool_bounds,
    record_model_error,
    record_usage,
    redact_and_delimit,
)
from src.investigation.agent.tools import CONTEXT_TOOLS, EVIDENCE_TOOLS
from src.investigation.schemas import WriterAssessment

INSTRUCTIONS_DIR = Path(__file__).resolve().parent / "instructions"
INSTRUCTION_FILES = {
    "incident_investigator": "master.txt",
    "evidence_agent": "evidence.txt",
    "context_agent": "context.txt",
    "assessment_writer": "writer.txt",
}


def load_instruction(filename: str) -> Tuple[str, str]:
    """Return (version, text) of an instruction file; '#' lines are header comments."""
    version, body = "0.0.0", []
    for line in (INSTRUCTIONS_DIR / filename).read_text(encoding="utf-8").splitlines():
        if line.startswith("# Version:"):
            version = line.split(":", 1)[1].strip()
        elif not line.startswith("#"):
            body.append(line)
    return version, "\n".join(body).strip()


INSTRUCTIONS: Dict[str, Tuple[str, str]] = {agent: load_instruction(f) for agent, f in INSTRUCTION_FILES.items()}
PROMPT_VERSIONS: Dict[str, str] = {agent: version for agent, (version, _) in INSTRUCTIONS.items()}


def build_model(*, base_url: str, model: str, api_key: str, timeout_seconds: float) -> OpenAILlm:
    """One OpenAI-compatible model for all agents: per-request timeout, no client-side retries."""
    client = AsyncOpenAI(base_url=base_url, api_key=api_key or "EMPTY", timeout=timeout_seconds, max_retries=0)
    return OpenAILlm(model=model, client=client)


def build_root_agent(model, max_output_tokens: int) -> Workflow:
    config = types.GenerateContentConfig(temperature=0.1, max_output_tokens=max_output_tokens)
    common = dict(
        model=model,
        generate_content_config=config,
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
        before_model_callback=budget_and_truncate,
        after_model_callback=record_usage,
        on_model_error_callback=record_model_error,
    )
    tool_callbacks = dict(before_tool_callback=enforce_tool_bounds, after_tool_callback=redact_and_delimit)

    evidence_agent = LlmAgent(
        name="evidence_agent",
        description="Reports what the firewall observed for this incident and whether it was blocked.",
        instruction=INSTRUCTIONS["evidence_agent"][1],
        tools=list(EVIDENCE_TOOLS),
        include_contents="none",
        output_key="evidence_notes",
        **tool_callbacks,
        **common,
    )
    context_agent = LlmAgent(
        name="context_agent",
        description="Reports what is known about the incident's hosts and signatures, and the eligible actions.",
        instruction=INSTRUCTIONS["context_agent"][1],
        tools=list(CONTEXT_TOOLS),
        include_contents="none",
        output_key="context_notes",
        **tool_callbacks,
        **common,
    )
    # skip_summarization stays False (ADR 005, deviation): with True, ADK ends the master's turn as
    # soon as the first specialist answers, so the master could neither call the second specialist
    # nor write investigation_notes.
    incident_investigator = LlmAgent(
        name="incident_investigator",
        description="Lead analyst: gathers evidence and context through the specialists and writes investigation notes.",
        instruction=INSTRUCTIONS["incident_investigator"][1],
        tools=[AgentTool(agent=evidence_agent), AgentTool(agent=context_agent)],
        output_key="investigation_notes",
        **tool_callbacks,
        **common,
    )
    assessment_writer = LlmAgent(
        name="assessment_writer",
        description="Writes the schema-bound assessment from the investigation notes.",
        instruction=INSTRUCTIONS["assessment_writer"][1],
        output_schema=WriterAssessment,
        include_contents="none",
        output_key="assessment_json",
        **common,
    )
    return Workflow(name="investigation", edges=[(START, incident_investigator, assessment_writer)])


def __getattr__(name: str):
    """``root_agent`` for ``adk`` tooling (plan C2.2), built from settings on first access."""
    if name == "root_agent":
        from config.settings import get_settings

        s = get_settings()
        model = build_model(base_url=s.llm_base_url, model=s.llm_model, api_key=s.llm_api_key, timeout_seconds=s.llm_timeout_seconds)
        return build_root_agent(model, s.llm_max_output_tokens)
    raise AttributeError(name)
