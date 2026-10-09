#!/usr/bin/env python3
"""Phase C.0 ADK compatibility spike (not shipped in the runtime image).

Runs the five steps of docs/GEMINI-PHASE-B1-AND-PHASE-C-ADK-PLAN.md section 2
(C0.2) through the real Google ADK against an OpenAI-compatible endpoint and
prints a Markdown transcript of everything it did and asserted:

  1. LlmAgent + LiteLlm + one plain-function tool: one tool call, result used.
  2. LlmAgent with output_schema=QwenAssessment, no tools, include_contents='none',
     fed a fixed note through session state: the output validates.
  3. SequentialAgent of both through Runner with RunConfig(max_llm_calls=4) and
     DatabaseSessionService on a scratch PostgreSQL database: session and event
     rows exist.
  4. Budget: max_llm_calls=1 with an instruction that needs two calls: record
     exactly what ADK raises or emits.
  5. Record versions, the vLLM flags the operator must use, p50/p95 latency of
     the three-call pipeline and token counts from the endpoint's usage.

Environment:
  LLM_BASE_URL        OpenAI-compatible base URL (default http://127.0.0.1:18995/v1)
  LLM_MODEL           served model name (default spike-fake-qwen only with --fake)
  LLM_API_KEY         API key if the server was started with --api-key (default EMPTY;
                      never printed)
  SPIKE_DATABASE_URL  SQLAlchemy async URL of a scratch database, for example
                      postgresql+asyncpg://postgres@127.0.0.1:55432/c0_spike
  LLM_TIMEOUT_SECONDS per-request timeout passed to LiteLlm (default 120)

Flags:
  --fake         start scripts/adk_spike_fake_vllm.py on the LLM_BASE_URL port first
  --report PATH  also write the transcript to PATH
  --notes PATH   include this hand-written Markdown file verbatim, under a
                 "Notes (hand-written)" heading, ahead of the transcript
  --runs N       measured pipeline runs for the latency statistics (default 8, min 5)

Agents never write: nothing here touches the service's own tables. The spike
creates only ADK's own session tables, refuses a database whose name does not
contain "spike" unless --allow-any-database is given, and checks by row count
that no pre-existing non-ADK table changed.

Exit status is non-zero when any assertion fails.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import importlib.metadata as md
import json
import math
import os
import platform
import re
import socket
import statistics
import subprocess
import sys
import time
import traceback
import uuid
import warnings
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Keep litellm from fetching its model price map from the internet at import time, and keep
# loopback traffic off any configured proxy. Both must be set before litellm is imported.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
_no_proxy = [p for p in os.environ.get("NO_PROXY", os.environ.get("no_proxy", "")).split(",") if p]
for _host in ("127.0.0.1", "localhost"):
    if _host not in _no_proxy:
        _no_proxy.append(_host)
os.environ["NO_PROXY"] = os.environ["no_proxy"] = ",".join(_no_proxy)

try:
    import httpx
    from google.adk.agents import LlmAgent, SequentialAgent
    from google.adk.agents.run_config import RunConfig
    from google.adk.models.lite_llm import LiteLlm
    from google.adk.runners import Runner
    from google.adk.sessions import DatabaseSessionService, InMemorySessionService
    from google.adk.tools.agent_tool import AgentTool
    from google.genai import types
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy import text as sa_text
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine
except ImportError as exc:  # pragma: no cover - exercised only on machines without ADK
    sys.stderr.write(
        "adk_spike: the Google ADK stack is not importable in this interpreter.\n"
        f"  ImportError: {exc}\n"
        "  Install the pins in requirements-agent.in into a scratch environment first.\n"
    )
    raise SystemExit(2)

try:
    import litellm as _litellm

    _litellm.suppress_debug_info = True
except Exception:  # pragma: no cover
    _litellm = None

from src.investigation.schemas import QwenAssessment  # noqa: E402

APP_NAME = "forti-investigator-c0-spike"
USER_ID = "system"
DEFAULT_BASE_URL = "http://127.0.0.1:18995/v1"
DEFAULT_FAKE_MODEL = "spike-fake-qwen"
VLLM_FLAGS = "--enable-auto-tool-choice --tool-call-parser hermes"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MIN_RUNS = 5

# ADK's own session tables (google/adk/sessions/schemas v0 and v1). Anything else in the
# scratch database is somebody else's and must not change while the spike runs.
ADK_TABLES = {"sessions", "events", "app_states", "user_states", "adk_internal_metadata"}
# The service's own tables (migrations/*.sql). If any exist in the scratch database the transcript
# says so, and the before/after row-count check proves the spike left them untouched.
SERVICE_TABLES = {
    "query_checkpoints", "coverage_gaps", "selected_events", "incidents", "incident_revisions",
    "jobs", "notification_outbox", "rejected_events", "model_runs", "episodes", "schema_migrations",
}

FIXED_NOTE = """\
INCIDENT NOTE (fixed fixture for the C.0 spike, not real data)
incident_id: INC-SPIKE-0001
incident_revision: 3
visibility_scope: FIREWALL_ONLY
source_ip: 198.51.100.45
target_ip: 203.0.113.10
enforcement: ALLOWED_OR_DETECTED
deterministic_severity_floor: HIGH
signature: Apache.Log4j.Error.Log.Remote.Code.Execution
observed: 14 IPS detections over 90 seconds, action=detected (the sessions were not dropped)
evidence: EVID-1 (IPS detection at 12:00:02), EVID-2 (IPS detection at 12:00:31)
"""
NOTE_EVIDENCE_IDS = {"EVID-1", "EVID-2"}

TOOL_INSTRUCTION = (
    "You are a test agent. Call the tool echo_evidence exactly once with evidence_id set to EVID-1. "
    "After the tool returns, reply with exactly one sentence that quotes the value of the echo field "
    "from the tool result. Do not call the tool a second time."
)
WRITER_INSTRUCTION = (
    "Produce exactly one assessment object that matches the schema, using only the notes below. "
    "Copy incident_id and incident_revision exactly from the incident note. Findings cite evidence ids "
    "that appear in the notes. Recommended action ids stay empty because no action catalog is provided. "
    "Never claim confirmed compromise.\n\n"
    "Incident note:\n{investigation_notes}\n\n"
    "Tool echo (may be empty):\n{tool_echo?}\n"
)


# --------------------------------------------------------------------------------------
# Configuration, redaction, transcript
# --------------------------------------------------------------------------------------


@dataclasses.dataclass
class SpikeConfig:
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_FAKE_MODEL
    api_key: str = "EMPTY"
    db_url: Optional[str] = None
    fake: bool = False
    runs: int = 8
    llm_timeout: float = 120.0
    run_timeout: float = 240.0
    allow_any_database: bool = False

    @property
    def root_url(self) -> str:
        url = self.base_url.rstrip("/")
        return url[: -len("/v1")] if url.endswith("/v1") else url


def _is_private_or_site_host(host: Optional[str]) -> bool:
    return bool(host) and host not in LOOPBACK_HOSTS


class Redactor:
    """Keeps hostnames, addresses, credentials and local paths out of the transcript."""

    def __init__(self, cfg: SpikeConfig) -> None:
        self.subs: List[tuple] = []
        llm_host = urlparse(cfg.base_url).hostname
        if _is_private_or_site_host(llm_host):
            self.subs.append((re.compile(re.escape(llm_host)), "<llm-host>"))
        if cfg.db_url:
            try:
                db_host = make_url(cfg.db_url).host
            except Exception:
                db_host = None
            if _is_private_or_site_host(db_host):
                self.subs.append((re.compile(re.escape(db_host)), "<db-host>"))
        if cfg.api_key and cfg.api_key != "EMPTY":
            self.subs.append((re.compile(re.escape(cfg.api_key)), "<api-key>"))
        self.subs += [
            (re.compile(r"(\w[\w+]*://[^:/@\s]+):[^@/\s]+@"), r"\1:<redacted>@"),
            (re.compile(r'File "[^"]*site-packages/'), 'File "<site-packages>/'),
            (re.compile(r"/[^\s\"']*/site-packages/"), "<site-packages>/"),
            (re.compile(re.escape(str(REPO_ROOT))), "<repo>"),
            (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<private-ip>"),
            (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"), "<private-ip>"),
            (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "<private-ip>"),
        ]

    def __call__(self, text: str) -> str:
        for pattern, repl in self.subs:
            text = pattern.sub(repl, text)
        return text


class Transcript:
    """Collects Markdown lines, echoes them to stdout, and counts assertion results."""

    def __init__(self, redact: Callable[[str], str], echo: bool = True) -> None:
        self.lines: List[str] = []
        self.redact = redact
        self.echo = echo
        self.passed = 0
        self.failures: List[str] = []
        self.step_results: List[tuple] = []  # (step title, passed, failed)

    def _add(self, text: str) -> None:
        text = self.redact(text)
        self.lines.append(text)
        if self.echo:
            print(text, flush=True)

    def _gap(self) -> None:
        """Markdown needs a blank line between a list item and the block that follows it."""
        if self.lines and self.lines[-1].strip() and not self.lines[-1].endswith("\n"):
            self._add("")

    def h1(self, title: str) -> None:
        self._add(f"# {title}\n")

    def h2(self, title: str) -> None:
        self._gap()
        self._add(f"## {title}\n")

    def para(self, text: str) -> None:
        self._gap()
        self._add(text + "\n")

    def bullet(self, text: str) -> None:
        self._add(f"- {text}")

    def code(self, text: str, lang: str = "") -> None:
        self._gap()
        fence = "````" if "```" in text else "```"
        self._add(f"{fence}{lang}\n{text.rstrip()}\n{fence}\n")

    def details(self, summary: str, text: str) -> None:
        self._gap()
        self._add(f"<details><summary>{summary}</summary>\n")
        fence = "````" if "```" in text else "```"
        self._add(f"{fence}\n{text.rstrip()}\n{fence}\n")
        self._add("</details>\n")

    def table(self, rows: List[List[str]], header: List[str]) -> None:
        self._gap()
        self._add("| " + " | ".join(header) + " |")
        self._add("|" + "|".join("---" for _ in header) + "|")
        for row in rows:
            self._add("| " + " | ".join(str(c).replace("|", "\\|") for c in row) + " |")
        self._add("")

    def check(self, description: str, ok: bool, detail: str = "") -> bool:
        tag = "PASS" if ok else "FAIL"
        suffix = f" ({detail})" if detail else ""
        self._add(f"- **{tag}** {description}{suffix}")
        if ok:
            self.passed += 1
        else:
            self.failures.append(description)
        return ok

    def render(self) -> str:
        return "\n".join(self.lines) + "\n"


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------


def package_version(name: str) -> str:
    try:
        return md.version(name)
    except md.PackageNotFoundError:
        return "not installed"


def nearest_rank(values: List[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def trimmed_json(obj: Any, limit: int = 1800) -> str:
    text = json.dumps(obj, indent=2, default=str)
    return text if len(text) <= limit else text[:limit] + f"\n... ({len(text) - limit} more characters)"


def new_session_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def mask_url(url: str) -> str:
    try:
        parsed = make_url(url)
        return parsed.render_as_string(hide_password=True)
    except Exception:
        return re.sub(r"(://[^:/@]+):[^@]+@", r"\1:***@", url)


# Tool call bookkeeping: the tool records every real invocation so the spike can prove the tool
# ran exactly as many times as the model asked, independently of what ADK reports.
TOOL_LOG: List[Dict[str, Any]] = []


def echo_evidence(evidence_id: str) -> dict:
    """Echo an evidence id back together with a marker that proves this function ran.

    Args:
        evidence_id: The evidence identifier to echo, for example EVID-1.

    Returns:
        A dict with a status, the evidence id and an echo marker.
    """
    marker = f"echo-{uuid.uuid4().hex[:8]}"
    TOOL_LOG.append({"evidence_id": evidence_id, "echo": marker})
    return {"status": "success", "evidence_id": evidence_id, "echo": marker}


class CallRecorder:
    """before_model_callback target: counts the model calls ADK attempts."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def reset(self) -> None:
        self.calls.clear()

    def before_model(self, callback_context, llm_request):  # ADK passes both by keyword
        config = getattr(llm_request, "config", None)
        self.calls.append(
            {
                "agent": getattr(callback_context, "agent_name", "?"),
                "contents": len(getattr(llm_request, "contents", None) or []),
                "tools": sorted((getattr(llm_request, "tools_dict", None) or {}).keys()),
                "response_schema": bool(
                    getattr(config, "response_schema", None) or getattr(config, "response_json_schema", None)
                ),
            }
        )
        return None


class FakeCapture:
    """Client for GET /capture of scripts/adk_spike_fake_vllm.py (absent on a real server)."""

    def __init__(self, root_url: str) -> None:
        self.root = root_url

    @classmethod
    def detect(cls, root_url: str) -> Optional["FakeCapture"]:
        try:
            with httpx.Client(timeout=3.0) as client:
                data = client.get(f"{root_url}/capture").json()
            if isinstance(data, dict) and "requests" in data:
                return cls(root_url)
        except Exception:
            pass
        return None

    def requests(self) -> List[Dict[str, Any]]:
        with httpx.Client(timeout=10.0) as client:
            return client.get(f"{self.root}/capture").json()["requests"]

    def count(self) -> int:
        return len(self.requests())


@dataclasses.dataclass
class Ctx:
    cfg: SpikeConfig
    tr: Transcript
    rec: CallRecorder
    cap: Optional[FakeCapture]

    def server_count(self) -> int:
        return self.cap.count() if self.cap else 0

    def server_requests_since(self, n0: int) -> List[Dict[str, Any]]:
        return self.cap.requests()[n0:] if self.cap else []


@dataclasses.dataclass
class RunRecord:
    events: List[Any] = dataclasses.field(default_factory=list)
    error: Optional[BaseException] = None
    tb: str = ""
    elapsed: float = 0.0

    def function_calls(self) -> List[Dict[str, Any]]:
        out = []
        for ev in self.events:
            for fc in ev.get_function_calls() or []:
                out.append({"author": ev.author, "name": fc.name, "args": dict(fc.args or {})})
        return out

    def function_responses(self) -> List[Dict[str, Any]]:
        out = []
        for ev in self.events:
            for fr in ev.get_function_responses() or []:
                out.append({"author": ev.author, "name": fr.name, "response": fr.response})
        return out

    @staticmethod
    def event_text(ev) -> str:
        parts = (ev.content.parts if ev.content and ev.content.parts else []) or []
        return "".join(p.text for p in parts if getattr(p, "text", None) and not getattr(p, "thought", False))

    def final_text(self, author: Optional[str] = None) -> str:
        for ev in reversed(self.events):
            if author and ev.author != author:
                continue
            if ev.is_final_response() and self.event_text(ev):
                return self.event_text(ev)
        return ""

    def usage(self) -> Dict[str, int]:
        total = {"prompt": 0, "completion": 0, "total": 0}
        for ev in self.events:
            um = getattr(ev, "usage_metadata", None)
            if um is None:
                continue
            total["prompt"] += um.prompt_token_count or 0
            total["completion"] += um.candidates_token_count or 0
            total["total"] += um.total_token_count or 0
        return total

    def summaries(self) -> List[str]:
        rows = []
        for ev in self.events:
            kinds = []
            for fc in ev.get_function_calls() or []:
                kinds.append(f"function_call {fc.name}({json.dumps(dict(fc.args or {}))})")
            for fr in ev.get_function_responses() or []:
                kinds.append(f"function_response {fr.name}")
            txt = self.event_text(ev)
            if txt:
                kinds.append("text " + json.dumps(txt[:70] + ("..." if len(txt) > 70 else "")))
            if getattr(ev, "error_code", None) or getattr(ev, "error_message", None):
                kinds.append(f"ERROR code={ev.error_code!r} message={ev.error_message!r}")
            if getattr(ev, "partial", None):
                kinds.append("partial")
            if ev.is_final_response():
                kinds.append("final")
            rows.append(f"author={ev.author or '-'}: " + ("; ".join(kinds) if kinds else "(no content)"))
        return rows


def make_model(cfg: SpikeConfig) -> LiteLlm:
    return LiteLlm(
        model=f"openai/{cfg.model}",
        api_base=cfg.base_url,
        api_key=cfg.api_key,
        timeout=cfg.llm_timeout,
    )


def deterministic_config() -> types.GenerateContentConfig:
    return types.GenerateContentConfig(temperature=0.0)


def build_tool_agent(cfg: SpikeConfig, rec: CallRecorder, output_key: Optional[str] = None) -> LlmAgent:
    return LlmAgent(
        name="tool_agent",
        model=make_model(cfg),
        description="Calls echo_evidence once and reports the echo marker.",
        instruction=TOOL_INSTRUCTION,
        tools=[echo_evidence],
        output_key=output_key,
        generate_content_config=deterministic_config(),
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
        before_model_callback=rec.before_model,
    )


def build_writer(cfg: SpikeConfig, rec: CallRecorder) -> LlmAgent:
    return LlmAgent(
        name="assessment_writer",
        model=make_model(cfg),
        description="Writes the schema-bound assessment from the notes in session state.",
        instruction=WRITER_INSTRUCTION,
        output_schema=QwenAssessment,
        include_contents="none",
        output_key="assessment_json",
        generate_content_config=deterministic_config(),
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
        before_model_callback=rec.before_model,
    )


def build_pipeline(cfg: SpikeConfig, rec: CallRecorder) -> SequentialAgent:
    return SequentialAgent(
        name="spike_pipeline",
        sub_agents=[build_tool_agent(cfg, rec, output_key="tool_echo"), build_writer(cfg, rec)],
    )


async def drive(runner: Runner, session_id: str, run_config: RunConfig, timeout: float, text: str = "Run the spike task.") -> RunRecord:
    """Run one invocation to completion, capturing events and any exception verbatim."""
    record = RunRecord()
    message = types.Content(role="user", parts=[types.Part(text=text)])
    started = time.perf_counter()

    async def consume() -> None:
        async for event in runner.run_async(
            user_id=USER_ID, session_id=session_id, new_message=message, run_config=run_config
        ):
            record.events.append(event)

    try:
        await asyncio.wait_for(consume(), timeout=timeout)
    except Exception as exc:  # captured, never swallowed: the caller asserts on it
        record.error = exc
        record.tb = traceback.format_exc()
    record.elapsed = time.perf_counter() - started
    return record


def parse_assessment(raw: Any) -> QwenAssessment:
    if isinstance(raw, QwenAssessment):
        return raw
    if isinstance(raw, (str, bytes)):
        return QwenAssessment.model_validate_json(raw)
    return QwenAssessment.model_validate(raw)


def describe_wire(request: Dict[str, Any]) -> str:
    roles = [m.get("role") for m in request.get("messages", [])]
    tools = [t.get("function", {}).get("name") for t in request.get("tools", [])]
    rf = request.get("response_format")
    rf_desc = None
    if isinstance(rf, dict):
        rf_desc = rf.get("type")
        name = (rf.get("json_schema") or {}).get("name")
        strict = (rf.get("json_schema") or {}).get("strict")
        if name:
            rf_desc += f" name={name} strict={strict}"
    return f"roles={roles} tools={tools} response_format={rf_desc} keys={request.get('request_keys')}"


# --------------------------------------------------------------------------------------
# Database inspection (ADK's own tables only)
# --------------------------------------------------------------------------------------


class DbProbe:
    def __init__(self, db_url: str) -> None:
        self.engine = create_async_engine(db_url)

    async def tables(self) -> List[str]:
        async with self.engine.connect() as conn:
            return sorted(await conn.run_sync(lambda c: sa_inspect(c).get_table_names()))

    async def counts(self, tables: List[str]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        async with self.engine.connect() as conn:
            for name in tables:
                out[name] = (await conn.execute(sa_text(f'SELECT count(*) FROM "{name}"'))).scalar_one()
        return out

    async def fetch(self, sql: str, **params: Any) -> List[Any]:
        async with self.engine.connect() as conn:
            return list((await conn.execute(sa_text(sql), params)).all())

    async def close(self) -> None:
        await self.engine.dispose()


# --------------------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------------------


async def step1_tool_roundtrip(ctx: Ctx) -> None:
    tr, rec = ctx.tr, ctx.rec
    tr.h2("Step 1: LlmAgent + LiteLlm + one plain-function tool")
    tr.para(
        f"`LlmAgent(model=LiteLlm(model=\"openai/{ctx.cfg.model}\", api_base=..., api_key=...), "
        "tools=[echo_evidence])` run through `Runner` with `InMemorySessionService` and `RunConfig(max_llm_calls=4)`."
    )
    TOOL_LOG.clear()
    rec.reset()
    n0 = ctx.server_count()
    svc = InMemorySessionService()
    runner = Runner(app_name=APP_NAME, agent=build_tool_agent(ctx.cfg, rec), session_service=svc)
    sid = new_session_id("s1")
    await svc.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid)
    rr = await drive(runner, sid, RunConfig(max_llm_calls=4), ctx.cfg.run_timeout)

    tr.para("Events yielded by the runner:")
    tr.code("\n".join(rr.summaries()) or "(none)")
    tr.check("run completed without an exception", rr.error is None, repr(rr.error) if rr.error else f"{rr.elapsed:.2f}s")
    if rr.error:
        tr.code(rr.tb)
        return

    calls = rr.function_calls()
    tr.check(
        "exactly one tool call event, echo_evidence with evidence_id EVID-1",
        len(calls) == 1 and calls[0]["name"] == "echo_evidence" and calls[0]["args"] == {"evidence_id": "EVID-1"},
        json.dumps(calls),
    )
    tr.check("exactly one tool response event", len(rr.function_responses()) == 1)
    tr.check("the tool function executed exactly once", len(TOOL_LOG) == 1, json.dumps(TOOL_LOG))
    marker = TOOL_LOG[0]["echo"] if TOOL_LOG else "<no-marker>"
    final = rr.final_text()
    tr.check("the tool result reached the final answer (marker quoted)", marker in final, f"final={final!r}")
    tr.check("two model calls were attempted (tool request, then answer)", len(rec.calls) == 2, json.dumps(rec.calls))

    if ctx.cap:
        reqs = ctx.server_requests_since(n0)
        tr.check("the endpoint received exactly two requests", len(reqs) == 2, f"{len(reqs)} received")
        if len(reqs) == 2:
            first_tools = [t.get("function", {}).get("name") for t in reqs[0]["tools"]]
            tr.check("request 1 declared echo_evidence as an OpenAI function tool", first_tools == ["echo_evidence"], str(first_tools))
            tr.check(
                "request 2 carried a tool role message with the tool result",
                any(m.get("role") == "tool" for m in reqs[1]["messages"]),
            )
            tr.para("Wire format observed by the endpoint:")
            tr.code(
                f"request 1: {describe_wire(reqs[0])}\nrequest 2: {describe_wire(reqs[1])}\n\n"
                f"request 1 tools[0]:\n{trimmed_json(reqs[0]['tools'][0] if reqs[0]['tools'] else None)}"
            )
    await runner.close()


async def step2_output_schema(ctx: Ctx) -> None:
    tr, rec = ctx.tr, ctx.rec
    tr.h2("Step 2: output_schema=QwenAssessment, no tools, include_contents='none', note from session state")
    rec.reset()
    n0 = ctx.server_count()
    svc = InMemorySessionService()
    runner = Runner(app_name=APP_NAME, agent=build_writer(ctx.cfg, rec), session_service=svc)
    sid = new_session_id("s2")
    await svc.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid, state={"investigation_notes": FIXED_NOTE})
    rr = await drive(runner, sid, RunConfig(max_llm_calls=4), ctx.cfg.run_timeout)

    tr.para("Events yielded by the runner:")
    tr.code("\n".join(rr.summaries()) or "(none)")
    tr.check("run completed without an exception", rr.error is None, repr(rr.error) if rr.error else f"{rr.elapsed:.2f}s")
    if rr.error:
        tr.code(rr.tb)
        return

    final = rr.final_text()
    tr.check("exactly one model call was attempted and it carried a response schema", len(rec.calls) == 1 and rec.calls[0]["response_schema"], json.dumps(rec.calls))
    tr.check("the writer declared no tools", all(not c["tools"] for c in rec.calls))
    try:
        assessment = parse_assessment(final)
        tr.check("the final text validates as QwenAssessment", True)
    except Exception as exc:
        tr.check("the final text validates as QwenAssessment", False, f"{type(exc).__name__}: {str(exc)[:400]}")
        tr.code(final[:1500])
        await runner.close()
        return

    stored = (await svc.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid)).state.get("assessment_json")
    try:
        parse_assessment(stored)
        tr.check("the output_key value in session state validates as QwenAssessment", True, f"stored as {type(stored).__name__}")
    except Exception as exc:
        tr.check("the output_key value in session state validates as QwenAssessment", False, f"{type(exc).__name__}: {exc}")

    tr.check(
        "identity from the note survived the round trip (incident_id and incident_revision)",
        assessment.incident_id == "INC-SPIKE-0001" and assessment.incident_revision == 3,
        f"incident_id={assessment.incident_id!r} incident_revision={assessment.incident_revision}",
    )
    cited = {e for f in assessment.findings for e in f.evidence_ids}
    tr.check("every cited evidence id appears in the note", bool(cited) and cited <= NOTE_EVIDENCE_IDS, f"cited={sorted(cited)}")
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    tr.para(
        f"Informational (not asserted): severity={assessment.severity} against floor HIGH "
        f"({'at or above' if order.index(assessment.severity) >= order.index('HIGH') else 'BELOW'} the floor); "
        f"enforcement={assessment.enforcement}; findings={len(assessment.findings)}."
    )
    tr.para("Assessment as parsed:")
    tr.code(trimmed_json(assessment.model_dump(mode="json")), "json")

    if ctx.cap:
        reqs = ctx.server_requests_since(n0)
        tr.check("the endpoint received exactly one request", len(reqs) == 1, f"{len(reqs)} received")
        if reqs:
            rf = reqs[0].get("response_format") or {}
            tr.check(
                "the request carried response_format json_schema named QwenAssessment",
                rf.get("type") == "json_schema" and (rf.get("json_schema") or {}).get("name") == "QwenAssessment",
                json.dumps({k: v for k, v in rf.items() if k != "json_schema"}) + f" name={(rf.get('json_schema') or {}).get('name')}",
            )
            tr.check("the request carried no tools", not reqs[0]["tools"])
            tr.check(
                "the note reached the model through the instruction (state templating)",
                "INC-SPIKE-0001" in json.dumps(reqs[0]["messages"]),
            )
            schema = (rf.get("json_schema") or {}).get("schema") or {}
            props = list(schema.get("properties", {}))
            required = list(schema.get("required", []))
            tr.para("JSON schema ADK put on the wire (what vLLM guided decoding would have to honour):")
            tr.code(
                f"strict={(rf.get('json_schema') or {}).get('strict')} additionalProperties={schema.get('additionalProperties')}\n"
                f"properties ({len(props)}): {props}\n"
                f"required   ({len(required)}): {sorted(required)}\n"
                f"not required: {sorted(set(props) - set(required)) or 'none'}\n"
                f"$defs: {sorted(schema.get('$defs', {}))}; 'const' and 'anyOf' with null present: "
                f"{'const' in json.dumps(schema)} / {'anyOf' in json.dumps(schema)}"
            )
            server_owned = sorted({"assessment_source", "model_reported_enforcement"} & set(required))
            tr.para(
                f"Informational: ADK's strict mode marks every property required, including the service-owned fields {server_owned}. "
                "A model that must fill them is a C.1 design point (trim the writer's schema or overwrite those fields after parsing)."
            )
            tr.para("Wire format observed by the endpoint:")
            tr.code(describe_wire(reqs[0]))
            tr.para("Messages the endpoint received (include_contents='none'):")
            tr.code(trimmed_json([{"role": m.get("role"), "content": str(m.get("content"))[:300]} for m in reqs[0]["messages"]]), "json")
    await runner.close()


async def step3_pipeline_database(ctx: Ctx, db: DbProbe) -> Optional[DbProbe]:
    tr, rec = ctx.tr, ctx.rec
    tr.h2("Step 3: SequentialAgent through Runner with max_llm_calls=4 and DatabaseSessionService")
    tr.para(
        f"Database: `{mask_url(ctx.cfg.db_url)}`. App name `{APP_NAME}`, user `{USER_ID}`. "
        "The pipeline is `SequentialAgent([tool_agent, assessment_writer])`, three model calls in total."
    )
    before_tables = await db.tables()
    before_counts = await db.counts([t for t in before_tables if t not in ADK_TABLES])
    tr.para(f"Tables present before the run: {before_tables or '(none)'}")
    present_service = sorted(set(before_tables) & SERVICE_TABLES)
    if present_service:
        tr.para(f"Service tables present (they are left untouched and counted before and after): {present_service}")

    TOOL_LOG.clear()
    rec.reset()
    n0 = ctx.server_count()
    svc = DatabaseSessionService(db_url=ctx.cfg.db_url)
    runner = Runner(app_name=APP_NAME, agent=build_pipeline(ctx.cfg, rec), session_service=svc)
    sid = new_session_id("s3")
    await svc.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid, state={"investigation_notes": FIXED_NOTE})
    rr = await drive(runner, sid, RunConfig(max_llm_calls=4), ctx.cfg.run_timeout)

    tr.para("Events yielded by the runner:")
    tr.code("\n".join(rr.summaries()) or "(none)")
    ok_run = tr.check("run completed without an exception", rr.error is None, repr(rr.error) if rr.error else f"{rr.elapsed:.2f}s (first run against the database)")
    if rr.error:
        tr.code(rr.tb)
        await runner.close()
        return None

    tr.check("three model calls were attempted (tool request, answer, structured writer)", len(rec.calls) == 3, json.dumps([c["agent"] for c in rec.calls]))
    tr.check("the tool function executed exactly once", len(TOOL_LOG) == 1)
    marker = TOOL_LOG[0]["echo"] if TOOL_LOG else "<no-marker>"
    reread = await svc.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid)
    state = reread.state if reread else {}
    tr.check("the tool agent's output_key landed in session state and quotes the marker", marker in str(state.get("tool_echo", "")), f"tool_echo={str(state.get('tool_echo'))[:120]!r}")
    try:
        assessment = parse_assessment(state.get("assessment_json"))
        tr.check("the writer's output in session state validates as QwenAssessment", True, f"incident_id={assessment.incident_id} revision={assessment.incident_revision}")
    except Exception as exc:
        tr.check("the writer's output in session state validates as QwenAssessment", False, f"{type(exc).__name__}: {str(exc)[:300]}")

    after_tables = await db.tables()
    created = sorted(set(after_tables) - set(before_tables))
    tr.para(f"Tables present after the run: {after_tables}. Created by this run: {created or '(none)'}")
    tr.check("every table ADK created is one of ADK's own session tables", set(created) <= ADK_TABLES and bool(set(after_tables) & {"sessions", "events"}), str(created))

    sess_rows = await db.fetch("SELECT id, app_name, user_id, state FROM sessions WHERE id = :sid", sid=sid)
    tr.check("a sessions row exists for the run", len(sess_rows) == 1 and sess_rows[0].app_name == APP_NAME and sess_rows[0].user_id == USER_ID, f"{len(sess_rows)} row(s)")
    persisted_state = sess_rows[0].state if sess_rows else {}
    if isinstance(persisted_state, str):
        persisted_state = json.loads(persisted_state)
    tr.check("the sessions row holds the writer's output and the fixed note", "assessment_json" in persisted_state and "investigation_notes" in persisted_state, f"state keys={sorted(persisted_state)}")
    event_rows = await db.fetch("SELECT id, invocation_id FROM events WHERE session_id = :sid AND app_name = :app", sid=sid, app=APP_NAME)
    db_event_ids = {r.id for r in event_rows}
    yielded_ids = {ev.id for ev in rr.events if not getattr(ev, "partial", False)}
    tr.check("events rows exist for the run", len(event_rows) >= 1, f"{len(event_rows)} row(s) in events for this session; runner yielded {len(rr.events)} event(s)")
    tr.check("every non-partial event the runner yielded is persisted", yielded_ids <= db_event_ids, f"missing={sorted(yielded_ids - db_event_ids)}")
    authors = await db.fetch("SELECT event_data->>'author' AS author FROM events WHERE session_id = :sid ORDER BY timestamp", sid=sid)
    tr.para(f"Persisted event authors in order: {[a.author for a in authors]}")

    fresh = DatabaseSessionService(db_url=ctx.cfg.db_url)
    revived = await fresh.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid)
    tr.check(
        "a second DatabaseSessionService instance (new engine) reloads the session with its events and state",
        revived is not None and len(revived.events) >= 1 and "assessment_json" in revived.state,
        f"events={len(revived.events) if revived else 0}",
    )

    after_counts = await db.counts(list(before_counts))
    tr.check("no pre-existing non-ADK table changed (agents never write to the service's tables)", after_counts == before_counts, f"before={before_counts} after={after_counts}")

    if ctx.cap:
        reqs = ctx.server_requests_since(n0)
        tr.check("the endpoint received exactly three requests", len(reqs) == 3, f"{len(reqs)} received")
    await runner.close()
    await fresh.close()
    return db if ok_run else None


@dataclasses.dataclass
class BudgetObservation:
    label: str
    raised: bool = False
    exception_class: str = ""
    exception_module: str = ""
    message: str = ""
    chain: List[str] = dataclasses.field(default_factory=list)
    error_events: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    events_before_stop: int = 0
    final_text: str = ""


def exception_chain(exc: BaseException) -> List[str]:
    """The raised exception first, then each exception it was raised while handling."""
    out, seen = [], set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        out.append(f"{type(cur).__module__}.{type(cur).__qualname__}: {cur}")
        cur = cur.__cause__ or (None if cur.__suppress_context__ else cur.__context__)
    return out


async def budget_case(
    ctx: Ctx,
    db: Optional[DbProbe],
    label: str,
    agent: Any,
    max_calls: int,
    state: Optional[Dict[str, Any]],
    expect_attempted: int,
    expect_sent: int,
    expect_tool_runs: int,
    cutoff_author: str,
    absent_state_key: Optional[str] = None,
) -> BudgetObservation:
    tr, rec = ctx.tr, ctx.rec
    tr.para(f"**{label}**")
    TOOL_LOG.clear()
    rec.reset()
    n0 = ctx.server_count()
    svc = DatabaseSessionService(db_url=ctx.cfg.db_url) if (db and ctx.cfg.db_url) else InMemorySessionService()
    runner = Runner(app_name=APP_NAME, agent=agent, session_service=svc)
    sid = new_session_id("s4")
    await svc.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid, state=state)
    rr = await drive(runner, sid, RunConfig(max_llm_calls=max_calls), ctx.cfg.run_timeout)

    obs = BudgetObservation(label=label, events_before_stop=len(rr.events), final_text=rr.final_text(cutoff_author))
    if rr.error is not None:
        obs.raised = True
        obs.exception_class = type(rr.error).__qualname__
        obs.exception_module = type(rr.error).__module__
        obs.message = str(rr.error)
        obs.chain = exception_chain(rr.error)
    for ev in rr.events:
        if getattr(ev, "error_code", None) or getattr(ev, "error_message", None):
            obs.error_events.append(
                {"author": ev.author, "error_code": ev.error_code, "error_message": ev.error_message, "is_final_response": ev.is_final_response()}
            )

    tr.para("Events yielded before the run stopped:")
    tr.code("\n".join(rr.summaries()) or "(none)")
    tr.para("Observed, verbatim:")
    if obs.raised:
        tr.code(
            f"Runner.run_async raised : {obs.exception_module}.{obs.exception_class}\n"
            f"str(exception)          : {obs.message}\n"
            f"repr(exception)         : {rr.error!r}\n"
            f"exception chain         : " + "\n                          <- while handling ".join(obs.chain) + "\n"
            f"events yielded first    : {len(rr.events)}"
        )
        tr.details("Full traceback of the raised exception (site-packages and repository paths collapsed)", rr.tb)
    else:
        tr.para("No exception left `Runner.run_async`.")
    if obs.error_events:
        tr.code("\n".join(json.dumps(e) for e in obs.error_events))
    else:
        tr.para("No yielded event carried an error code or message.")

    tr.check("the run stopped with an observable signal (exception or error event)", obs.raised or bool(obs.error_events))
    tr.check(f"the agent that hit the cut-off ({cutoff_author}) produced no final answer", not obs.final_text, f"its final text={obs.final_text!r}")
    tr.check(f"before_model_callback fired {expect_attempted} time(s) (the over-budget attempt included)", len(rec.calls) == expect_attempted, f"fired {len(rec.calls)}")
    if ctx.cap:
        sent = len(ctx.server_requests_since(n0))
        tr.check(f"only {expect_sent} request(s) reached the endpoint (the over-budget call was never sent)", sent == expect_sent, f"{sent} received")
    tr.check(
        "tool side effects that preceded the cut-off had already run",
        len(TOOL_LOG) == expect_tool_runs,
        f"tool executions={len(TOOL_LOG)}",
    )
    persisted = await svc.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid)
    tr.check("a session that tripped the budget is still readable afterwards", persisted is not None)
    if persisted is not None:
        tr.para(f"Session after the failure: {len(persisted.events)} persisted event(s), authors {[e.author for e in persisted.events]}, state keys {sorted(persisted.state)}.")
        if absent_state_key:
            tr.check(f"the over-budget agent's output key `{absent_state_key}` was not written", absent_state_key not in persisted.state)

    TOOL_LOG.clear()
    rec.reset()
    sid2 = new_session_id("s4b")
    await svc.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid2, state=state)
    rr2 = await drive(runner, sid2, RunConfig(max_llm_calls=4), ctx.cfg.run_timeout)
    tr.check(
        "the same Runner serves a fresh session normally afterwards (max_llm_calls=4)",
        rr2.error is None and bool(rr2.final_text()),
        repr(rr2.error) if rr2.error else f"{rr2.elapsed:.2f}s",
    )
    await runner.close()
    return obs


async def step4_budget(ctx: Ctx, db: Optional[DbProbe]) -> None:
    tr, rec = ctx.tr, ctx.rec
    tr.h2("Step 4: budget test, max_llm_calls=1 with an instruction that needs two calls")
    tr.para(
        "The `tool_agent` must call the tool (model call 1) and then answer (model call 2). With "
        "`RunConfig(max_llm_calls=1)` the second call is over budget. Nothing is asserted about *which* mechanism "
        "ADK uses; the point is to capture it exactly, because it decides the C.2 fallback path. A second case "
        "repeats the test in the topology C.1 will actually use, a `SequentialAgent` whose third model call (the "
        "writer) is the one over budget."
    )
    a = await budget_case(
        ctx, db, "Case 4a: bare LlmAgent, max_llm_calls=1 (the plan's literal test)",
        build_tool_agent(ctx.cfg, rec), 1, None, expect_attempted=2, expect_sent=1, expect_tool_runs=1,
        cutoff_author="tool_agent",
    )
    b = await budget_case(
        ctx, db, "Case 4b: SequentialAgent [tool_agent, assessment_writer], max_llm_calls=2",
        build_pipeline(ctx.cfg, rec), 2, {"investigation_notes": FIXED_NOTE},
        expect_attempted=3, expect_sent=2, expect_tool_runs=1, cutoff_author="assessment_writer",
        absent_state_key="assessment_json",
    )

    tr.check(
        "both cases surfaced the same exception class",
        a.raised and b.raised and (a.exception_module, a.exception_class) == (b.exception_module, b.exception_class),
        f"4a={a.exception_class or 'none'} 4b={b.exception_class or 'none'}",
    )
    findings = []
    for obs in (a, b):
        bits = []
        if obs.raised:
            bits.append(f"`Runner.run_async` raised `{obs.exception_module}.{obs.exception_class}` (`{obs.message}`)")
        if obs.error_events:
            e = obs.error_events[0]
            bits.append(
                f"it also yielded an event with `error_code={e['error_code']!r}` and `error_message={e['error_message']!r}`; "
                f"`Event.is_final_response()` is {e['is_final_response']} for that event"
            )
        findings.append(f"{obs.label.split(':')[0]}: " + (" and ".join(bits) if bits else "neither an exception nor an error event"))
    tr.para("Summary of what ADK did: " + "; ".join(findings) + ".")
    observations = []
    if a.raised and b.raised:
        observations.append(
            f"`Runner.run_async` raised `{a.exception_module}.{a.exception_class}` in both topologies, so the exception is the "
            "one signal present everywhere."
        )
    elif a.raised or b.raised:
        observations.append("The exception was not raised in both topologies; do not rely on it alone.")
    observations.append(
        f"An error event was yielded in case 4a: {bool(a.error_events)}; in case 4b: {bool(b.error_events)}."
    )
    if any(e["is_final_response"] for o in (a, b) for e in o.error_events):
        observations.append(
            "Where an error event is yielded, `Event.is_final_response()` is True for it, so a loop that stops at the first "
            "final-flagged event would take the error for the answer."
        )
    observations.append(
        "Events and session rows written before the cut-off remain (see the per-case checks), and tool calls that preceded the "
        "cut-off had already executed, so an abandoned run still leaves its side effects behind."
    )
    tr.para("What the two cases show: " + " ".join(observations))
    tr.para(
        "Recommended C.2 wrapper (analysis, not an observation): catch the exception class around the `async for`, treat it as "
        "the authoritative budget signal, discard partial output, and fall back with a budget-exhausted reason code; separately "
        "ignore any final-flagged event that carries `error_code`."
    )


async def probe_agent_tool_budget(ctx: Ctx, db: Optional[DbProbe]) -> None:
    """Informational probe beyond the plan: AgentTool round trip and how nested calls meet max_llm_calls."""
    tr, rec = ctx.tr, ctx.rec
    tr.h2("Extra probe (not in the plan): AgentTool nesting and the budget")
    tr.para(
        "C.1's master agent calls its specialists through `AgentTool`. This probe wraps the tool agent in `AgentTool` under a "
        "master `LlmAgent` and asks two questions: does the round trip work through LiteLlm, and are the nested agent's model "
        "calls counted against the caller's `max_llm_calls`? The master needs 2 model calls of its own and the nested agent 2 more."
    )

    def build_master() -> LlmAgent:
        return LlmAgent(
            name="master",
            model=make_model(ctx.cfg),
            instruction=(
                "Call the tool tool_agent exactly once with the request \"check EVID-1\", then answer in one sentence that "
                "quotes the echo value in the tool's reply. Do not call it a second time."
            ),
            tools=[AgentTool(agent=build_tool_agent(ctx.cfg, rec))],
            generate_content_config=deterministic_config(),
            disallow_transfer_to_parent=True,
            disallow_transfer_to_peers=True,
            before_model_callback=rec.before_model,
        )

    results: Dict[int, tuple] = {}
    for max_calls in (8, 2):
        TOOL_LOG.clear()
        rec.reset()
        n0 = ctx.server_count()
        svc = InMemorySessionService()
        runner = Runner(app_name=APP_NAME, agent=build_master(), session_service=svc)
        sid = new_session_id("s4x")
        await svc.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid)
        rr = await drive(runner, sid, RunConfig(max_llm_calls=max_calls), ctx.cfg.run_timeout)
        sent = len(ctx.server_requests_since(n0)) if ctx.cap else None
        results[max_calls] = (rr, len(rec.calls), sent, len(TOOL_LOG), [c["agent"] for c in rec.calls])
        tr.para(f"**max_llm_calls={max_calls}**: events")
        tr.code("\n".join(rr.summaries()) or "(none)")
        await runner.close()

    rr, attempted, sent, tool_runs, who = results[8]
    tr.check("AgentTool round trip completes with a generous budget (max_llm_calls=8)", rr.error is None and bool(rr.final_text()), repr(rr.error) if rr.error else f"{rr.elapsed:.2f}s")
    tr.check("the master and the nested agent made 4 model calls in total (master, tool_agent, tool_agent, master)", who == ["master", "tool_agent", "tool_agent", "master"], str(who))
    tr.check("the nested tool function executed exactly once", tool_runs == 1)
    if ctx.cap:
        tr.check("the endpoint received those 4 requests", sent == 4, f"{sent} received")

    rr2, attempted2, sent2, tool_runs2, who2 = results[2]
    outcome = f"raised {type(rr2.error).__module__}.{type(rr2.error).__qualname__}: {rr2.error}" if rr2.error else "completed without an exception"
    tr.para(
        f"Observed with max_llm_calls=2: the run {outcome}; ADK attempted {attempted2} model calls "
        f"(authors {who2})" + (f" and the endpoint received {sent2}." if sent2 is not None else ".")
    )
    if rr2.error is None and attempted2 > 2:
        tr.para(
            f"Reading: {attempted2} model calls ran under max_llm_calls=2 and nothing tripped, so the calls made inside the "
            "AgentTool are not added to the caller's count. `max_llm_calls` therefore does not bound the total number of "
            "model calls of a master that delegates through AgentTool; a total-call ceiling for C.1 needs a counter of its "
            "own (for example in a before_model_callback shared through state) in addition to RunConfig."
        )
    elif rr2.error is not None:
        tr.para("Reading: the nested calls were counted against the caller's budget (the run tripped at max_llm_calls=2).")


async def step5_record(ctx: Ctx, db: Optional[DbProbe]) -> None:
    tr, rec = ctx.tr, ctx.rec
    cfg = ctx.cfg
    tr.h2("Step 5: versions, vLLM flags, latency and tokens of the three-call pipeline")

    tr.para("Versions in the interpreter that ran this spike:")
    packages = ["google-adk", "litellm", "google-genai", "openai", "sqlalchemy", "asyncpg", "aiosqlite", "pydantic",
                "pydantic-settings", "fastapi", "starlette", "uvicorn", "httpx", "opentelemetry-api"]
    tr.table([[p, package_version(p)] for p in packages] + [["python", platform.python_version()]], ["package", "version"])

    server_version, served_models = "not available", "not available"
    try:
        with httpx.Client(timeout=5.0) as client:
            server_version = json.dumps(client.get(f"{cfg.root_url}/version").json())
    except Exception as exc:
        server_version = f"not available ({type(exc).__name__})"
    try:
        with httpx.Client(timeout=5.0) as client:
            data = client.get(f"{cfg.base_url.rstrip('/')}/models").json()
        served_models = ", ".join(f"{m.get('id')} (max_model_len={m.get('max_model_len', 'n/a')})" for m in data.get("data", []))
    except Exception as exc:
        served_models = f"not available ({type(exc).__name__})"
    tr.table(
        [
            ["endpoint", "scripted fake (not vLLM)" if cfg.fake or ctx.cap else "live OpenAI-compatible server"],
            ["model name used", cfg.model],
            ["GET /version", server_version],
            ["GET /v1/models", served_models],
            ["vLLM flags the operator must use for Qwen tool calling", f"`{VLLM_FLAGS}`"],
            ["flags verified from the client", "no: the client cannot read server flags; the operator confirms them in the vLLM launch command" if not (cfg.fake or ctx.cap) else "not applicable (scripted fake)"],
        ],
        ["item", "value"],
    )
    try:
        caps = make_model(cfg).capabilities  # type: ignore[attr-defined]
        tr.para(
            f"LiteLlm capabilities for `openai/{cfg.model}`: `{caps}`. This is computed client-side from the model string "
            "and provider prefix; it is not a statement about the server or the Qwen chat template, so the plan's separate "
            "writer agent (output_schema without tools) stays the safe choice."
        )
    except Exception as exc:
        tr.para(f"LiteLlm capabilities attribute not readable: {type(exc).__name__}")

    if not db or not cfg.db_url:
        tr.check("latency runs need the database (SPIKE_DATABASE_URL)", False, "skipped")
        return

    tr.para(
        f"Latency: {cfg.runs} measured runs of the full three-call pipeline (`SequentialAgent`, "
        "`DatabaseSessionService`, `RunConfig(max_llm_calls=4)`), each in a fresh session, after the first run in step 3. "
        "Percentiles use the nearest-rank method."
    )
    svc = DatabaseSessionService(db_url=cfg.db_url)
    runner = Runner(app_name=APP_NAME, agent=build_pipeline(cfg, rec), session_service=svc)
    latencies: List[float] = []
    rows: List[List[str]] = []
    adk_usage_total = {"prompt": 0, "completion": 0, "total": 0}
    server_usage_total = {"prompt": 0, "completion": 0, "total": 0}
    all_ok = True
    for i in range(cfg.runs):
        TOOL_LOG.clear()
        rec.reset()
        n0 = ctx.server_count()
        sid = new_session_id("s5")
        await svc.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid, state={"investigation_notes": FIXED_NOTE})
        rr = await drive(runner, sid, RunConfig(max_llm_calls=4), cfg.run_timeout)
        usage = rr.usage()
        ok = rr.error is None and len(rec.calls) == 3 and len(TOOL_LOG) == 1
        try:
            if ok:
                parse_assessment((await svc.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=sid)).state.get("assessment_json"))
        except Exception:
            ok = False
        all_ok &= ok
        latencies.append(rr.elapsed)
        for k in adk_usage_total:
            adk_usage_total[k] += usage[k]
        server_note = ""
        if ctx.cap:
            for r in ctx.server_requests_since(n0):
                u = r.get("usage") or {}
                server_usage_total["prompt"] += u.get("prompt_tokens", 0)
                server_usage_total["completion"] += u.get("completion_tokens", 0)
                server_usage_total["total"] += u.get("total_tokens", 0)
            server_note = f"{sum((r.get('usage') or {}).get('total_tokens', 0) for r in ctx.server_requests_since(n0))}"
        rows.append([str(i + 1), f"{rr.elapsed * 1000:.0f}", str(len(rec.calls)), str(usage["prompt"]), str(usage["completion"]), str(usage["total"]), server_note or "n/a", "ok" if ok else "FAILED"])
    await runner.close()

    tr.table(rows, ["run", "latency ms", "model calls", "prompt tokens (ADK)", "completion tokens (ADK)", "total tokens (ADK)", "total tokens (endpoint usage)", "result"])
    tr.check(f"all {cfg.runs} measured runs completed with 3 model calls, 1 tool execution and a valid QwenAssessment", all_ok)
    p50 = statistics.median(latencies)
    p95 = nearest_rank(latencies, 0.95)
    tr.table(
        [[f"{p50 * 1000:.0f}", f"{p95 * 1000:.0f}", f"{min(latencies) * 1000:.0f}", f"{max(latencies) * 1000:.0f}", str(len(latencies))]],
        ["p50 ms", "p95 ms", "min ms", "max ms", "runs"],
    )
    per_run = {k: v / max(1, cfg.runs) for k, v in adk_usage_total.items()}
    tr.para(
        f"Token counts per pipeline run as ADK reports them from the endpoint's `usage`: prompt {per_run['prompt']:.0f}, "
        f"completion {per_run['completion']:.0f}, total {per_run['total']:.0f} (mean over {cfg.runs} runs)."
    )
    tr.check("the run count meets the plan's minimum of 5", cfg.runs >= MIN_RUNS, f"runs={cfg.runs}")
    tr.check("ADK reported non-zero token usage taken from the endpoint", adk_usage_total["total"] > 0)
    if ctx.cap:
        tr.check(
            "ADK's token totals equal the totals the endpoint returned in `usage`",
            adk_usage_total == server_usage_total,
            f"adk={adk_usage_total} endpoint={server_usage_total}",
        )
        tr.para("These latencies measure ADK, LiteLlm and database overhead against a scripted fake with no inference time. They say nothing about model latency.")
    else:
        tr.para("These latencies include real inference time on the endpoint named above.")


# --------------------------------------------------------------------------------------
# Fake server lifecycle, report assembly, entry point
# --------------------------------------------------------------------------------------


def port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0


def start_fake_server(cfg: SpikeConfig) -> subprocess.Popen:
    parsed = urlparse(cfg.base_url)
    host, port = parsed.hostname or "127.0.0.1", parsed.port or 80
    if host not in LOOPBACK_HOSTS:
        raise SystemExit(f"--fake refuses to run against a non-loopback LLM_BASE_URL host ({host!r})")
    if not port_is_free(host, port):
        raise SystemExit(f"--fake: port {port} on {host} is already in use; refusing to talk to an unknown server")
    proc = subprocess.Popen(
        [sys.executable, str(Path(__file__).with_name("adk_spike_fake_vllm.py")), "--host", host, "--port", str(port), "--model", cfg.model],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"fake vLLM exited early: {proc.stderr.read().decode(errors='replace')[:800]}")
        try:
            with httpx.Client(timeout=1.0) as client:
                if client.get(f"{cfg.root_url}/health").status_code == 200:
                    return proc
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    raise SystemExit("fake vLLM did not become ready within 30 seconds")


def git_provenance() -> str:
    def run(*args: str) -> str:
        return subprocess.run(["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True, timeout=10).stdout.strip()

    try:
        sha, branch = run("rev-parse", "HEAD"), run("rev-parse", "--abbrev-ref", "HEAD")
        dirty = run("status", "--porcelain", "--untracked-files=no")
        return f"`{sha}` on `{branch}` ({'clean tree' if not dirty else 'uncommitted tracked changes present'})"
    except Exception:
        return "unavailable"


def build_cfg(args: argparse.Namespace) -> SpikeConfig:
    base_url = os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL)
    model = os.environ.get("LLM_MODEL") or (DEFAULT_FAKE_MODEL if args.fake else "")
    if not model:
        raise SystemExit("LLM_MODEL must be set to the served model name (it defaults only with --fake)")
    db_url = os.environ.get("SPIKE_DATABASE_URL")
    if not db_url:
        raise SystemExit("SPIKE_DATABASE_URL must be set (for example postgresql+asyncpg://postgres@127.0.0.1:55432/c0_spike)")
    if not db_url.startswith(("postgresql+asyncpg://", "sqlite+aiosqlite://")):
        raise SystemExit("SPIKE_DATABASE_URL must use an async driver (postgresql+asyncpg:// or sqlite+aiosqlite://)")
    if args.runs < MIN_RUNS:
        raise SystemExit(f"--runs must be at least {MIN_RUNS}")
    name = make_url(db_url).database or ""
    if "spike" not in name and not args.allow_any_database:
        raise SystemExit(f"refusing database {name!r}: its name must contain 'spike' (override with --allow-any-database)")
    return SpikeConfig(
        base_url=base_url,
        model=model,
        api_key=os.environ.get("LLM_API_KEY") or "EMPTY",
        db_url=db_url,
        fake=args.fake,
        runs=args.runs,
        llm_timeout=float(os.environ.get("LLM_TIMEOUT_SECONDS", "120")),
        allow_any_database=args.allow_any_database,
    )


async def run_all(ctx: Ctx) -> None:
    db = DbProbe(ctx.cfg.db_url)
    try:
        for label, coro_factory in (
            ("step 1", lambda: step1_tool_roundtrip(ctx)),
            ("step 2", lambda: step2_output_schema(ctx)),
        ):
            await guarded(ctx, label, coro_factory)
        await guarded(ctx, "step 3", lambda: step3_pipeline_database(ctx, db))
        await guarded(ctx, "step 4", lambda: step4_budget(ctx, db))
        await guarded(ctx, "extra probe (AgentTool)", lambda: probe_agent_tool_budget(ctx, db))
        await guarded(ctx, "step 5", lambda: step5_record(ctx, db))
    finally:
        await db.close()


async def guarded(ctx: Ctx, label: str, factory: Callable[[], Awaitable[Any]]) -> None:
    before_fail, before_pass = len(ctx.tr.failures), ctx.tr.passed
    try:
        await factory()
    except Exception as exc:
        ctx.tr.check(f"{label} raised no unexpected exception", False, f"{type(exc).__name__}: {str(exc)[:300]}")
        ctx.tr.code(traceback.format_exc())
    ctx.tr.step_results.append((label, ctx.tr.passed - before_pass, len(ctx.tr.failures) - before_fail))


def assemble_report(cfg: SpikeConfig, tr: Transcript, notes: Optional[str], started: dt.datetime) -> str:
    mode = "scripted fake (scripts/adk_spike_fake_vllm.py), not a real model" if cfg.fake else "live OpenAI-compatible endpoint"
    head = [
        "# Phase C.0 ADK compatibility spike report",
        "",
        "Generated by `scripts/adk_spike.py`; everything under \"Spike transcript\" is program output.",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Generated (UTC) | {started.strftime('%Y-%m-%dT%H:%M:%SZ')} |",
        f"| Repository state | {git_provenance()} |",
        f"| Endpoint | {mode} |",
        f"| LLM_BASE_URL | `{cfg.base_url}` |",
        f"| LLM_MODEL | `{cfg.model}` |",
        f"| SPIKE_DATABASE_URL | `{mask_url(cfg.db_url)}` |",
        f"| google-adk / litellm | {package_version('google-adk')} / {package_version('litellm')} |",
        f"| Python | {platform.python_version()} on {platform.system()} {platform.machine()} |",
        f"| Result | {'PASS' if not tr.failures else 'FAIL'}: {tr.passed} assertions passed, {len(tr.failures)} failed |",
        "",
    ]
    if notes:
        head += ["## Notes (hand-written)", "", notes.strip(), ""]
    summary = ["## Result by step", "", "| Step | Passed | Failed |", "|---|---|---|"]
    summary += [f"| {label} | {p} | {f} |" for label, p, f in tr.step_results]
    summary += [""]
    if tr.failures:
        summary += ["Failed assertions:", ""] + [f"- {f}" for f in tr.failures] + [""]
    body = ["## Spike transcript", ""] + tr.lines
    return tr.redact("\n".join(head + summary + body)) + "\n"


def report_warnings(tr: Transcript, caught: List[Any]) -> None:
    """Warnings ADK and LiteLlm emitted during the run, de-duplicated, because they are findings."""
    tr.h2("Warnings emitted during the run")
    seen: Dict[str, int] = {}
    for w in caught:
        key = f"{w.category.__name__}: {str(w.message).splitlines()[0][:400]}"
        seen[key] = seen.get(key, 0) + 1
    if not seen:
        tr.para("None.")
        return
    tr.para("Python warnings captured while the steps ran (message, count):")
    tr.code("\n".join(f"{n}x {msg}" for msg, n in sorted(seen.items())))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--fake", action="store_true", help="start the scripted fake vLLM on the LLM_BASE_URL port")
    parser.add_argument("--report", metavar="PATH", help="write the Markdown transcript to PATH")
    parser.add_argument("--notes", metavar="PATH", help="hand-written Markdown to include verbatim in the report")
    parser.add_argument("--runs", type=int, default=8, help="measured pipeline runs for latency (min 5)")
    parser.add_argument("--allow-any-database", action="store_true", help="skip the 'spike' database-name guard")
    args = parser.parse_args(argv)

    cfg = build_cfg(args)
    started = dt.datetime.now(dt.timezone.utc)
    tr = Transcript(Redactor(cfg))
    tr.h1("Phase C.0 ADK compatibility spike: transcript")
    tr.para(
        f"Mode: {'scripted fake' if cfg.fake else 'live endpoint'}; model `{cfg.model}`; endpoint `{cfg.base_url}`; "
        f"database `{mask_url(cfg.db_url)}`; started {started.strftime('%Y-%m-%dT%H:%M:%SZ')}."
    )

    fake_proc = start_fake_server(cfg) if cfg.fake else None
    try:
        ctx = Ctx(cfg=cfg, tr=tr, rec=CallRecorder(), cap=FakeCapture.detect(cfg.root_url))
        if ctx.cap:
            tr.para("The endpoint exposes `/capture`: it is the scripted fake, so wire-level assertions are enabled.")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            asyncio.run(run_all(ctx))
        report_warnings(tr, caught)
    finally:
        if fake_proc is not None:
            fake_proc.terminate()
            try:
                fake_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                fake_proc.kill()

    tr.h2("Overall")
    tr.para(f"{tr.passed} assertions passed, {len(tr.failures)} failed.")
    for failure in tr.failures:
        tr.bullet(f"FAILED: {failure}")

    if args.report:
        notes = Path(args.notes).read_text(encoding="utf-8") if args.notes else None
        out = Path(args.report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(assemble_report(cfg, tr, notes, started), encoding="utf-8")
        print(f"\nReport written to {out}", flush=True)
    return 1 if tr.failures else 0


if __name__ == "__main__":
    sys.exit(main())
