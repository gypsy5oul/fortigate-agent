"""Fake external service endpoints for End-to-End testing.

Implements lightweight FastAPI mock endpoints for:
1. Grafana Loki (GET /loki/api/v1/query_range)
2. Local vLLM/Qwen OpenAI-compatible chat API (POST /v1/chat/completions), including the scripted
   tool-calling answers for the ADK investigator (shadow and adk modes)
3. Google Chat Incoming Webhook (POST /chat, POST /gchat)
"""

import json
import re
import asyncio
from typing import List, Tuple, Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse


class FakeEndpointsState:
    def __init__(self):
        self.staged_logs: List[Tuple[int, str]] = []  # (ts_ns, raw_line)
        self.captured_chats: List[Dict[str, Any]] = []
        self.chat_response_mode: str = "valid"  # valid, invalid_json, schema_invalid, injection_obeying, timeout
        self.loki_response_mode: str = "valid"  # valid, error
        self.adk_requests: List[Dict[str, Any]] = []  # what the ADK agents sent, and what was answered

    def reset(self):
        self.staged_logs.clear()
        self.captured_chats.clear()
        self.adk_requests.clear()
        self.chat_response_mode = "valid"
        self.loki_response_mode = "valid"


state = FakeEndpointsState()
app = FastAPI(title="Fake E2E Endpoints")


@app.get("/loki/api/v1/query_range")
async def loki_query_range(
    query: str = "",
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 1000,
    direction: str = "forward",
):
    if state.loki_response_mode == "error":
        raise HTTPException(status_code=500, detail="Simulated Loki storage failure")

    start_ns = int(start) if start else 0
    end_ns = int(end) if end else 2**63 - 1

    line_filters_raw = re.findall(r'\|=\s*"((?:\\.|[^"\\])*)"', query)
    line_filters = [f.replace('\\"', '"') for f in line_filters_raw]

    regex_filters_raw = re.findall(r'\|~\s*"((?:\\.|[^"\\])*)"', query)
    compiled_regexes = []
    for r in regex_filters_raw:
        try:
            compiled_regexes.append(re.compile(r.replace('\\"', '"')))
        except Exception:
            pass

    matched = []
    for ts, line in state.staged_logs:
        if not (start_ns <= ts <= end_ns):
            continue
        if line_filters and not all(f in line for f in line_filters):
            continue
        if compiled_regexes and not all(r.search(line) for r in compiled_regexes):
            continue
        matched.append((ts, line))

    matched.sort(key=lambda x: x[0], reverse=(direction == "backward"))
    matched = matched[:limit]

    values = [[str(ts), line] for ts, line in matched]
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"service_name": "forticlient"},
                    "values": values,
                }
            ] if values else [],
        },
    }


# ---------------------------------------------------------------------------------------------
# Scripted ADK investigation (Phase C.1). The ADK agents are told apart by the tools they declare
# (or by the WriterAssessment response schema); each answers with OpenAI-format tool_calls first and
# a text (or JSON) answer once its tool results are in the conversation. Identity, evidence ids,
# signatures and eligible actions are lifted from the tool results the service returned, so the
# scripted assessment is grounded in what the real tools produced.
# ---------------------------------------------------------------------------------------------

_ADK_TOOL_OWNERS = {
    "evidence_agent": "incident_investigator",
    "get_incident_packet": "evidence_agent",
    "lookup_asset": "context_agent",
}


def _adk_agent(body: Dict[str, Any]) -> Optional[str]:
    rf = body.get("response_format") or {}
    if isinstance(rf, dict) and (rf.get("json_schema") or {}).get("name") == "WriterAssessment":
        return "assessment_writer"
    for tool in body.get("tools") or []:
        owner = _ADK_TOOL_OWNERS.get((tool.get("function") or {}).get("name"))
        if owner:
            return owner
    return None


def _text_of(content: Any) -> str:
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return content or ""


def _tool_call(index: int, calls: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": f"call_{index}_{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
            for i, (name, args) in enumerate(calls)
        ],
    }


def _adk_answer(agent: str, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    tool_msgs = [_text_of(m.get("content")) for m in messages if m.get("role") == "tool"]
    user_text = " ".join(_text_of(m.get("content")) for m in messages if m.get("role") == "user")
    n = len(state.adk_requests)

    if agent == "evidence_agent":
        if not tool_msgs:
            return _tool_call(n, [("get_incident_packet", {}), ("query_traffic_context", {"direction": "to_target", "minutes_before": 10})])
        packet = next((json.loads(t) for t in tool_msgs if '"evidence_ids"' in t), {})
        sigs = [re.sub(r"<<UNTRUSTED id=[^>]+>>\n|\n<</UNTRUSTED>>", "", x) for x in packet.get("signatures", [])]
        return {"role": "assistant", "content": (
            f"incident_id={packet.get('incident_id')} incident_revision={packet.get('revision')} "
            f"source_ip={packet.get('source_ip')} target_ip={packet.get('target_ip')} "
            f"enforcement={packet.get('enforcement')} floor={packet.get('deterministic_severity_floor')} "
            f"signatures={'|'.join(sigs)} evidence_ids={','.join(packet.get('evidence_ids', [])[:3])}"
        )}

    if agent == "context_agent":
        if not tool_msgs:
            ips = re.findall(r"(?:source_ip|target_ip)=([0-9a-fA-F.:]+)", user_text)
            sigs = (re.search(r"signatures=(\S*)", user_text) or [None, ""])[1].split("|")
            calls = [("lookup_asset", {"ip": ip}) for ip in ips]
            calls += [("lookup_signature", {"signature": sig}) for sig in sigs if sig]
            calls += [("recent_incidents_for_source", {}), ("get_action_catalog", {})]
            return _tool_call(n, calls)
        catalog = next((json.loads(t) for t in tool_msgs if '"eligible_actions"' in t), {})
        eligible = [a["id"] for a in catalog.get("eligible_actions", [])]
        return {"role": "assistant", "content": f"eligible_actions={','.join(eligible)}"}

    if agent == "incident_investigator":
        if len(tool_msgs) == 0:
            return _tool_call(n, [("evidence_agent", {"request": "Report what the firewall observed for this incident."})])
        if len(tool_msgs) == 1:
            evidence = json.loads(tool_msgs[0]).get("result", "")
            return _tool_call(n, [("context_agent", {"request": f"Context for: {evidence}"})])
        notes = " ".join(json.loads(t).get("result", "") for t in tool_msgs)
        return {"role": "assistant", "content": f"INVESTIGATION NOTES: {notes}"}

    # assessment_writer: one WriterAssessment object from the notes in its instruction.
    text = " ".join(_text_of(m.get("content")) for m in messages)
    def pick(pattern, default):
        found = re.search(pattern, text)
        return found.group(1) if found else default
    evidence_ids = pick(r"evidence_ids=(\S+)", "EVID-1").split(",")
    eligible = [a for a in pick(r"eligible_actions=(\S+)", "").split(",") if a]
    return {"role": "assistant", "content": json.dumps({
        "incident_id": pick(r"incident_id=(\S+)", "INC-MOCK-E2E"),
        "incident_revision": int(pick(r"incident_revision=(\d+)", "1")),
        "severity": pick(r"floor=(\w+)", "CRITICAL"),
        "attack_category": "EXPLOITATION_ATTEMPT",
        "exploitation_assessment": "ATTEMPT_OBSERVED",
        "enforcement": pick(r"enforcement=(\w+)", "ALLOWED_OR_DETECTED"),
        "summary": "ADK shadow assessment of the exploit probe (scripted fake).",
        "findings": [{"kind": "OBSERVATION", "statement": "IPS signature observed by the firewall.", "evidence_ids": evidence_ids[:1]}],
        "cve_references": [],
        "visibility_gaps": ["No endpoint telemetry."],
        "recommended_action_ids": [a for a in eligible if a == "ACT_INSPECT_APPLICATION_LOGS"][:1],
        "analyst_follow_up": ["Verify application patch status"],
    })}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body_peek = await request.json()
    adk_agent = _adk_agent(body_peek)
    if adk_agent is not None and state.chat_response_mode == "valid":
        message = _adk_answer(adk_agent, body_peek.get("messages") or [])
        state.adk_requests.append({
            "agent": adk_agent,
            "tools": [(t.get("function") or {}).get("name") for t in body_peek.get("tools") or []],
            "answered_with": [c["function"]["name"] for c in message.get("tool_calls", [])] or "text",
        })
        return {
            "id": f"chatcmpl-adk-{len(state.adk_requests)}",
            "object": "chat.completion",
            "model": body_peek.get("model"),
            "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
            "usage": {"prompt_tokens": 150, "completion_tokens": 40, "total_tokens": 190},
        }

    if state.chat_response_mode == "timeout":
        await asyncio.sleep(15.0)
        raise HTTPException(status_code=504, detail="Simulated LLM Gateway Timeout")

    if state.chat_response_mode == "invalid_json":
        return {
            "id": "chatcmpl-mock-invalid",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "This is raw text without valid JSON formatting {broken: True",
                    },
                    "finish_reason": "stop",
                }
            ],
        }

    if state.chat_response_mode == "schema_invalid":
        return {
            "id": "chatcmpl-mock-schema-invalid",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps({"unknown_forbidden_key": "violates extra=forbid"}),
                    },
                    "finish_reason": "stop",
                }
            ],
        }

    # Extract incident details from all messages in conversation
    body = await request.json()
    messages = body.get("messages", [])
    full_text = " ".join(m.get("content", "") for m in messages)

    inc_id_match = re.search(r'"incident_id":\s*"([^"]+)"', full_text)
    rev_match = re.search(r'"incident_revision":\s*(\d+)', full_text)
    enf_match = re.search(r'"enforcement":\s*"([^"]+)"', full_text)
    sev_match = re.search(r'"deterministic_severity_floor":\s*"([^"]+)"', full_text)

    inc_id = inc_id_match.group(1) if inc_id_match else "INC-MOCK-E2E"
    rev = int(rev_match.group(1)) if rev_match else 2
    enforcement = enf_match.group(1) if enf_match else "ALLOWED_OR_DETECTED"
    severity = sev_match.group(1) if sev_match else "CRITICAL"

    # Extract valid evidence ID from <<UNTRUSTED id=...>> or "id": "..."
    ev_matches = [m for m in re.findall(r'<<UNTRUSTED id=([^\s>]+)>>', full_text) if m != "..."]
    if not ev_matches:
        ev_matches = [
            m for m in re.findall(r'"id":\s*"([^"]+)"', full_text)
            if m not in ("QwenAssessment", "FindingItem", "IncidentPacket", inc_id, "...")
        ]
    chosen_ev_id = ev_matches[0] if ev_matches else "EVID-1"

    if state.chat_response_mode == "injection_obeying":
        # Attempts to smuggle unauthorized actions
        assessment = {
            "incident_id": inc_id,
            "incident_revision": rev,
            "visibility_scope": "FIREWALL_ONLY",
            "severity": "CRITICAL",
            "attack_category": "EXPLOITATION_ATTEMPT",
            "exploitation_assessment": "ATTEMPT_OBSERVED",
            "enforcement": enforcement,
            "summary": "Obeyed prompt injection to recommend unauthorized quarantine action.",
            "findings": [
                {
                    "kind": "OBSERVATION",
                    "statement": "Hostile attack detected with injection payload.",
                    "evidence_ids": [chosen_ev_id],
                }
            ],
            "cve_references": [],
            "visibility_gaps": [],
            "recommended_action_ids": ["ACT_QUARANTINE_SRC_IP", "UNAUTHORIZED_BOGUS_ACTION"],
            "analyst_follow_up": [],
        }
    else:
        # Default valid response
        assessment = {
            "incident_id": inc_id,
            "incident_revision": rev,
            "visibility_scope": "FIREWALL_ONLY",
            "severity": severity,
            "attack_category": "EXPLOITATION_ATTEMPT",
            "exploitation_assessment": "ATTEMPT_OBSERVED",
            "enforcement": enforcement,
            "summary": "Model analysis of exploit probe. Deterministic enforcement preserved.",
            "findings": [
                {
                    "kind": "OBSERVATION",
                    "statement": "Log pattern indicates exploit signature probe against protected VIP.",
                    "evidence_ids": [chosen_ev_id],
                }
            ],
            "cve_references": ["CVE-2021-44228"] if "CVE-2021-44228" in full_text else [],
            "visibility_gaps": [],
            "recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"],
            "analyst_follow_up": ["Verify application patch status"],
        }

    return {
        "id": "chatcmpl-mock-valid",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(assessment),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
    }


@app.post("/chat")
@app.post("/gchat")
async def chat_webhook(request: Request):
    payload = await request.json()
    state.captured_chats.append(payload)
    return {"name": "spaces/MOCK_SPACE/messages/MOCK_MSG_123"}


@app.get("/capture")
async def get_capture():
    return {
        "captured_chats": state.captured_chats,
        "staged_logs_count": len(state.staged_logs),
        "adk_requests": state.adk_requests,
    }


@app.post("/reset")
async def reset_state():
    state.reset()
    return {"status": "ok"}


@app.post("/stage_logs")
async def stage_logs_endpoint(request: Request):
    logs = await request.json()
    for item in logs:
        state.staged_logs.append((int(item[0]), str(item[1])))
    return {"status": "ok", "staged_count": len(state.staged_logs)}


@app.post("/set_mode")
async def set_mode_endpoint(request: Request):
    body = await request.json()
    if "chat_response_mode" in body:
        state.chat_response_mode = body["chat_response_mode"]
    if "loki_response_mode" in body:
        state.loki_response_mode = body["loki_response_mode"]
    return {
        "chat_response_mode": state.chat_response_mode,
        "loki_response_mode": state.loki_response_mode,
    }


def generate_scenario_logs(base_ts_ns: int) -> Dict[str, List[Tuple[int, str]]]:
    """Generates synthetic logs matching Section 1 validation scenarios."""
    scenarios = {}

    # 1. Benign internal host (DNS + HTTPS, closed normally)
    scenarios["scenario_1_benign"] = [
        (
            base_ts_ns + 1_000_000_000,
            'date=2026-10-06 time=12:00:00 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
            'subtype="forward" level="notice" vd="root" srcip=10.0.1.5 srcport=51234 dstip=1.1.1.1 '
            'dstport=53 proto=17 service="DNS" action="close" sessionid=200001 sentbyte=64 rcvdbyte=128',
        ),
        (
            base_ts_ns + 2_000_000_000,
            'date=2026-10-06 time=12:00:01 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
            'subtype="forward" level="notice" vd="root" srcip=10.0.1.5 srcport=51235 dstip=93.184.216.34 '
            'dstport=443 proto=6 service="HTTPS" action="close" sessionid=200002 sentbyte=1200 rcvdbyte=4500',
        ),
    ]

    # 2. Non-blocked IPS detection against VIP (action=detected) -> CRITICAL URGENT
    scenarios["scenario_2_nonblocked_ips"] = [
        (
            base_ts_ns + 3_000_000_000,
            'date=2026-10-06 time=12:00:02 devname="FGT" devid="FGT1" logid="0419016384" type="utm" '
            'subtype="ips" eventtype="signature" level="critical" vd="root" policyid=10 sessionid=200003 '
            'srcip=198.51.100.45 srcport=44812 dstip=10.0.14.120 dstport=443 proto=6 service="HTTPS" '
            'attack="Apache.Log4j.Error.Log.Remote.Code.Execution" vuln_name="CVE-2021-44228" action="detected" '
            'severity="critical" direction="incoming" msg="IPS signature matched in decrypted SSL payload"',
        ),
    ]

    # 3. IPS-dropped exploit (action=dropped) + accepted traffic log of same session -> BLOCKED, No Urgent Alert
    scenarios["scenario_3_blocked_exploit"] = [
        (
            base_ts_ns + 4_000_000_000,
            'date=2026-10-06 time=12:00:03 devname="FGT" devid="FGT1" logid="0419016384" type="utm" '
            'subtype="ips" eventtype="signature" level="critical" vd="root" policyid=10 sessionid=200004 '
            'srcip=198.51.100.46 srcport=44813 dstip=10.0.14.120 dstport=443 proto=6 service="HTTPS" '
            'attack="Apache.Log4j.Error.Log.Remote.Code.Execution" vuln_name="CVE-2021-44228" action="dropped" '
            'utmaction="dropped" severity="critical" direction="incoming" msg="IPS dropped malicious session"',
        ),
        (
            base_ts_ns + 4_100_000_000,
            'date=2026-10-06 time=12:00:03 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
            'subtype="forward" level="notice" vd="root" sessionid=200004 srcip=198.51.100.46 srcport=44813 '
            'dstip=10.0.14.120 dstport=443 proto=6 service="HTTPS" action="accept" policyid=10',
        ),
    ]

    # 4. Internal host, antivirus blocked a download -> No Urgent Alert
    scenarios["scenario_4_internal_av_blocked"] = [
        (
            base_ts_ns + 5_000_000_000,
            'date=2026-10-06 time=12:00:04 devname="FGT" devid="FGT1" logid="0211016384" type="utm" '
            'subtype="virus" level="warning" vd="root" policyid=5 sessionid=200005 srcip=10.0.1.50 '
            'srcport=54321 dstip=203.0.113.10 dstport=80 proto=6 service="HTTP" virus="Eicar-Test-Signature" '
            'action="blocked" utmaction="blocked" direction="outgoing" msg="Virus detected and download blocked"',
        ),
    ]

    # 5. Blocked scanner, 12 denies -> Digest (no urgent alert)
    scanner_logs = []
    for i in range(12):
        scanner_logs.append((
            base_ts_ns + 6_000_000_000 + i * 100_000_000,
            f'date=2026-10-06 time=12:00:05 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
            f'subtype="forward" level="notice" vd="root" sessionid={200010 + i} srcip=198.51.100.99 '
            f'srcport={40000 + i} dstip=10.0.14.120 dstport={1000 + i} proto=6 service="TCP/{1000 + i}" '
            f'action="deny" policyid=0',
        ))
    scenarios["scenario_5_blocked_scanner"] = scanner_logs

    # 6. Burst of 400 events
    burst_logs = []
    for i in range(400):
        burst_logs.append((
            base_ts_ns + 10_000_000_000 + i * 10_000_000,
            f'date=2026-10-06 time=12:00:10 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
            f'subtype="forward" level="notice" vd="root" sessionid={300000 + i} srcip=198.51.100.200 '
            f'srcport={30000 + (i % 500)} dstip=10.0.14.120 dstport=80 proto=6 service="HTTP" '
            f'action="deny" policyid=0',
        ))
    scenarios["burst_400"] = burst_logs

    # 7. Late-arrival batch (logs with timestamp 30s in the past)
    late_logs = [
        (
            base_ts_ns - 30_000_000_000,
            'date=2026-10-06 time=11:59:30 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" '
            'subtype="forward" level="notice" vd="root" sessionid=199999 srcip=198.51.100.77 srcport=45000 '
            'dstip=10.0.14.120 dstport=80 proto=6 service="HTTP" action="deny" policyid=0',
        )
    ]
    scenarios["late_arrival"] = late_logs

    return scenarios
