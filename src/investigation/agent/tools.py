"""Read-only tools of the ADK investigator (plan C1.2).

Plain functions; ADK wraps them as FunctionTools and hides the ``tool_context`` parameter from the
model. Identity (incident, revision, IPs, time window) comes from ``tool_context.state`` only, never
from arguments. Every bound is enforced here in code; a refused call returns
``{"status": "refused", "reason": ...}`` and no tool ever raises. The only database access is
``_select``, which refuses anything but a SELECT: agents never write.
"""

import functools
import inspect
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from google.adk.tools import ToolContext

from src.context.assets import get_asset_manager
from src.context.signatures import get_signature_manager
from src.investigation.schemas import IncidentPacket
from src.parsing.normalizer import normalize_event
from src.parsing.redaction import redact_evidence_record
from src.sources.query_profiles import TRAFFIC_CONTEXT_PROFILE
from src.storage.timeutil import to_utc_datetime

logger = logging.getLogger(__name__)

IDENTITY_KEYS = ("incident_id", "revision", "source_ip", "target_ip", "window_start_ns", "window_end_ns")
PACKET_KEY = "packet"
DIRECTIONS = ("to_target", "from_source")
MINUTES_MIN, MINUTES_MAX = 1, 30
TRAFFIC_MAX_LINES = 200
TRAFFIC_MAX_SAMPLES = 20
RECENT_WINDOW = timedelta(hours=24)
RECENT_MAX_ROWS = 10
# Fields of a normalized event an agent may see; raw_message never leaves the service.
EVIDENCE_FIELDS = (
    "id", "loki_ts_ns", "log_type", "subtype", "action_normalized", "action_raw", "utmaction", "direction",
    "srcport", "dstport", "proto", "service", "policyid", "sessionid", "signature", "url", "http_method",
    "severity_raw",
)


@dataclass
class ToolDeps:
    """Services the tools read from. Set once by the runtime; tests set fakes."""

    loki: Any = None        # src.sources.loki_client.LokiClient (query_range only)
    selector: str = '{service_name="forticlient"}'
    db: Any = None          # src.storage.database.Database (reached only through _select)


_deps = ToolDeps()


def configure_tools(deps: ToolDeps) -> None:
    global _deps
    _deps = deps


def refused(reason: str) -> Dict[str, Any]:
    return {"status": "refused", "reason": reason}


def _contract(func):
    """Turn any exception into an error result: a tool never raises into the agent."""

    def _error(exc: Exception) -> Dict[str, Any]:
        logger.warning("agent tool %s failed: %s", func.__name__, exc)
        reason = "incident identity missing from session state" if isinstance(exc, KeyError) else type(exc).__name__
        return {"status": "error", "reason": reason}

    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as exc:  # contract: never raise
                return _error(exc)
    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:  # contract: never raise
                return _error(exc)
    return wrapper


async def _select(db, sql: str, *args) -> List[Dict[str, Any]]:
    """The tools' only door to the database: SELECT statements, nothing else."""
    if not sql.lstrip().upper().startswith("SELECT"):
        raise PermissionError("agent tools are read-only")
    return await db.fetch_all(sql, *args)


def evidence_view(event: Dict[str, Any]) -> Dict[str, Any]:
    """Redacted, field-limited view of one normalized event."""
    clean = redact_evidence_record(event)
    return {k: clean[k] for k in EVIDENCE_FIELDS if clean.get(k) is not None}


def session_state_for(packet: IncidentPacket) -> Dict[str, Any]:
    """Initial ADK session state: the identity the tools bind to, and the redacted packet."""
    data = packet.model_dump(mode="json")
    data["evidence_events"] = [evidence_view(ev) for ev in packet.evidence_events if isinstance(ev, dict)]
    return {
        "incident_id": packet.incident_id,
        "revision": packet.incident_revision,
        "source_ip": packet.source_ip,
        "target_ip": packet.target_ip,
        "window_start_ns": int(to_utc_datetime(packet.first_seen).timestamp() * 1e9),
        "window_end_ns": int(to_utc_datetime(packet.last_seen).timestamp() * 1e9),
        PACKET_KEY: data,
    }


def _iso(ts_ns: Optional[int]) -> Optional[str]:
    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat() if ts_ns else None


@_contract
def get_incident_packet(tool_context: ToolContext) -> dict:
    """Return the incident under investigation: identity, enforcement counts, deterministic rule ids and
    reasons, the severity floor, signatures, and the redacted evidence events with their evidence ids.

    Returns:
        A dict with status "success" and the packet fields.
    """
    st = tool_context.state
    pkt = st[PACKET_KEY]
    evidence = pkt.get("evidence_events") or []
    return {
        "status": "success",
        "incident_id": st["incident_id"],
        "revision": st["revision"],
        "visibility_scope": "FIREWALL_ONLY",
        "source_ip": st["source_ip"],
        "target_ip": st["target_ip"],
        "target_app": pkt.get("target_app"),
        "first_seen": pkt.get("first_seen"),
        "last_seen": pkt.get("last_seen"),
        "event_count": pkt.get("event_count"),
        "enforcement": pkt.get("enforcement"),
        "enforcement_counts": pkt.get("enforcement_counts") or {},
        "deterministic_severity_floor": pkt.get("deterministic_severity_floor"),
        "deterministic_rule_ids": pkt.get("deterministic_rule_ids") or [],
        "deterministic_reasons": pkt.get("deterministic_reasons") or [],
        "signatures": pkt.get("signatures") or [],
        "evidence_ids": [str(ev["id"]) for ev in evidence if ev.get("id")],
        "evidence": evidence,
    }


@_contract
async def query_traffic_context(direction: str, minutes_before: int, tool_context: ToolContext) -> dict:
    """Summarize FortiGate traffic logs around this incident from Loki.

    Args:
        direction: "to_target" for traffic to the incident's target IP, or "from_source" for traffic
            from the incident's source IP.
        minutes_before: how many minutes before the incident window to include, 1 to 30.

    Returns:
        A dict with status, counts by action and destination port, first and last seen, and up to 20
        redacted sample events.
    """
    st = tool_context.state
    if direction not in DIRECTIONS:
        return refused(f"direction must be one of {list(DIRECTIONS)}")
    try:
        minutes = min(MINUTES_MAX, max(MINUTES_MIN, int(minutes_before)))
    except (TypeError, ValueError):
        return refused("minutes_before must be an integer")
    if _deps.loki is None:
        return {"status": "error", "reason": "traffic context source is not configured"}

    params = {"dstip": st["target_ip"]} if direction == "to_target" else {"srcip": st["source_ip"]}
    query = TRAFFIC_CONTEXT_PROFILE.render(_deps.selector, params)
    start_ns = int(st["window_start_ns"]) - minutes * 60 * 1_000_000_000
    end_ns = int(st["window_end_ns"])
    try:
        lines = await _deps.loki.query_range(query, start_ns, end_ns, limit=TRAFFIC_MAX_LINES, direction="backward")
    except Exception as exc:
        return {"status": "error", "reason": f"traffic context query failed ({type(exc).__name__})"}

    # The profile's line filters are substring matches (dstip=192.0.2.1 also matches 192.0.2.10), so the
    # parsed events are filtered again on the exact incident IP.
    ip_field, ip_value = ("dstip", st["target_ip"]) if direction == "to_target" else ("srcip", st["source_ip"])
    parsed = (normalize_event(ts, line, allow_accepted_traffic=True) for ts, line in lines[:TRAFFIC_MAX_LINES])
    events = [ev for ev in parsed if ev and ev.get(ip_field) == ip_value]
    by_action: Dict[str, int] = {}
    by_port: Dict[str, int] = {}
    for ev in events:
        by_action[ev["action_normalized"]] = by_action.get(ev["action_normalized"], 0) + 1
        port = str(ev.get("dstport")) if ev.get("dstport") is not None else "none"
        by_port[port] = by_port.get(port, 0) + 1
    stamps = [ev["loki_ts_ns"] for ev in events]
    samples = []
    for ev in events[:TRAFFIC_MAX_SAMPLES]:
        view = evidence_view(ev)
        view["id"] = f"TC-{str(ev['id'])[:12]}"
        samples.append(view)
    return {
        "status": "success",
        "direction": direction,
        "minutes_before": minutes,
        "query_profile": f"{TRAFFIC_CONTEXT_PROFILE.name}@v{TRAFFIC_CONTEXT_PROFILE.version}",
        "lines_returned": len(lines),
        "events_parsed": len(events),
        "counts_by_action": by_action,
        "counts_by_dstport": by_port,
        "first_seen": _iso(min(stamps)) if stamps else None,
        "last_seen": _iso(max(stamps)) if stamps else None,
        "samples": samples,
    }


@_contract
def lookup_asset(ip: str, tool_context: ToolContext) -> dict:
    """Return asset context (VIP metadata, trusted network, shared NAT/CDN, approved scanner) for one of
    the incident's two IPs.

    Args:
        ip: the incident's source IP or target IP.

    Returns:
        A dict with status, the role of the IP, the VIP record if any, and the source classification
        with its provenance.
    """
    st = tool_context.state
    ip = str(ip or "").strip()
    if ip not in (st["source_ip"], st["target_ip"]):
        return refused("ip is not part of this incident")
    mgr = get_asset_manager()
    return {
        "status": "success",
        "ip": ip,
        "role": "target" if ip == st["target_ip"] else "source",
        "target_asset": mgr.get_target_asset(ip),
        "source_context": mgr.get_source_context(ip),
    }


@_contract
def lookup_signature(signature: str, tool_context: ToolContext) -> dict:
    """Return the locally reviewed metadata of one of the incident's signatures: grounded CVE ids,
    product, provenance and review date.

    Args:
        signature: one signature name exactly as listed in the incident packet.

    Returns:
        A dict with status and the reviewed metadata.
    """
    sigs = tool_context.state[PACKET_KEY].get("signatures") or []
    if signature not in sigs:
        return refused("signature is not one of this incident's signatures")
    mgr = get_signature_manager()
    meta = mgr.get_metadata(signature)
    return {
        "status": "success",
        "signature": signature,
        "reviewed": signature.strip() in mgr.signatures,
        "cve_ids": list(meta.get("cve_ids") or []),
        "product": meta.get("product"),
        "provenance": meta.get("provenance"),
        "reviewed_at": meta.get("reviewed_at"),
    }


@_contract
async def recent_incidents_for_source(tool_context: ToolContext) -> dict:
    """List up to 10 other incidents from the same source IP in the 24 hours before this incident.

    Returns:
        A dict with status and the incidents (id, target, severity, enforcement, last seen, rule ids).
    """
    st = tool_context.state
    if _deps.db is None:
        return {"status": "error", "reason": "incident store is not configured"}
    since = to_utc_datetime(int(st["window_end_ns"])) - RECENT_WINDOW
    rows = await _select(
        _deps.db,
        "SELECT id, target_ip, severity, enforcement, last_seen, deterministic_rule_ids FROM incidents "
        "WHERE source_ip = $1 AND id <> $2 ORDER BY last_seen DESC LIMIT 50",
        st["source_ip"],
        st["incident_id"],
    )
    out = []
    for row in rows:
        last_seen = to_utc_datetime(row["last_seen"])
        if last_seen < since:
            continue
        rule_ids = row.get("deterministic_rule_ids") or []
        if isinstance(rule_ids, str):
            rule_ids = json.loads(rule_ids or "[]")
        out.append({
            "id": row["id"],
            "target_ip": row["target_ip"],
            "severity": row["severity"],
            "enforcement": row["enforcement"],
            "last_seen": last_seen.isoformat(),
            "rule_ids": list(rule_ids),
        })
        if len(out) >= RECENT_MAX_ROWS:
            break
    return {"status": "success", "source_ip": st["source_ip"], "window_hours": 24, "incidents": out}


@_contract
def get_action_catalog(tool_context: ToolContext) -> dict:
    """Return the action ids an analyst may consider for this incident (deterministically eligible).

    Returns:
        A dict with status and the eligible actions (id, name, risk, requires_approval).
    """
    catalog = tool_context.state[PACKET_KEY].get("action_catalog") or []
    return {
        "status": "success",
        "eligible_actions": [
            {
                "id": a["id"],
                "name": a.get("name", a["id"]),
                "risk": a.get("risk_level", a.get("risk", "LOW")),
                "requires_approval": a.get("requires_approval", True),
            }
            for a in catalog
            if isinstance(a, dict) and a.get("id")
        ],
    }


EVIDENCE_TOOLS = [get_incident_packet, query_traffic_context]
CONTEXT_TOOLS = [lookup_asset, lookup_signature, recent_incidents_for_source, get_action_catalog]
