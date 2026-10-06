"""Normalizer for parsed FortiOS events into typed security event representations."""

import hashlib
from typing import Dict, Any, Optional
from src.parsing.fortios_parser import parse_fortios_line

BLOCKED_ACTIONS = frozenset([
    "deny", "drop", "blocked", "reset", "close", "client-rst", "server-rst", "clear_session"
])

ALLOWED_ACTIONS = frozenset([
    "accept", "pass", "passthrough", "detected", "monitor", "permit"
])


def normalize_action(action_raw: Optional[str]) -> str:
    """Map raw FortiOS action to standardized enforcement categories."""
    if not action_raw:
        return "UNKNOWN"
    act = action_raw.strip().lower()
    if act in BLOCKED_ACTIONS:
        return "BLOCKED"
    if act in ALLOWED_ACTIONS:
        return "ALLOWED_OR_DETECTED"
    return "UNKNOWN"


def generate_event_id(loki_ts_ns: int, raw_line: str, parsed: Dict[str, str]) -> str:
    """Generate a deterministic SHA-256 fingerprint for deduplication."""
    devid = parsed.get("devid", "")
    logid = parsed.get("logid", "")
    srcip = parsed.get("srcip", "")
    dstip = parsed.get("dstip", "")
    srcport = parsed.get("srcport", "")
    dstport = parsed.get("dstport", "")
    proto = parsed.get("proto", "")
    action = parsed.get("action", "")

    seed = f"{devid}|{logid}|{loki_ts_ns}|{srcip}|{srcport}|{dstip}|{dstport}|{proto}|{action}|{raw_line}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def normalize_event(loki_ts_ns: int, raw_line: str) -> Optional[Dict[str, Any]]:
    """Parse raw log line and return normalized security event dictionary."""
    parsed = parse_fortios_line(raw_line)
    if not parsed:
        return None

    srcip = parsed.get("srcip")
    dstip = parsed.get("dstip")
    if not srcip or not dstip:
        # Ignore events without source/destination IP (e.g. system status banners)
        return None

    action_raw = parsed.get("action")
    action_normalized = normalize_action(action_raw)

    def _to_int(val: Optional[str]) -> Optional[int]:
        if val is None or val == "":
            return None
        try:
            return int(val)
        except ValueError:
            return None

    signature = (
        parsed.get("attack") or
        parsed.get("virus") or
        parsed.get("app") or
        parsed.get("msg") or
        parsed.get("vuln_name")
    )

    event_id = generate_event_id(loki_ts_ns, raw_line, parsed)

    return {
        "id": event_id,
        "loki_ts_ns": loki_ts_ns,
        "eventtime_ns": _to_int(parsed.get("eventtime")),
        "devid": parsed.get("devid"),
        "logid": parsed.get("logid"),
        "log_type": parsed.get("type", "unknown"),
        "subtype": parsed.get("subtype"),
        "action_raw": action_raw,
        "action_normalized": action_normalized,
        "srcip": srcip,
        "srcport": _to_int(parsed.get("srcport")),
        "dstip": dstip,
        "dstport": _to_int(parsed.get("dstport")),
        "proto": _to_int(parsed.get("proto")),
        "service": parsed.get("service"),
        "policyid": _to_int(parsed.get("policyid")),
        "sessionid": _to_int(parsed.get("sessionid")),
        "signature": signature,
        "url": parsed.get("url"),
        "http_method": parsed.get("httpmethod"),
        "severity_raw": parsed.get("level") or parsed.get("crlevel") or parsed.get("severity"),
        "raw_message": raw_line,
    }
