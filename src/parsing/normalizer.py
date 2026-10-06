"""Normalizer for parsed FortiOS events into typed security event representations."""

import hashlib
import ipaddress
from typing import Dict, Any, Optional
from src.parsing.fortios_parser import parse_fortios_line

# Security blocking actions: firewall or UTM dropped/denied/quarantined the traffic
BLOCKED_ACTIONS = frozenset([
    "deny", "drop", "blocked", "block", "dropped", "ip-block", "quarantine",
    "reset", "reset-client", "reset-server", "reset-both"
])

# Permitted actions: firewall or UTM allowed the traffic to pass / detected without blocking
ALLOWED_ACTIONS = frozenset([
    "accept", "pass", "passthrough", "detected", "monitor", "permit"
])

# Normal session termination actions: routine TCP closure, RST, or timeout
SESSION_CLOSE_ACTIONS = frozenset([
    "close", "client-rst", "server-rst", "timeout", "clear_session"
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
    if act in SESSION_CLOSE_ACTIONS:
        return "SESSION_CLOSED"
    return "UNKNOWN"


INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


def classify_direction(
    srcip: str,
    dstip: str,
    srcintfrole: Optional[str] = None,
    dstintfrole: Optional[str] = None,
    raw_direction: Optional[str] = None,
) -> str:
    """Classify traffic flow direction (INBOUND, OUTBOUND, LATERAL, EXTERNAL, UNKNOWN)."""
    # 1. Direct log direction token (from UTM / IPS logs)
    if raw_direction:
        d = raw_direction.strip().lower()
        if d in ("incoming", "inbound"):
            return "INBOUND"
        if d in ("outgoing", "outbound"):
            return "OUTBOUND"

    # 2. Interface roles
    s_role = (srcintfrole or "").strip().lower()
    d_role = (dstintfrole or "").strip().lower()
    if s_role == "wan" and d_role in ("lan", "dmz", "undefined", ""):
        return "INBOUND"
    if s_role in ("lan", "dmz") and d_role == "wan":
        return "OUTBOUND"

    # 3. IP address scope (RFC 1918 / CGNAT / Local vs Global)
    try:
        s_ip = ipaddress.ip_address(srcip)
        d_ip = ipaddress.ip_address(dstip)
        s_priv = any(s_ip in net for net in INTERNAL_NETWORKS)
        d_priv = any(d_ip in net for net in INTERNAL_NETWORKS)

        if not s_priv and d_priv:
            return "INBOUND"
        if s_priv and not d_priv:
            return "OUTBOUND"
        if s_priv and d_priv:
            return "LATERAL"
        return "EXTERNAL"
    except ValueError:
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

    srcintfrole = parsed.get("srcintfrole")
    dstintfrole = parsed.get("dstintfrole")
    raw_direction = parsed.get("direction")
    vd = parsed.get("vd", "root")
    direction = classify_direction(srcip, dstip, srcintfrole, dstintfrole, raw_direction)

    event_id = generate_event_id(loki_ts_ns, raw_line, parsed)

    return {
        "id": event_id,
        "loki_ts_ns": loki_ts_ns,
        "eventtime_ns": _to_int(parsed.get("eventtime")),
        "devid": parsed.get("devid"),
        "vd": vd,
        "direction": direction,
        "srcintfrole": srcintfrole,
        "dstintfrole": dstintfrole,
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
        "processing_status": "PENDING",
    }
