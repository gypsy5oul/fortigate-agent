"""Normalizer for parsed FortiOS events into typed security event representations."""

import hashlib
import ipaddress
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from src.parsing.fortios_parser import parse_fortios_line
from src.observability.metrics import UNKNOWN_ACTIONS_TOTAL

_ACTION_MAP: Optional[Dict[str, Any]] = None
_ACTION_MAP_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "action_map.yaml"


def get_action_map() -> Dict[str, Any]:
    global _ACTION_MAP
    if _ACTION_MAP is None:
        if _ACTION_MAP_PATH.exists():
            try:
                with open(_ACTION_MAP_PATH, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    _ACTION_MAP = data.get("mappings", {})
            except Exception:
                _ACTION_MAP = {}
        else:
            _ACTION_MAP = {}
    return _ACTION_MAP


# Security blocking fallback actions
BLOCKED_ACTIONS = frozenset([
    "deny", "drop", "blocked", "block", "dropped", "ip-block", "quarantine",
    "reset", "reset-client", "reset-server", "reset-both", "reset_client", "reset_server",
    "drop_session", "clear_session"
])

# Permitted fallback actions
ALLOWED_ACTIONS = frozenset([
    "accept", "pass", "passthrough", "detected", "monitor", "permit", "monitored",
    "pass_session", "exempt"
])

# Session termination fallback actions
SESSION_CLOSE_ACTIONS = frozenset([
    "close", "client-rst", "server-rst", "timeout"
])


def normalize_action(
    action_raw: Optional[str],
    log_type: Optional[str] = None,
    subtype: Optional[str] = None,
    utmaction: Optional[str] = None,
) -> str:
    """Map raw FortiOS action to standardized enforcement categories using config/action_map.yaml.
    
    If utmaction is present in traffic logs, it takes precedence over action.
    """
    norm_type = (log_type or "").strip().lower()
    norm_subtype = (subtype or "").strip().lower()

    target_action = utmaction if (norm_type == "traffic" and utmaction) else action_raw
    if not target_action:
        return "UNKNOWN"

    act = target_action.strip().lower()
    action_map = get_action_map()

    entry = None
    if norm_type and norm_type in action_map:
        type_cfg = action_map[norm_type]
        if norm_subtype and norm_subtype in type_cfg:
            entry = type_cfg[norm_subtype].get(act)
        if not entry and "default" in type_cfg:
            entry = type_cfg["default"].get(act)

    # Check top-level or other namespaces if not matched or no log_type supplied
    if not entry:
        for t_name, t_cfg in action_map.items():
            if isinstance(t_cfg, dict):
                if norm_subtype and norm_subtype in t_cfg and act in t_cfg[norm_subtype]:
                    entry = t_cfg[norm_subtype][act]
                    break
                if "default" in t_cfg and act in t_cfg["default"]:
                    entry = t_cfg["default"][act]
                    break

    if entry and "enforcement" in entry:
        return entry["enforcement"]

    # Fallback to hardcoded sets if action map had no match
    if act in BLOCKED_ACTIONS:
        return "BLOCKED"
    if act in ALLOWED_ACTIONS:
        return "ALLOWED_OR_DETECTED"
    if act in SESSION_CLOSE_ACTIONS:
        return "SESSION_CLOSED"

    UNKNOWN_ACTIONS_TOTAL.labels(type=norm_type or "unknown", subtype=norm_subtype or "unknown").inc()
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
    utmaction = parsed.get("utmaction")
    log_type = parsed.get("type", "unknown")
    subtype = parsed.get("subtype")
    action_normalized = normalize_action(action_raw, log_type=log_type, subtype=subtype, utmaction=utmaction)

    def _to_int(val: Optional[str]) -> Optional[int]:
        if val is None or val == "":
            return None
        try:
            return int(val)
        except ValueError:
            return None

    raw_signature = (
        parsed.get("attack") or
        parsed.get("virus") or
        parsed.get("app") or
        parsed.get("msg") or
        parsed.get("vuln_name")
    )
    signature_truncated = False
    signature = raw_signature
    if signature and len(signature) > 512:
        signature = signature[:512]
        signature_truncated = True

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
        "log_type": log_type,
        "subtype": subtype,
        "action_raw": action_raw,
        "utmaction": utmaction,
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
        "signature_truncated": signature_truncated,
        "url": parsed.get("url"),
        "http_method": parsed.get("httpmethod"),
        "severity_raw": parsed.get("level") or parsed.get("crlevel") or parsed.get("severity"),
        "raw_message": raw_line,
        "processing_status": "PENDING",
    }
