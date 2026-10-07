"""Named, versioned LogQL query profiles with typed parameter rendering and escaping."""

import re
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field


def escape_logql_string(val: str) -> str:
    """Escapes strings for safe inclusion in LogQL line and regex filters.
    
    Prevents LogQL injection by escaping backslashes, double quotes, and control chars.
    """
    if not isinstance(val, str):
        val = str(val)
    val = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return val


def escape_logql_regex(val: str) -> str:
    """Escapes strings for safe inclusion inside a LogQL regular expression."""
    escaped = re.escape(val)
    return escape_logql_string(escaped)


@dataclass
class QueryProfile:
    """Represents a named, versioned LogQL query profile."""
    name: str
    version: int
    template_fn: Callable[[str, Dict[str, Any]], str]
    description: str = ""

    def render(self, selector: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Renders the safe LogQL query string."""
        return self.template_fn(selector.strip(), params or {})

    def stream_key(self, selector: str) -> str:
        """Returns the durable stream name for checkpoints: <selector>#<profile>@v<version>"""
        return f"{selector.strip()}#{self.name}@v{self.version}"


def _render_utm_detections(selector: str, params: Dict[str, Any]) -> str:
    query = f'{selector} |= "type=\\"utm\\""'
    subtypes = params.get("subtypes")
    if subtypes and isinstance(subtypes, (list, tuple)):
        escaped_subtypes = [escape_logql_regex(s) for s in subtypes if s]
        if escaped_subtypes:
            regex_pattern = f'subtype=\\\"(?:{"|".join(escaped_subtypes)})\\\"'
            query += f' |~ "{regex_pattern}"'
    return query


def _render_firewall_events(selector: str, params: Dict[str, Any]) -> str:
    query = f'{selector} |= "type=\\"event\\""'
    subtypes = params.get("subtypes")
    if subtypes and isinstance(subtypes, (list, tuple)):
        escaped_subtypes = [escape_logql_regex(s) for s in subtypes if s]
        if escaped_subtypes:
            regex_pattern = f'subtype=\\\"(?:{"|".join(escaped_subtypes)})\\\"'
            query += f' |~ "{regex_pattern}"'
    return query


def _render_traffic_context(selector: str, params: Dict[str, Any]) -> str:
    query = f'{selector} |= "type=\\"traffic\\""'
    
    # Bounded parameter filters
    if params.get("vd"):
        query += f' |= "vd=\\"{escape_logql_string(params["vd"])}\\""'
    if params.get("devid"):
        query += f' |= "devid=\\"{escape_logql_string(params["devid"])}\\""'
    if params.get("srcip"):
        query += f' |= "srcip={escape_logql_string(params["srcip"])}"'
    if params.get("dstip"):
        query += f' |= "dstip={escape_logql_string(params["dstip"])}"'
    if params.get("srcport"):
        query += f' |= "srcport={int(params["srcport"])}"'
    if params.get("dstport"):
        query += f' |= "dstport={int(params["dstport"])}"'
    if params.get("sessionid"):
        query += f' |= "sessionid={int(params["sessionid"])}"'

    return query


def _render_traffic_baseline(selector: str, params: Dict[str, Any]) -> str:
    query = f'{selector} |= "type=\\"traffic\\""'
    if params.get("vd"):
        query += f' |= "vd=\\"{escape_logql_string(params["vd"])}\\""'
    if params.get("devid"):
        query += f' |= "devid=\\"{escape_logql_string(params["devid"])}\\""'
    return query


def _render_security_events(selector: str, params: Dict[str, Any]) -> str:
    return f'{selector} |~ "type=\\"utm\\"|type=\\"event\\"|action=\\"deny\\"|utmaction=\\"block\\""'


SECURITY_EVENTS_PROFILE = QueryProfile(
    name="security_events",
    version=1,
    template_fn=_render_security_events,
    description="Selects FortiOS UTM, events, and blocked/denied traffic for security monitoring",
)

UTM_DETECTIONS_PROFILE = QueryProfile(
    name="utm_detections",
    version=1,
    template_fn=_render_utm_detections,
    description="Selects FortiOS UTM security detection logs (IPS, WAF, AV, WebFilter, SSL anomaly)",
)

FIREWALL_EVENTS_PROFILE = QueryProfile(
    name="firewall_events",
    version=1,
    template_fn=_render_firewall_events,
    description="Selects FortiOS system, administration, and authentication event logs",
)

TRAFFIC_CONTEXT_PROFILE = QueryProfile(
    name="traffic_context",
    version=1,
    template_fn=_render_traffic_context,
    description="On-demand bounded traffic logs for incident-scoped session enrichment",
)

TRAFFIC_BASELINE_PROFILE = QueryProfile(
    name="traffic_baseline",
    version=1,
    template_fn=_render_traffic_baseline,
    description="Aggregate traffic volume baseline analysis (disabled by default)",
)

QUERY_PROFILES: Dict[str, QueryProfile] = {
    SECURITY_EVENTS_PROFILE.name: SECURITY_EVENTS_PROFILE,
    UTM_DETECTIONS_PROFILE.name: UTM_DETECTIONS_PROFILE,
    FIREWALL_EVENTS_PROFILE.name: FIREWALL_EVENTS_PROFILE,
    TRAFFIC_CONTEXT_PROFILE.name: TRAFFIC_CONTEXT_PROFILE,
    TRAFFIC_BASELINE_PROFILE.name: TRAFFIC_BASELINE_PROFILE,
}


def get_query_profile(name: str) -> QueryProfile:
    """Fetches a registered query profile by name."""
    if name not in QUERY_PROFILES:
        raise KeyError(f"Unknown query profile '{name}'. Registered: {list(QUERY_PROFILES.keys())}")
    return QUERY_PROFILES[name]
