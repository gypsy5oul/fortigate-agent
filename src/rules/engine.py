import os
import yaml
import logging
import ipaddress
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
PRIORITY_RANKS = {"URGENT_ALERT_AND_INVESTIGATE": 3, "INVESTIGATE": 2, "DIGEST": 1}

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


def is_trusted_network(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


class RuleEngine:
    def __init__(self, rules_path: Optional[str] = None):
        if not rules_path:
            rules_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "rules.yaml")
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.rules_path):
            logger.warning("Rules file %s not found. Using empty rule set.", self.rules_path)
            return []
        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data.get("rules", [])

    def evaluate_episode(self, episode: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate an attack episode against the deterministic rule pack.
        
        Returns:
            Dict containing matched_rule_ids, severity_floor, routing_outcome, reasons
        """
        matched_rules = []
        highest_severity = "LOW"
        highest_priority = "DIGEST"
        reasons = []

        events = episode.get("events", [])
        enforcement = episode.get("enforcement", "UNKNOWN")
        event_count = episode.get("event_count", 0)
        direction = episode.get("direction", "UNKNOWN")
        source_ip = episode.get("source_ip", "")

        for rule in self.rules:
            cond = rule.get("condition", {})
            matched = False
            sig_name = episode.get("signatures", [""])[0] if episode.get("signatures") else "exploit"
            rule_sev_override = None
            rule_prio_override = None

            # Check 1: Non-blocked UTM detection (requires UTM event with action_normalized == ALLOWED_OR_DETECTED)
            if rule["id"] == "RULE_NONBLOCKED_EXPLOIT_ATTEMPT":
                for ev in events:
                    if ev.get("log_type") == "utm" and ev.get("subtype") in ("ips", "waf"):
                        if ev.get("action_normalized") == "ALLOWED_OR_DETECTED":
                            matched = True
                            sig_name = ev.get("signature") or "payload"
                            break

            # Check 2: Mixed enforcement sequence (requires both BLOCKED and ALLOWED_OR_DETECTED UTM events)
            elif rule["id"] == "RULE_MIXED_ENFORCEMENT_SEQUENCE":
                utm_blocked = any(ev.get("log_type") == "utm" and ev.get("action_normalized") == "BLOCKED" for ev in events)
                utm_allowed = any(ev.get("log_type") == "utm" and ev.get("action_normalized") == "ALLOWED_OR_DETECTED" for ev in events)
                if utm_blocked and utm_allowed and event_count >= cond.get("min_events", 2):
                    matched = True

            # Check 3: High frequency scanner (requires direction == INBOUND and source not in RFC1918/CGNAT/ULA)
            elif rule["id"] == "RULE_HIGH_FREQUENCY_SCANNER":
                if (
                    enforcement == "BLOCKED"
                    and event_count >= cond.get("min_events", 10)
                    and direction == "INBOUND"
                    and not is_trusted_network(source_ip)
                ):
                    matched = True

            # Check 4: SSL inspection anomaly (static reason + action_raw, no raw line)
            elif rule["id"] == "RULE_SSL_INSPECTION_ANOMALY":
                for ev in events:
                    if ev.get("subtype") == "ssl" and ev.get("action_raw") != "success":
                        matched = True
                        sig_name = f"action={ev.get('action_raw', 'failed')}"
                        break

            # Check 5: Antivirus detection (CRITICAL/URGENT only when ALLOWED_OR_DETECTED; blocked AV -> MEDIUM/DIGEST)
            elif rule["id"] == "RULE_ANTIVIRUS_DETECTION":
                for ev in events:
                    if ev.get("subtype") == "virus":
                        matched = True
                        sig_name = ev.get("signature") or "malware"
                        if ev.get("action_normalized") == "ALLOWED_OR_DETECTED":
                            rule_sev_override = "CRITICAL"
                            rule_prio_override = "URGENT_ALERT_AND_INVESTIGATE"
                        else:
                            rule_sev_override = "MEDIUM"
                            rule_prio_override = "DIGEST"
                        break

            # Check 6: Unknown action mapping visibility rule (DIGEST, LOW)
            elif rule["id"] == "RULE_UNKNOWN_ACTION_MAPPING":
                for ev in events:
                    if ev.get("action_normalized") == "UNKNOWN":
                        matched = True
                        sig_name = ev.get("action_raw") or "unknown"
                        break

            if matched:
                matched_rules.append(rule["id"])
                rule_sev = rule_sev_override or rule.get("min_severity", "LOW")
                rule_prio = rule_prio_override or rule.get("priority", "DIGEST")

                if SEVERITY_RANKS.get(rule_sev, 1) > SEVERITY_RANKS.get(highest_severity, 1):
                    highest_severity = rule_sev

                if PRIORITY_RANKS.get(rule_prio, 1) > PRIORITY_RANKS.get(highest_priority, 1):
                    highest_priority = rule_prio

                template = rule.get("reason_template", "{name}")
                reason_str = template.format(
                    signature=sig_name,
                    event_count=event_count,
                    reason=sig_name,
                    name=rule["name"],
                )
                reasons.append(reason_str)

        return {
            "matched_rule_ids": matched_rules,
            "severity_floor": highest_severity,
            "routing_outcome": highest_priority if matched_rules else "DIGEST",
            "reasons": reasons,
        }
