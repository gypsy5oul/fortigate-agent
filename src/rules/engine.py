"""Deterministic detection rule evaluation engine enforcing severity floors."""

import os
import yaml
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
PRIORITY_RANKS = {"URGENT_ALERT_AND_INVESTIGATE": 3, "INVESTIGATE": 2, "DIGEST": 1}


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

        for rule in self.rules:
            cond = rule.get("condition", {})
            matched = False
            sig_name = episode.get("signatures", [""])[0] if episode.get("signatures") else "exploit"

            # Check 1: Non-blocked UTM detection
            if rule["id"] == "RULE_NONBLOCKED_EXPLOIT_ATTEMPT":
                if enforcement in ("ALLOWED_OR_DETECTED", "MIXED"):
                    for ev in events:
                        if ev.get("log_type") == "utm" and ev.get("subtype") in ("ips", "waf"):
                            if ev.get("action_normalized") != "BLOCKED":
                                matched = True
                                sig_name = ev.get("signature") or "payload"
                                break

            # Check 2: Mixed enforcement sequence
            elif rule["id"] == "RULE_MIXED_ENFORCEMENT_SEQUENCE":
                if enforcement == "MIXED" and event_count >= cond.get("min_events", 2):
                    matched = True

            # Check 3: High frequency scanner
            elif rule["id"] == "RULE_HIGH_FREQUENCY_SCANNER":
                if enforcement == "BLOCKED" and event_count >= cond.get("min_events", 10):
                    matched = True

            # Check 4: SSL inspection anomaly
            elif rule["id"] == "RULE_SSL_INSPECTION_ANOMALY":
                for ev in events:
                    if ev.get("subtype") == "ssl" and ev.get("action_raw") != "success":
                        matched = True
                        sig_name = ev.get("raw_message", "handshake error")
                        break

            # Check 5: Antivirus detection
            elif rule["id"] == "RULE_ANTIVIRUS_DETECTION":
                for ev in events:
                    if ev.get("subtype") == "virus":
                        matched = True
                        sig_name = ev.get("signature") or "malware"
                        break

            if matched:
                matched_rules.append(rule["id"])
                rule_sev = rule.get("min_severity", "LOW")
                rule_prio = rule.get("priority", "DIGEST")

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
