"""Declarative data-driven rule evaluation engine for firewall security episodes."""

import os
import re
import html
import yaml
import logging
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set

from src.context.assets import get_asset_manager

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
PRIORITY_RANKS = {
    "URGENT_ALERT_AND_INVESTIGATE": 3,
    "INVESTIGATE": 2,
    "DIGEST": 1,
    "RETAIN_WITH_VISIBILITY_GAP": 0,
    "RETAIN_AS_BASELINE": 0,
}

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
    """Checks if IP belongs to RFC 1918, CGNAT, loopback, or configured trusted networks."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if any(ip in net for net in INTERNAL_NETWORKS):
            return True
        asset_mgr = get_asset_manager()
        ctx = asset_mgr.get_source_context(ip_str)
        return bool(ctx.get("is_trusted", False))
    except (ValueError, Exception):
        return False


class RuleEngine:
    def __init__(self, rules_path: Optional[str] = None, rules: Optional[List[Dict[str, Any]]] = None):
        if rules is not None:
            self.rules = rules
            self.rules_path = rules_path or ""
        else:
            if not rules_path:
                rules_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "rules.yaml")
            self.rules_path = rules_path
            self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.rules_path):
            logger.warning("Rules file %s not found. Using empty rule set.", self.rules_path)
            return []
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("rules", [])
        except Exception as e:
            logger.error("Failed to load rules from %s: %s", self.rules_path, e)
            return []

    def _evaluate_condition(self, cond: Dict[str, Any], episode: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Evaluates declarative conditions against security episode data."""
        events = episode.get("events", [])
        event_count = episode.get("event_count", len(events))
        enforcement = episode.get("enforcement", "UNKNOWN")
        direction = (episode.get("direction") or "UNKNOWN").upper()
        source_ip = episode.get("source_ip", "")

        # Cumulative evidence carried by the episode itself. The aggregator keeps
        # ``signatures`` and ``enforcement_counts`` for every event it ever saw, while
        # ``events`` holds at most 25 retained lines and is empty right after a restart.
        # Every check below therefore combines the live event list with this evidence,
        # so an episode is never judged on its newest event alone (B.1 Defect A).
        stored_sigs = [s for s in (episode.get("signatures") or []) if s]
        stored_subtypes = {str(s).lower() for s in (episode.get("utm_subtypes") or []) if s}
        stored_counts = {
            k: v for k, v in (episode.get("enforcement_counts") or {}).items()
            if isinstance(v, (int, float)) and v > 0
        }
        # Subtypes and signatures only come from UTM logs; ALLOWED_OR_DETECTED is only
        # produced by UTM logs.
        stored_has_utm = bool(stored_subtypes) or bool(stored_sigs) or stored_counts.get("ALLOWED_OR_DETECTED", 0) > 0

        template_params: Dict[str, Any] = {
            "event_count": event_count,
            "source_ip": source_ip,
            "target_ip": episode.get("target_ip", ""),
            "signature": "exploit",
            "reason": "anomaly detected",
        }

        # 1. Minimum total events
        if "min_events" in cond:
            if event_count < cond["min_events"]:
                return False, {}

        # 2. Direction constraint
        if "direction" in cond:
            if direction != cond["direction"].upper():
                return False, {}

        # 3. Source exclusion (trusted networks)
        if cond.get("source_not_in") == "trusted_networks":
            if is_trusted_network(source_ip):
                return False, {}

        # 4. Required evidence presence
        req_ev = cond.get("required_evidence")
        if req_ev == "utm":
            has_utm = any(ev.get("log_type") == "utm" for ev in events) or stored_has_utm
            if not has_utm:
                return False, {}

        # 5. Type and subtype matching
        req_type = cond.get("type")
        req_subtypes = [s.lower() for s in cond.get("subtypes", [])]

        if req_type or req_subtypes:
            matching_events = []
            for ev in events:
                if req_type and ev.get("log_type", "").lower() != req_type.lower():
                    continue
                if req_subtypes and ev.get("subtype", "").lower() not in req_subtypes:
                    continue
                matching_events.append(ev)

            # Stored UTM subtypes and signatures stand in for UTM events that are no longer
            # in the retained event list (evicted by the 25-line cap or lost across a
            # restart). A rule that names subtypes needs one of them in the stored set.
            stored_match = (
                (req_type or "").lower() == "utm"
                and (bool(stored_subtypes) or bool(stored_sigs))
                and (not req_subtypes or bool(stored_subtypes & set(req_subtypes)))
            )
            if not matching_events and not stored_match:
                return False, {}

            # If rule specifies enforcement with type=utm, verify against the UTM evidence
            if "enforcement" in cond and req_type == "utm":
                allowed_enfs = set(cond["enforcement"])
                utm_enfs = {ev.get("action_normalized") for ev in matching_events}
                if stored_match:
                    utm_enfs |= set(stored_counts)
                    if enforcement in allowed_enfs:
                        utm_enfs.add(enforcement)
                if not (allowed_enfs & utm_enfs):
                    return False, {}
            # Capture signature from a matching event, else from the stored evidence
            for ev in matching_events:
                sig = ev.get("signature") or ev.get("attack") or ev.get("virus") or ev.get("vuln_name")
                if sig:
                    template_params["signature"] = sig
                    break
            if template_params["signature"] == "exploit" and stored_sigs:
                template_params["signature"] = stored_sigs[0]
        else:
            # 6. Episode-level enforcement check
            if "enforcement" in cond:
                allowed_enfs = set(cond["enforcement"])
                if enforcement == "MIXED" and "MIXED" in allowed_enfs:
                    utm_blocked = (
                        any(ev.get("log_type") == "utm" and ev.get("action_normalized") == "BLOCKED" for ev in events)
                        or stored_counts.get("BLOCKED", 0) > 0
                    )
                    utm_allowed = (
                        any(ev.get("log_type") == "utm" and ev.get("action_normalized") == "ALLOWED_OR_DETECTED" for ev in events)
                        or stored_counts.get("ALLOWED_OR_DETECTED", 0) > 0
                    )
                    if not (utm_blocked and utm_allowed):
                        return False, {}
                elif enforcement not in allowed_enfs:
                    return False, {}

        # 7. Status_not condition
        if "status_not" in cond:
            forbidden_statuses = set(cond["status_not"])
            has_valid_status = False
            for ev in events:
                status_val = ev.get("status") or ev.get("action_raw") or ""
                if status_val.lower() not in forbidden_statuses:
                    has_valid_status = True
                    template_params["reason"] = f"action={status_val}"
                    break
            if not has_valid_status:
                return False, {}

        # 8. Distinct services / ports
        if "min_distinct_services" in cond:
            distinct_services = set(episode.get("services", [])) | set(episode.get("target_ports", []))
            for ev in events:
                if ev.get("service"):
                    distinct_services.add(ev["service"])
                if ev.get("dstport"):
                    distinct_services.add(ev["dstport"])
            if len(distinct_services) < cond["min_distinct_services"]:
                return False, {}

        # 9. Distinct sources (distributed attack)
        if "min_distinct_sources" in cond:
            distinct_srcs = set(episode.get("source_ips", []))
            for ev in events:
                if ev.get("srcip"):
                    distinct_srcs.add(ev["srcip"])
            if len(distinct_srcs) < cond["min_distinct_sources"]:
                return False, {}

        # 10. Distinct targets
        if "min_distinct_targets" in cond:
            distinct_targets = set(episode.get("target_ips", []))
            for ev in events:
                if ev.get("dstip"):
                    distinct_targets.add(ev["dstip"])
            if len(distinct_targets) < cond["min_distinct_targets"]:
                return False, {}

        # 11. Unmapped actions
        if cond.get("action_normalized") == "UNKNOWN":
            has_unknown = any(ev.get("action_normalized") == "UNKNOWN" for ev in events)
            if not has_unknown and enforcement != "UNKNOWN":
                return False, {}

        # 12. Health metrics
        if "health_metric" in cond:
            ep_metric = episode.get("health_metric")
            if ep_metric != cond["health_metric"]:
                return False, {}

        # Capture first signature if not already set
        if template_params["signature"] == "exploit":
            sigs = episode.get("signatures", [])
            if sigs:
                template_params["signature"] = sigs[0]

        return True, template_params

    def evaluate_episode(self, episode: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate an attack episode against the declarative rule set.
        
        Returns:
            Dict containing matched_rule_ids, severity_floor, routing_outcome, reasons
        """
        matched_rules = []
        highest_severity = "LOW"
        highest_priority = "DIGEST"
        routing_outcome = "DIGEST"
        reasons = []

        max_sev_rank = 0
        max_prio_rank = -1

        for rule in self.rules:
            cond = rule.get("condition", {})
            matched, t_params = self._evaluate_condition(cond, episode)
            if not matched:
                continue

            rule_id = rule.get("id", "UNKNOWN_RULE")
            matched_rules.append(rule_id)

            # Severity floor tracking
            rule_sev = rule.get("min_severity", "LOW")
            sev_rank = SEVERITY_RANKS.get(rule_sev, 1)
            if sev_rank > max_sev_rank:
                max_sev_rank = sev_rank
                highest_severity = rule_sev

            # Priority and routing tracking
            rule_prio = rule.get("priority", "DIGEST")
            rule_routing = rule.get("routing_outcome") or rule_prio
            prio_rank = PRIORITY_RANKS.get(rule_prio, 1)

            if prio_rank > max_prio_rank:
                max_prio_rank = prio_rank
                highest_priority = rule_prio
                routing_outcome = rule_routing

            # Safe templated reason string
            template = rule.get("reason_template", "Firewall security rule triggered: {rule_id}")
            try:
                reason_str = template.format(**t_params, rule_id=rule_id)
            except Exception:
                reason_str = f"Rule {rule_id} condition satisfied ({t_params.get('event_count', 1)} events)."
            reasons.append(reason_str)

        return {
            "matched_rule_ids": matched_rules,
            "severity_floor": highest_severity,
            "priority": highest_priority,
            "routing_outcome": routing_outcome,
            "reasons": reasons,
        }
