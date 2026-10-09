"""Google Chat Cards v2 payload builder with strict HTML escaping and incident threading."""

import html
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def get_severity_emoji(severity: str) -> str:
    mapping = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🔵 LOW",
    }
    return mapping.get(severity, "⚪ UNKNOWN")


def build_gchat_card(
    incident: Dict[str, Any],
    revision: int,
    assessment: Dict[str, Any],
    grafana_base_url: str = "https://grafana.example.internal",
    datasource_uid: str = "loki",
    cli_recommendations_enabled: bool = False,
    fortios_build: Optional[str] = None,
) -> Dict[str, Any]:
    """Render Google Chat Cards v2 payload with HTML escaping and safe action rendering."""
    incident_id = incident["id"]
    source_ip = incident["source_ip"]
    target_ip = incident["target_ip"]
    target_app = incident.get("target_app") or f"Target Host ({target_ip})"
    severity = assessment.get("severity") or incident.get("severity", "MEDIUM")
    enforcement = assessment.get("enforcement") or incident.get("enforcement", "UNKNOWN")
    summary = assessment.get("summary", "Security event detected on perimeter firewall.")
    actions = assessment.get("recommended_action_ids", [])

    # Derive card title from rule name or attack/virus/vuln_name only (never raw msg/url/app)
    title_sig = incident.get("rule_name") or incident.get("attack") or incident.get("virus") or incident.get("vuln_name")
    if not title_sig and incident.get("rule_ids"):
        title_sig = incident["rule_ids"][0]
    if not title_sig:
        cve_refs = assessment.get("cve_references") or []
        title_sig = cve_refs[0] if cve_refs else "Perimeter Detection"

    def _defang(val: Any) -> str:
        s = str(val) if val is not None else ""
        return s.replace("http://", "hxxp://").replace("https://", "hxxps://")

    # HTML escaping for all injected fields (with URL defanging to prevent link injection)
    esc_incident_id = html.escape(_defang(incident_id), quote=True)
    esc_source_ip = html.escape(_defang(source_ip), quote=True)
    esc_target_ip = html.escape(_defang(target_ip), quote=True)
    esc_target_app = html.escape(_defang(target_app), quote=True)
    esc_severity = html.escape(_defang(severity), quote=True)
    esc_enforcement = html.escape(_defang(enforcement), quote=True)
    esc_summary = html.escape(_defang(summary), quote=True)
    esc_title_sig = html.escape(_defang(title_sig), quote=True)
    esc_exploit = html.escape(_defang(assessment.get("exploitation_assessment", "INSUFFICIENT_EVIDENCE")), quote=True)
    event_count = incident.get("event_count", 1)

    # Deep drilldown Grafana Explore URL (URL constructed with query params, pointing only to grafana_base_url)
    clean_grafana_base = grafana_base_url.rstrip("/")
    explore_url = f"{clean_grafana_base}/explore?left=%5B%22now-1h%22,%22now%22,%22{datasource_uid}%22,%7B%22expr%22:%22%7Bservice_name%3D%5C%22forticlient%5C%22%7D%20%7C%3D%20%5C%22{source_ip}%5C%22%22%7D%5D"

    # Action rendering: only show CLI commands if enabled, verified build matches, and eligible
    rendered_actions = []
    for act_id in actions:
        if cli_recommendations_enabled and fortios_build is not None:
            # In Phase A.1 / B2, action templates require verified_build matching
            rendered_actions.append(f"Manual review: {html.escape(str(act_id), quote=True)}")
        else:
            rendered_actions.append(f"Manual review: {html.escape(str(act_id), quote=True)}")

    action_text = f"<b>Recommended Actions:</b><br>{'<br>'.join(rendered_actions) if rendered_actions else 'None'}"

    widgets: List[Dict[str, Any]] = [
        {
            "decoratedText": {
                "topLabel": "Incident Target",
                "text": f"<b>{esc_target_app}</b> ({esc_target_ip})",
                "icon": {"knownIcon": "BOOKMARK"},
            }
        },
        {
            "decoratedText": {
                "topLabel": "Attacker Source IP",
                "text": f"<b>{esc_source_ip}</b>",
                "icon": {"knownIcon": "PERSON"},
            }
        },
        {
            "decoratedText": {
                "topLabel": "Enforcement Status",
                "text": f"<b>{esc_enforcement}</b> (Events: {event_count})",
                "icon": {"knownIcon": "SHIELD"},
            }
        },
        {
            "decoratedText": {
                "topLabel": "Exploitation Assessment",
                "text": f"<i>{esc_exploit}</i>",
                "icon": {"knownIcon": "DESCRIPTION"},
            }
        },
        {
            "textParagraph": {
                "text": f"<b>Analysis Summary:</b><br>{esc_summary}"
            }
        },
        {
            "textParagraph": {
                "text": action_text
            }
        },
        {
            "textParagraph": {
                "text": "<font color=\"#888888\"><i>Visibility Scope: FIREWALL_ONLY. Compromise cannot be verified from perimeter telemetry alone.</i></font>"
            }
        },
        {
            "buttonList": {
                "buttons": [
                    {
                        "text": "View in Grafana",
                        "onClick": {
                            "openLink": {"url": explore_url}
                        }
                    }
                ]
            }
        }
    ]

    card_v2 = {
        "cardId": f"forti_{incident_id}_{revision}",
        "card": {
            "header": {
                "title": f"{get_severity_emoji(severity)}: {esc_title_sig}",
                "subtitle": f"Incident {esc_incident_id} • Revision {revision} • FortiGate 200G DPI",
            },
            "sections": [
                {
                    "collapsible": False,
                    "widgets": widgets,
                }
            ],
        },
    }

    plain_text = (
        f"[{esc_severity}] FortiGate Alert: {esc_title_sig}\n"
        f"Target: {esc_target_app} ({esc_target_ip}) | Attacker: {esc_source_ip}\n"
        f"Enforcement: {esc_enforcement} | Incident: {esc_incident_id} (Rev {revision})\n"
        f"Summary: {esc_summary}\n"
        f"Grafana: {explore_url}"
    )

    return {
        "text": plain_text,
        "cardsV2": [card_v2],
        "thread": {"threadKey": incident_id},
    }


def build_digest_gchat_card(
    digest_data: Dict[str, Any],
    grafana_base_url: str = "https://grafana.example.internal",
    datasource_uid: str = "loki",
) -> Dict[str, Any]:
    """Render Google Chat Cards v2 payload for aggregated periodic DIGEST alerts."""
    total_incidents = digest_data.get("total_incidents", 0)
    sources = digest_data.get("counts_by_source", {})
    targets = digest_data.get("counts_by_target", {})
    rules = digest_data.get("counts_by_rule", {})

    top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5]
    top_targets = sorted(targets.items(), key=lambda x: x[1], reverse=True)[:5]
    top_rules = sorted(rules.items(), key=lambda x: x[1], reverse=True)[:5]

    src_text = ", ".join(f"{html.escape(s)} ({c})" for s, c in top_sources) or "None"
    dst_text = ", ".join(f"{html.escape(t)} ({c})" for t, c in top_targets) or "None"
    rule_text = ", ".join(f"{html.escape(r)} ({c})" for r, c in top_rules) or "None"

    explore_url = f"{grafana_base_url.rstrip('/')}/explore?left=%5B%22now-1h%22,%22now%22,%22{datasource_uid}%22,%7B%22expr%22:%22%7Bservice_name%3D%5C%22forticlient%5C%22%7D%22%7D%5D"

    card_v2 = {
        "cardId": f"forti_digest_{int(digest_data.get('since', datetime.now(timezone.utc)).timestamp()) if hasattr(digest_data.get('since'), 'timestamp') else 0}",
        "card": {
            "header": {
                "title": "🛡️ FortiGate Security Activity Digest",
                "subtitle": f"Aggregated {total_incidents} events in interval • FortiGate DPI Monitor",
            },
            "sections": [
                {
                    "widgets": [
                        {
                            "decoratedText": {
                                "topLabel": "Active Scanner & Low-Severity Sources",
                                "text": src_text,
                            }
                        },
                        {
                            "decoratedText": {
                                "topLabel": "Target Destinations / VIPs",
                                "text": dst_text,
                            }
                        },
                        {
                            "decoratedText": {
                                "topLabel": "Triggered Security Rules",
                                "text": rule_text,
                            }
                        },
                        {
                            "buttonList": {
                                "buttons": [
                                    {
                                        "text": "View Activity in Grafana",
                                        "onClick": {"openLink": {"url": explore_url}}
                                    }
                                ]
                            }
                        }
                    ]
                }
            ],
        },
    }

    plain_text = (
        f"[DIGEST] FortiGate Security Activity Digest\n"
        f"Total Events: {total_incidents}\n"
        f"Top Sources: {src_text}\n"
        f"Top Targets: {dst_text}\n"
        f"Rules: {rule_text}\n"
        f"Explore: {explore_url}"
    )

    return {
        "text": plain_text,
        "cardsV2": [card_v2],
        "thread": {"threadKey": "FORTIGATE-PERIODIC-DIGEST"},
    }
