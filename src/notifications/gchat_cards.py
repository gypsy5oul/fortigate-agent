"""Google Chat Cards v2 payload builder with plain-text fallback and incident threading."""

from typing import Dict, Any, List


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
    grafana_base_url: str = "https://grafana.6dcorp.internal",
    datasource_uid: str = "loki",
) -> Dict[str, Any]:
    """Render Google Chat Cards v2 payload."""
    incident_id = incident["id"]
    source_ip = incident["source_ip"]
    target_ip = incident["target_ip"]
    target_app = incident.get("target_app") or f"Target Host ({target_ip})"
    severity = assessment.get("severity") or incident.get("severity", "MEDIUM")
    enforcement = assessment.get("enforcement") or incident.get("enforcement", "UNKNOWN")
    summary = assessment.get("summary", "Security event detected on perimeter firewall.")
    actions = assessment.get("recommended_action_ids", [])
    signatures = assessment.get("cve_references") or incident.get("signatures", [])
    sig_str = ", ".join(signatures) if signatures else "Generic Anomaly"

    # Deep drilldown Grafana Explore URL
    explore_url = f"{grafana_base_url.rstrip('/')}/explore?left=%5B%22now-1h%22,%22now%22,%22{datasource_uid}%22,%7B%22expr%22:%22%7Bservice_name%3D%5C%22forticlient%5C%22%7D%20%7C%3D%20%5C%22{source_ip}%5C%22%22%7D%5D"

    # CLI mitigation snippet suggestion
    cli_snippet = f"diagnose user banned-ip add src4 {source_ip} 3600 \"SOC auto-quarantine {incident_id}\""

    widgets: List[Dict[str, Any]] = [
        {
            "decoratedText": {
                "topLabel": "Incident Target",
                "text": f"<b>{target_app}</b> ({target_ip})",
                "icon": {"knownIcon": "BOOKMARK"},
            }
        },
        {
            "decoratedText": {
                "topLabel": "Attacker Source IP",
                "text": f"<b>{source_ip}</b>",
                "icon": {"knownIcon": "PERSON"},
            }
        },
        {
            "decoratedText": {
                "topLabel": "Enforcement Status",
                "text": f"<b>{enforcement}</b> (Events: {incident.get('event_count', 1)})",
                "icon": {"knownIcon": "SHIELD"},
            }
        },
        {
            "decoratedText": {
                "topLabel": "Exploitation Assessment",
                "text": f"<i>{assessment.get('exploitation_assessment', 'INSUFFICIENT_EVIDENCE')}</i>",
                "icon": {"knownIcon": "DESCRIPTION"},
            }
        },
        {
            "textParagraph": {
                "text": f"<b>Analysis Summary:</b><br>{summary}"
            }
        },
        {
            "textParagraph": {
                "text": f"<b>Recommended Actions:</b> {', '.join(actions) if actions else 'None'}<br><code>{cli_snippet}</code>"
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
                "title": f"{get_severity_emoji(severity)}: {sig_str}",
                "subtitle": f"Incident {incident_id} • Revision {revision} • FortiGate 200G DPI",
                "imageUrl": "https://img.icons8.com/color/48/firewall.png",
                "imageType": "SQUARE",
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
        f"[{severity}] FortiGate Alert: {sig_str}\n"
        f"Target: {target_app} ({target_ip}) | Attacker: {source_ip}\n"
        f"Enforcement: {enforcement} | Incident: {incident_id} (Rev {revision})\n"
        f"Summary: {summary}\n"
        f"Grafana: {explore_url}"
    )

    return {
        "text": plain_text,
        "cardsV2": [card_v2],
        "thread": {"threadKey": incident_id},
    }
