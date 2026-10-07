"""Deterministic action eligibility evaluator enforcing perimeter safety constraints."""

import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import yaml

from src.context.assets import get_asset_manager

logger = logging.getLogger(__name__)

_DEFAULT_CATALOG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "action_catalog.yaml"


def load_action_catalog(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Loads all action definitions from action_catalog.yaml."""
    cat_path = path or _DEFAULT_CATALOG_PATH
    if not cat_path.exists():
        return []
    try:
        with open(cat_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("actions", [])
    except Exception as e:
        logger.error("Error loading action catalog: %s", e)
        return []


def is_action_eligible(
    action: Dict[str, Any],
    episode: Dict[str, Any],
    configured_build: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Tuple[bool, Optional[str]]:
    """Evaluates whether an action is safe and eligible for the given security episode.
    
    Returns:
        (is_eligible, reason_if_ineligible)
    """
    act_id = action.get("id", "")
    src_ip = episode.get("source_ip", "")
    direction = (episode.get("direction") or "UNKNOWN").upper()
    asset_mgr = get_asset_manager()
    src_ctx = asset_mgr.get_source_context(src_ip, now=now)

    # Perimeter blocking actions
    if act_id in ("ACT_QUARANTINE_SRC_IP", "ACT_ADD_FIREWALL_BLOCKLIST"):
        # 1. Directionality constraint
        if direction != "INBOUND":
            return False, f"Direction is {direction}; perimeter block only eligible for INBOUND"

        # 2. Trusted network exclusion
        if src_ctx.get("is_trusted"):
            return False, f"Source IP {src_ip} belongs to trusted network"

        # 3. Shared NAT / CDN egress exclusion
        if src_ctx.get("is_nat_cdn"):
            return False, f"Source IP {src_ip} is shared NAT/CDN infrastructure"

        # 4. Approved active scanner exclusion
        app_scanner = src_ctx.get("approved_scanner")
        if app_scanner and app_scanner.get("is_active"):
            return False, f"Source IP {src_ip} is an active approved scanner ({app_scanner.get('owner')})"

        # 5. Address family & verified build template constraint
        is_ipv6 = False
        try:
            is_ipv6 = ipaddress.ip_address(src_ip).version == 6
        except ValueError:
            return False, f"Invalid IP address format: {src_ip}"

        verified_build = action.get("verified_build")
        if not configured_build or verified_build is None or verified_build != configured_build:
            return False, f"Action template requires configured build '{verified_build}', but got '{configured_build}'"

        if is_ipv6 and "src4" in action.get("cli_template", ""):
            return False, f"CLI template does not support IPv6 address {src_ip}"

    return True, None


def get_eligible_actions(
    episode: Dict[str, Any],
    configured_build: Optional[str] = None,
    catalog: Optional[List[Dict[str, Any]]] = None,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Returns the subset of catalog actions that are deterministically eligible for this episode."""
    all_actions = catalog if catalog is not None else load_action_catalog()
    eligible: List[Dict[str, Any]] = []

    for act in all_actions:
        ok, reason = is_action_eligible(act, episode, configured_build=configured_build, now=now)
        if ok:
            eligible.append(act)
        else:
            logger.debug("Action %s ineligible for episode: %s", act.get("id"), reason)

    return eligible
