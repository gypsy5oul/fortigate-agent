"""Asset inventory and IP contextualization loader."""

import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import yaml

logger = logging.getLogger(__name__)

_DEFAULT_ASSETS_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "assets.yaml"


class AssetContextManager:
    """Manages VIP mappings, trusted networks, NAT/CDN ranges, and approved scanners."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or _DEFAULT_ASSETS_PATH
        self.vips: Dict[str, Dict[str, Any]] = {}
        self.trusted_networks: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self.nat_cdn_ranges: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self.approved_scanners: List[Dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        """Loads and parses config/assets.yaml into typed network objects."""
        if not self.config_path.exists():
            logger.warning("Assets config not found at %s", self.config_path)
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            # 1. VIPs
            self.vips.clear()
            for vip in data.get("vips", []):
                pub_ip = vip.get("public_ip")
                if pub_ip:
                    self.vips[pub_ip.strip()] = {
                        "application": vip.get("application") or vip.get("target_app", "Unknown Application"),
                        "environment": vip.get("environment", "production"),
                        "criticality": vip.get("criticality", "HIGH"),
                        "owner": vip.get("owner", "Security Operations"),
                        "provenance": f"config/assets.yaml §VIPs ({pub_ip})",
                    }

            # 2. Trusted Networks
            self.trusted_networks.clear()
            for net in data.get("trusted_networks", []):
                cidr = net.get("cidr")
                if cidr:
                    try:
                        self.trusted_networks.append((
                            ipaddress.ip_network(cidr.strip(), strict=False),
                            net.get("description", "Trusted network"),
                        ))
                    except ValueError as e:
                        logger.error("Invalid CIDR in trusted_networks: %s (%s)", cidr, e)

            # 3. NAT / CDN Ranges
            self.nat_cdn_ranges.clear()
            for net in data.get("nat_cdn_ranges", []):
                cidr = net.get("cidr")
                if cidr:
                    try:
                        self.nat_cdn_ranges.append((
                            ipaddress.ip_network(cidr.strip(), strict=False),
                            net.get("description", "NAT/CDN shared egress"),
                        ))
                    except ValueError as e:
                        logger.error("Invalid CIDR in nat_cdn_ranges: %s (%s)", cidr, e)

            # 4. Approved Scanners
            self.approved_scanners.clear()
            for sc in data.get("approved_scanners", []):
                cidr = sc.get("cidr")
                if cidr:
                    try:
                        net_obj = ipaddress.ip_network(cidr.strip(), strict=False)
                        self.approved_scanners.append({
                            "network": net_obj,
                            "cidr": cidr.strip(),
                            "owner": sc.get("owner", "Unknown"),
                            "reason": sc.get("reason", "Vulnerability assessment"),
                            "scope": sc.get("scope", "All"),
                            "expiry_str": sc.get("expiry"),
                            "description": sc.get("description", ""),
                        })
                    except ValueError as e:
                        logger.error("Invalid CIDR in approved_scanners: %s (%s)", cidr, e)

            logger.info(
                "Assets loaded successfully: %d VIPs, %d trusted subnets, %d NAT/CDN subnets, %d approved scanners",
                len(self.vips), len(self.trusted_networks), len(self.nat_cdn_ranges), len(self.approved_scanners),
            )
        except Exception as e:
            logger.error("Failed to parse assets configuration: %s", e)

    def get_target_asset(self, ip_str: Optional[str]) -> Optional[Dict[str, Any]]:
        """Lookup VIP application metadata for target IP."""
        if not ip_str:
            return None
        return self.vips.get(ip_str.strip())

    def get_source_context(
        self,
        ip_str: Optional[str],
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Classify source IP against trusted networks, shared NAT/CDN egress, and approved scanners."""
        if not ip_str:
            return {
                "is_trusted": False,
                "is_nat_cdn": False,
                "approved_scanner": None,
                "provenance": "No source IP",
            }

        now_utc = now or datetime.now(timezone.utc)
        if now_utc.tzinfo is None:
            now_utc = now_utc.replace(tzinfo=timezone.utc)

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return {
                "is_trusted": False,
                "is_nat_cdn": False,
                "approved_scanner": None,
                "provenance": f"Invalid IP: {ip_str}",
            }

        # Check trusted networks
        is_trusted = False
        trusted_desc = ""
        for net, desc in self.trusted_networks:
            if ip_obj in net:
                is_trusted = True
                trusted_desc = desc
                break

        # Check NAT / CDN
        is_nat_cdn = False
        nat_cdn_desc = ""
        for net, desc in self.nat_cdn_ranges:
            if ip_obj in net:
                is_nat_cdn = True
                nat_cdn_desc = desc
                break

        # Check approved scanners
        approved_scanner_info = None
        for sc in self.approved_scanners:
            if ip_obj in sc["network"]:
                expiry_dt = None
                exp_str = sc.get("expiry_str")
                if exp_str:
                    try:
                        expiry_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                    except Exception:
                        pass

                is_active = True
                if expiry_dt and now_utc > expiry_dt:
                    is_active = False

                approved_scanner_info = {
                    "cidr": sc["cidr"],
                    "owner": sc["owner"],
                    "reason": sc["reason"],
                    "scope": sc["scope"],
                    "expiry": exp_str,
                    "is_active": is_active,
                }
                break

        provenance_parts = []
        if is_trusted:
            provenance_parts.append(f"Trusted network ({trusted_desc})")
        if is_nat_cdn:
            provenance_parts.append(f"NAT/CDN range ({nat_cdn_desc})")
        if approved_scanner_info:
            status_str = "ACTIVE" if approved_scanner_info["is_active"] else "EXPIRED"
            provenance_parts.append(f"Approved scanner [{status_str}] ({approved_scanner_info['owner']})")

        return {
            "is_trusted": is_trusted,
            "is_nat_cdn": is_nat_cdn,
            "approved_scanner": approved_scanner_info,
            "provenance": "; ".join(provenance_parts) or "Public unicast endpoint",
        }


_GLOBAL_ASSET_MANAGER: Optional[AssetContextManager] = None


def get_asset_manager() -> AssetContextManager:
    global _GLOBAL_ASSET_MANAGER
    if _GLOBAL_ASSET_MANAGER is None:
        _GLOBAL_ASSET_MANAGER = AssetContextManager()
    return _GLOBAL_ASSET_MANAGER
