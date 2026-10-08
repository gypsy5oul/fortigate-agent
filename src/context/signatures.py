"""Locally reviewed signature metadata and grounded CVE reference resolution."""

import logging
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
import yaml

logger = logging.getLogger(__name__)

_DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "signatures.yaml"


class SignatureMetadataManager:
    """Loads and indexes local signature metadata for grounded CVE verification."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or _DEFAULT_SIGNATURES_PATH
        self.signatures: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            logger.warning("Signatures file not found at %s", self.path)
            return

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            self.signatures.clear()
            for item in data.get("signatures", []):
                sig = item.get("signature")
                if sig:
                    self.signatures[sig.strip()] = {
                        "signature": sig.strip(),
                        "cve_ids": [cve.strip().upper() for cve in item.get("cve_ids", []) if cve],
                        "product": item.get("product", "Unknown"),
                        "provenance": item.get("provenance", ""),
                        "reviewed_at": item.get("reviewed_at", ""),
                    }
            logger.info("Loaded %d reviewed signature definitions", len(self.signatures))
        except Exception as e:
            logger.error("Failed to load signatures metadata: %s", e)

    def get_metadata(self, sig: str) -> Dict[str, Any]:
        """Returns metadata for signature or a default unmapped record."""
        return self.signatures.get(sig.strip(), {
            "signature": sig,
            "cve_ids": [],
            "product": "Unknown",
            "provenance": "Unreviewed or dynamically detected signature",
            "reviewed_at": None,
        })

    def get_grounded_cves(self, signatures: List[str]) -> Set[str]:
        """Returns the set of strictly grounded CVE IDs associated with the supplied signatures."""
        valid_cves: Set[str] = set()
        for s in signatures:
            if not s:
                continue
            meta = self.signatures.get(s.strip())
            if meta:
                valid_cves.update(meta.get("cve_ids", []))
        return valid_cves


_GLOBAL_SIGNATURE_MANAGER: Optional[SignatureMetadataManager] = None


def get_signature_manager() -> SignatureMetadataManager:
    global _GLOBAL_SIGNATURE_MANAGER
    if _GLOBAL_SIGNATURE_MANAGER is None:
        _GLOBAL_SIGNATURE_MANAGER = SignatureMetadataManager()
    return _GLOBAL_SIGNATURE_MANAGER
