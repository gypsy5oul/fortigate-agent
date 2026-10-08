"""Unit tests for local reviewed signature metadata and grounded CVE resolution (D7)."""

import pytest
from src.context.signatures import get_signature_manager, SignatureMetadataManager


@pytest.fixture
def sig_mgr():
    return get_signature_manager()


def test_grounded_cve_known_signature(sig_mgr):
    """Known reviewed signatures correctly resolve to their grounded CVE IDs."""
    sigs = ["Apache.Log4j.Error.Log.Remote.Code.Execution"]
    grounded = sig_mgr.get_grounded_cves(sigs)
    assert grounded == {"CVE-2021-44228"}

    hb_sigs = ["OpenSSL.Heartbleed.Information.Disclosure"]
    assert sig_mgr.get_grounded_cves(hb_sigs) == {"CVE-2014-0160"}


def test_grounded_cve_signature_without_cve(sig_mgr):
    """Signatures that have no associated CVE ID return an empty set."""
    sigs = ["SQL.Injection.UNION.SELECT", "Eicar-Test-Signature"]
    grounded = sig_mgr.get_grounded_cves(sigs)
    assert grounded == set()


def test_grounded_cve_unknown_signature(sig_mgr):
    """Unknown or unreviewed signatures do not produce hallucinated CVEs."""
    sigs = ["Completely.Unknown.Exploit.Payload", "Custom.Signature.123"]
    grounded = sig_mgr.get_grounded_cves(sigs)
    assert grounded == set()


def test_grounded_cve_mixed_set(sig_mgr):
    """Resolving a mixed batch of signatures returns only grounded CVEs from known entries."""
    sigs = [
        "Apache.Log4j.Error.Log.Remote.Code.Execution",
        "FortiOS.SSL.VPN.Authentication.Bypass",
        "SQL.Injection.UNION.SELECT",
        "Unknown.Probe.Signature",
    ]
    grounded = sig_mgr.get_grounded_cves(sigs)
    assert grounded == {"CVE-2021-44228", "CVE-2022-40684"}


def test_signature_metadata_lookup(sig_mgr):
    """get_metadata returns reviewed metadata for known signatures and safe defaults for unreviewed."""
    known_meta = sig_mgr.get_metadata("Apache.Log4j.Error.Log.Remote.Code.Execution")
    assert known_meta["product"] == "Apache Log4j"
    assert "CVE-2021-44228" in known_meta["cve_ids"]
    assert "fortiguard.com" in known_meta["provenance"]

    unknown_meta = sig_mgr.get_metadata("Unknown.Signature.Foo")
    assert unknown_meta["product"] == "Unknown"
    assert unknown_meta["cve_ids"] == []
    assert "Unreviewed" in unknown_meta["provenance"]
