"""Unit tests for deterministic action eligibility evaluation and perimeter safety constraints."""

from datetime import datetime, timezone
import pytest
from src.investigation.eligibility import is_action_eligible, get_eligible_actions


@pytest.fixture
def quarantine_action():
    return {
        "id": "ACT_QUARANTINE_SRC_IP",
        "name": "Quarantine Source IP",
        "category": "PERIMETER_ENFORCEMENT",
        "verified_build": "v7.4.4-b2658",
        "cli_template": "diagnose user banned-ip add src4 {source_ip} {expiry_seconds}",
    }


def test_build_gate_positive_and_negative(quarantine_action):
    """M6 Build Gate: perimeter actions eligible only when configured_build is set and equals verified_build."""
    episode = {
        "source_ip": "198.51.100.45",
        "direction": "INBOUND",
    }

    # Positive: configured_build matches verified_build
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.4.4-b2658")
    assert ok is True
    assert reason is None

    # Negative 1: configured_build is unset (None)
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build=None)
    assert ok is False
    assert "requires configured build" in reason

    # Negative 2: configured_build is mismatched
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.2.1-b1234")
    assert ok is False
    assert "requires configured build" in reason


def test_trusted_source_ineligible(quarantine_action):
    """Perimeter blocking is ineligible for trusted / internal RFC1918 sources."""
    episode = {
        "source_ip": "10.0.1.50",
        "direction": "INBOUND",
    }
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.4.4-b2658")
    assert ok is False
    assert "trusted network" in reason.lower()


def test_nat_cdn_source_ineligible(quarantine_action):
    """Perimeter blocking is ineligible for shared NAT or CDN egress IPs (e.g. Cloudflare)."""
    episode = {
        "source_ip": "104.16.50.1",
        "direction": "INBOUND",
    }
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.4.4-b2658")
    assert ok is False
    assert "shared nat/cdn" in reason.lower()


def test_active_scanner_ineligible(quarantine_action):
    """Perimeter blocking is ineligible for active approved vulnerability scanners."""
    episode = {
        "source_ip": "192.168.100.50",
        "direction": "INBOUND",
    }
    now = datetime(2026, 10, 6, tzinfo=timezone.utc)
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.4.4-b2658", now=now)
    assert ok is False
    assert "active approved scanner" in reason.lower() or "trusted network" in reason.lower()


def test_expired_scanner_eligible(quarantine_action):
    """Perimeter blocking is eligible when a scanner's authorization window has expired."""
    episode = {
        "source_ip": "198.51.100.77",
        "direction": "INBOUND",
    }
    now = datetime(2026, 10, 6, tzinfo=timezone.utc)  # Expired in 2025
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.4.4-b2658", now=now)
    assert ok is True
    assert reason is None


def test_outbound_direction_ineligible(quarantine_action):
    """Perimeter blocking is ineligible for OUTBOUND episodes."""
    episode = {
        "source_ip": "198.51.100.45",
        "direction": "OUTBOUND",
    }
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.4.4-b2658")
    assert ok is False
    assert "inbound" in reason.lower()


def test_ipv6_with_src4_template_ineligible(quarantine_action):
    """IPv6 sources are ineligible when the CLI template uses src4 commands."""
    episode = {
        "source_ip": "2001:db8:85a3::8a2e:370:7334",
        "direction": "INBOUND",
    }
    ok, reason = is_action_eligible(quarantine_action, episode, configured_build="v7.4.4-b2658")
    assert ok is False
    assert "ipv6" in reason.lower()


def test_non_perimeter_actions_always_eligible():
    """Non-perimeter actions like application log inspection are not blocked by perimeter constraints."""
    app_log_action = {
        "id": "ACT_INSPECT_APPLICATION_LOGS",
        "name": "Inspect Backend Application Logs",
        "category": "INVESTIGATION_STEP",
    }
    episode = {
        "source_ip": "10.0.1.50",  # Internal / trusted
        "direction": "OUTBOUND",
    }
    ok, reason = is_action_eligible(app_log_action, episode, configured_build=None)
    assert ok is True
    assert reason is None
