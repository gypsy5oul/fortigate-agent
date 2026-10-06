"""Unit tests for attack episode correlation and sliding window aggregator."""

import pytest
from src.correlator.session_aggregator import SessionAggregator
from src.parsing.normalizer import normalize_event
from tests.fixtures.fortios_logs import (
    SAMPLE_IPS_NONBLOCKED_EXPLOIT,
    SAMPLE_TRAFFIC_DENY,
)


def test_session_aggregator_mixed_enforcement():
    aggregator = SessionAggregator(idle_timeout_seconds=60)

    # Event 1: blocked deny
    ev_blocked = normalize_event(1791271940000000000, SAMPLE_TRAFFIC_DENY)
    # Align src and dst to same target
    ev_blocked["srcip"] = "198.51.100.45"
    ev_blocked["dstip"] = "10.0.14.120"

    # Event 2: allowed exploit detection
    ev_allowed = normalize_event(1791271941000000000, SAMPLE_IPS_NONBLOCKED_EXPLOIT)

    episodes = aggregator.process_events([ev_blocked, ev_allowed])
    assert len(episodes) == 1
    ep = episodes[0]
    assert ep["source_ip"] == "198.51.100.45"
    assert ep["target_ip"] == "10.0.14.120"
    assert ep["event_count"] == 2
    assert ep["enforcement"] == "MIXED"
    assert len(ep["signatures"]) == 1


def test_session_aggregator_idle_window_reset():
    aggregator = SessionAggregator(idle_timeout_seconds=5)

    ev1 = normalize_event(1791271900000000000, SAMPLE_TRAFFIC_DENY)
    ev1["eventtime_ns"] = 1791271900000000000

    # ev2 arrives 20 seconds later
    ev2 = normalize_event(1791271920000000000, SAMPLE_TRAFFIC_DENY)
    ev2["eventtime_ns"] = 1791271920000000000

    aggregator.process_events([ev1])
    episodes_after = aggregator.process_events([ev2])

    assert len(episodes_after) == 1
    # Because idle timeout exceeded, episode was reset
    assert episodes_after[0]["event_count"] == 1
