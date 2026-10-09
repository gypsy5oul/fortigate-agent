"""Acceptance tests for D2: Campaign linking isolation per target IP."""

import pytest
from src.correlator.session_aggregator import SessionAggregator


def test_two_targets_two_incidents():
    """Source A hitting targets X and Y produces distinct incident IDs."""
    aggregator = SessionAggregator(
        idle_timeout_seconds=120,
        campaign_window_seconds=1800,
    )

    t0 = 1700000000.0

    ev1 = {
        "id": "EV-1",
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.120",
        "vd": "root",
        "direction": "INBOUND",
        "log_type": "traffic",
        "action_normalized": "BLOCKED",
        "eventtime_ns": int(t0 * 1e9),
    }

    # 10 seconds later, same source hits different target Y
    ev2 = {
        "id": "EV-2",
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.200",
        "vd": "root",
        "direction": "INBOUND",
        "log_type": "traffic",
        "action_normalized": "BLOCKED",
        "eventtime_ns": int((t0 + 10) * 1e9),
    }

    eps1 = aggregator.process_events([ev1])
    eps2 = aggregator.process_events([ev2])

    assert len(eps1) == 1
    assert len(eps2) == 1

    inc1 = eps1[0]["incident_id"]
    inc2 = eps2[0]["incident_id"]

    assert inc1 != inc2, f"Target X ({inc1}) and Target Y ({inc2}) must have distinct incident_ids"


def test_same_target_rejoins_within_campaign_window():
    """Source A hitting target X again after an idle timeout rejoins the same incident."""
    aggregator = SessionAggregator(
        idle_timeout_seconds=120,
        campaign_window_seconds=1800,
    )

    t0 = 1700000000.0

    ev1 = {
        "id": "EV-1",
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.120",
        "vd": "root",
        "direction": "INBOUND",
        "log_type": "traffic",
        "action_normalized": "BLOCKED",
        "eventtime_ns": int(t0 * 1e9),
    }

    eps1 = aggregator.process_events([ev1])
    inc_id_first = eps1[0]["incident_id"]
    ep_id_first = eps1[0]["episode_id"]

    # 200 seconds later (idle timeout is 120s, but within 1800s campaign window)
    t1 = t0 + 200.0
    ev2 = {
        "id": "EV-2",
        "srcip": "198.51.100.45",
        "dstip": "10.0.14.120",
        "vd": "root",
        "direction": "INBOUND",
        "log_type": "traffic",
        "action_normalized": "BLOCKED",
        "eventtime_ns": int(t1 * 1e9),
    }

    eps2 = aggregator.process_events([ev2])
    inc_id_second = eps2[0]["incident_id"]
    ep_id_second = eps2[0]["episode_id"]

    assert inc_id_second == inc_id_first, "Rejoining target within campaign window must preserve incident_id"
    assert ep_id_second != ep_id_first, "New episode must be spawned after idle timeout"
