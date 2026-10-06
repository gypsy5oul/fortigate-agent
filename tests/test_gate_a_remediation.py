"""Comprehensive regression tests verifying Gate A and Gate B remediation findings (F02 - F14)."""

import pytest
import pytest_asyncio
from pydantic import ValidationError
from datetime import datetime, timezone

from src.storage.database import Database
from src.storage.repository import Repository
from src.parsing.normalizer import normalize_action, normalize_event, classify_direction
from src.correlator.session_aggregator import SessionAggregator, Episode
from src.rules.engine import RuleEngine
from src.investigation.schemas import IncidentPacket, QwenAssessment, FindingItem
from src.investigation.adk_workflow import ADKInvestigationWorkflow
from src.notifications.gchat_cards import build_gchat_card
from src.notifications.outbox_worker import OutboxWorker
from tests.fixtures.fortios_logs import (
    SAMPLE_TRAFFIC_DENY,
    SAMPLE_IPS_NONBLOCKED_EXPLOIT,
)


@pytest_asyncio.fixture
async def repo():
    db = Database("sqlite:///:memory:")
    await db.connect()
    repository = Repository(db)
    yield repository
    await db.close()


# --- F07: FortiOS Action Mappings & Directionality ---
def test_f07_action_normalization():
    # Session closes must NEVER be classified as BLOCKED
    assert normalize_action("close") == "SESSION_CLOSED"
    assert normalize_action("client-rst") == "SESSION_CLOSED"
    assert normalize_action("server-rst") == "SESSION_CLOSED"
    assert normalize_action("timeout") == "SESSION_CLOSED"
    assert normalize_action("clear_session") == "SESSION_CLOSED"

    # Actual security drops
    assert normalize_action("deny") == "BLOCKED"
    assert normalize_action("drop") == "BLOCKED"
    assert normalize_action("blocked") == "BLOCKED"
    assert normalize_action("reset") == "BLOCKED"

    # Allowed / detected
    assert normalize_action("detected") == "ALLOWED_OR_DETECTED"
    assert normalize_action("accept") == "ALLOWED_OR_DETECTED"


def test_f07_directionality_classification():
    # External attacker to internal server -> INBOUND
    assert classify_direction("198.51.100.45", "10.0.14.120") == "INBOUND"
    # Internal client to external internet -> OUTBOUND
    assert classify_direction("10.0.14.120", "142.251.222.174") == "OUTBOUND"
    # Internal to internal -> LATERAL
    assert classify_direction("10.0.1.5", "10.0.1.6") == "LATERAL"
    # Interface role override
    assert classify_direction("1.2.3.4", "5.6.7.8", srcintfrole="wan", dstintfrole="lan") == "INBOUND"
    assert classify_direction("1.2.3.4", "5.6.7.8", srcintfrole="lan", dstintfrole="wan") == "OUTBOUND"


# --- F03: Deduplication and Accurate Counts ---
@pytest.mark.asyncio
async def test_f03_accurate_insert_counts_and_deduplication(repo):
    ev = normalize_event(1791271940000000000, SAMPLE_TRAFFIC_DENY)
    
    # First insert: returns 1
    inserted1 = await repo.save_events([ev])
    assert inserted1 == 1

    # Second insert with identical event fingerprint: returns 0
    inserted2 = await repo.save_events([ev])
    assert inserted2 == 0

    # In-memory Episode deduplication
    ep = Episode("198.51.100.45", "10.0.14.120", 1791271940.0)
    added1 = ep.add_event(ev, 1791271940.0)
    assert added1 is True
    assert ep.event_count == 1

    # Replay of identical event ID must be rejected by Episode
    added2 = ep.add_event(ev, 1791271940.0)
    assert added2 is False
    assert ep.event_count == 1


# --- F02: Durable Inbox Processing Cursor ---
@pytest.mark.asyncio
async def test_f02_durable_inbox_draining(repo):
    # Insert 15 distinct events
    events = []
    base_ts = 1791271940000000000
    for i in range(15):
        raw = SAMPLE_TRAFFIC_DENY.replace("sessionid=1125626405", f"sessionid={1125626405 + i}")
        ev = normalize_event(base_ts + i * 1_000_000_000, raw)
        events.append(ev)

    saved = await repo.save_events(events)
    assert saved == 15

    # Fetch batch 1 of 10 items
    batch1 = await repo.fetch_pending_events(limit=10)
    assert len(batch1) == 10
    # Must be in chronological order
    assert batch1[0]["loki_ts_ns"] < batch1[-1]["loki_ts_ns"]

    # Mark batch 1 processed
    b1_ids = [e["id"] for e in batch1]
    await repo.mark_events_processed(b1_ids)

    # Fetch batch 2: should retrieve the remaining 5 items
    batch2 = await repo.fetch_pending_events(limit=10)
    assert len(batch2) == 5

    # Mark batch 2 processed
    b2_ids = [e["id"] for e in batch2]
    await repo.mark_events_processed(b2_ids)

    # Verify queue is drained
    batch3 = await repo.fetch_pending_events(limit=10)
    assert len(batch3) == 0


# --- F05 & F06: Monotonic Incident Escalation & Atomic Transactions ---
@pytest.mark.asyncio
async def test_f05_f06_incident_escalation_and_atomic_transition(repo):
    inc_id = "INC-ESCALATION-TEST"
    
    # 1. Initial State: Scanner MEDIUM (Revision 1)
    inc_v1 = {
        "id": inc_id,
        "current_revision": 1,
        "status": "ACTIVE",
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "event_count": 10,
        "summary": "10 blocked scanner probes",
    }
    rev_v1 = {
        "incident_id": inc_id,
        "revision": 1,
        "rule_ids": ["RULE_HIGH_FREQUENCY_SCANNER"],
        "severity": "MEDIUM",
        "enforcement": "BLOCKED",
        "assessment_json": {"summary": "Scanner probe"},
        "reasoning_summary": "Scanner probe",
        "evidence_ids": ["EVID-1"],
    }
    await repo.record_incident_transition(incident=inc_v1, revision=rev_v1)

    initial_inc = await repo.get_incident(inc_id)
    assert initial_inc["current_revision"] == 1
    assert initial_inc["severity"] == "MEDIUM"

    # 2. Material Escalation: Non-blocked exploit observed (Advances to Revision 2)
    inc_v2 = {
        "id": inc_id,
        "current_revision": 2,
        "status": "ACTIVE",
        "severity": "CRITICAL",
        "enforcement": "MIXED",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "first_seen": inc_v1["first_seen"],
        "last_seen": datetime.now(timezone.utc),
        "event_count": 12,
        "summary": "Active non-blocked exploit observed",
    }
    rev_v2 = {
        "incident_id": inc_id,
        "revision": 2,
        "rule_ids": ["RULE_NONBLOCKED_EXPLOIT_ATTEMPT"],
        "severity": "CRITICAL",
        "enforcement": "MIXED",
        "assessment_json": {"summary": "Exploit payload bypass"},
        "reasoning_summary": "Exploit payload bypass",
        "evidence_ids": ["EVID-2"],
    }
    notif_v2 = {
        "incident_id": inc_id,
        "revision": 2,
        "notification_type": "URGENT",
        "payload": {"text": "Critical escalation alert"},
    }
    job_v2 = {
        "id": f"JOB-{inc_id}-2",
        "job_type": "INVESTIGATE_INCIDENT",
        "payload": {"incident_id": inc_id, "revision": 2},
        "priority": 20,
    }

    # Atomically apply transition
    await repo.record_incident_transition(
        incident=inc_v2,
        revision=rev_v2,
        notification=notif_v2,
        job=job_v2,
    )

    # Verify escalated incident state
    updated_inc = await repo.get_incident(inc_id)
    assert updated_inc["current_revision"] == 2
    assert updated_inc["severity"] == "CRITICAL"
    assert updated_inc["enforcement"] == "MIXED"

    # Verify outbox has revision 2 alert
    pending_notifs = await repo.fetch_pending_notifications(limit=5)
    assert len(pending_notifs) == 1
    assert pending_notifs[0]["incident_id"] == inc_id
    assert pending_notifs[0]["revision"] == 2

    # Verify job queue has revision 2 investigation
    job = await repo.lease_next_job("worker-test")
    assert job is not None
    assert job["id"] == f"JOB-{inc_id}-2"


# --- F08: Pydantic Schema Guardrails (extra="forbid") ---
def test_f08_schema_strictness():
    # Extra fields must raise ValidationError
    with pytest.raises(ValidationError):
        FindingItem(
            kind="OBSERVATION",
            statement="Valid statement",
            evidence_ids=["EV-1"],
            hallucinated_extra_field="Should be rejected",
        )

    with pytest.raises(ValidationError):
        QwenAssessment(
            incident_id="INC-1",
            incident_revision=1,
            visibility_scope="FIREWALL_ONLY",
            severity="CRITICAL",
            attack_category="EXPLOITATION_ATTEMPT",
            exploitation_assessment="ATTEMPT_OBSERVED",
            enforcement="MIXED",
            summary="Valid summary",
            invented_field="Illegal injection",
        )


# --- F09: Conditional Validated CLI Mitigation Snippets ---
def test_f09_cli_snippet_rules():
    # Scenario A: Quarantine is NOT recommended -> snippet must NOT appear
    card_no_quarantine = build_gchat_card(
        incident={"id": "INC-1", "source_ip": "198.51.100.45", "target_ip": "10.0.14.120"},
        revision=1,
        assessment={"recommended_action_ids": ["ACT_INSPECT_APPLICATION_LOGS"]},
    )
    card_text = str(card_no_quarantine)
    assert "diagnose user banned-ip" not in card_text

    # Scenario B: IPv4 Quarantine IS recommended -> generates src4
    card_ipv4 = build_gchat_card(
        incident={"id": "INC-1", "source_ip": "198.51.100.45", "target_ip": "10.0.14.120"},
        revision=1,
        assessment={"recommended_action_ids": ["ACT_QUARANTINE_SRC_IP"]},
    )
    assert "diagnose user banned-ip add src4 198.51.100.45 3600" in str(card_ipv4)

    # Scenario C: IPv6 Quarantine IS recommended -> generates src6
    card_ipv6 = build_gchat_card(
        incident={"id": "INC-2", "source_ip": "2001:db8:85a3::8a2e:370:7334", "target_ip": "10.0.14.120"},
        revision=1,
        assessment={"recommended_action_ids": ["ACT_QUARANTINE_SRC_IP"]},
    )
    assert "diagnose user banned-ip add src6 2001:db8:85a3::8a2e:370:7334 3600" in str(card_ipv6)


# --- F10: Outbox Worker Status Differentiation ---
@pytest.mark.asyncio
async def test_f10_outbox_simulated_status(repo):
    worker = OutboxWorker(repository=repo, webhook_url=None, dry_run=True)
    await repo.enqueue_notification("INC-DRYRUN", 1, "URGENT", {"text": "Dry run alert"})

    dispatched = await worker.process_outbox_batch(limit=5)
    assert dispatched == 1

    # Must be marked SIMULATED in DB, NOT SENT
    row = await repo.db.fetch_one("SELECT status FROM notification_outbox WHERE incident_id = 'INC-DRYRUN'")
    assert row["status"] == "SIMULATED"
    await worker.close()
