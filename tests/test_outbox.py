"""Unit tests for Google Chat Cards v2 and outbox worker."""

import pytest
import pytest_asyncio
from src.notifications.gchat_cards import build_gchat_card
from src.notifications.outbox_worker import OutboxWorker
from src.storage.database import Database
from src.storage.repository import Repository


def test_build_gchat_card():
    incident = {
        "id": "INC-TEST-999",
        "source_ip": "198.51.100.45",
        "target_ip": "10.0.14.120",
        "target_app": "Corporate Portal",
        "event_count": 5,
        "signatures": ["CVE-2021-44228"],
    }
    assessment = {
        "severity": "CRITICAL",
        "enforcement": "ALLOWED_OR_DETECTED",
        "summary": "Log4Shell payload observed reaching application backend.",
        "recommended_action_ids": ["ACT_QUARANTINE_SRC_IP", "ACT_INSPECT_APPLICATION_LOGS"],
        "cve_references": ["CVE-2021-44228"],
        "exploitation_assessment": "ATTEMPT_OBSERVED",
    }

    card_data = build_gchat_card(incident, revision=1, assessment=assessment)

    assert "text" in card_data
    assert "cardsV2" in card_data
    assert card_data["thread"]["threadKey"] == "INC-TEST-999"

    card = card_data["cardsV2"][0]["card"]
    assert "CRITICAL" in card["header"]["title"]
    assert "198.51.100.45" in card_data["text"]
    assert "explore" in card_data["text"]


@pytest_asyncio.fixture
async def repo():
    db = Database("sqlite:///:memory:")
    await db.connect()
    repository = Repository(db)
    yield repository
    await db.close()


@pytest.mark.asyncio
async def test_outbox_dry_run_dispatch(repo):
    worker = OutboxWorker(repository=repo, webhook_url=None, dry_run=True)

    # Enqueue a message
    await repo.enqueue_notification("INC-TEST-999", 1, "URGENT", {"text": "Dry run test alert"})

    dispatched = await worker.process_outbox_batch(limit=5)
    assert dispatched == 1

    # Outbox item must now be marked SENT
    pending = await repo.fetch_pending_notifications(limit=5)
    assert len(pending) == 0

    await worker.close()
