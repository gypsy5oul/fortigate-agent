"""Durable outbox dispatcher for Google Chat with rate-limiting and dry-run safety."""

import re
import asyncio
import logging
from typing import Optional
import httpx
from src.storage.repository import Repository
from src.observability.metrics import OUTBOX_DELIVERED_TOTAL, OUTBOX_FAILURES_TOTAL

logger = logging.getLogger(__name__)


class OutboxWorker:
    def __init__(
        self,
        repository: Repository,
        webhook_url: Optional[str] = None,
        dry_run: bool = True,
        rate_limit_delay_seconds: float = 2.0,
    ):
        self.repo = repository
        self.webhook_url = webhook_url
        self.dry_run = dry_run
        self.delay = rate_limit_delay_seconds
        if not dry_run and not webhook_url:
            logger.warning("GCHAT_DRY_RUN is false but GCHAT_WEBHOOK_URL is not set. Outbox will mark items as SIMULATED.")
        self._client = httpx.AsyncClient(timeout=10.0)

    async def close(self):
        await self._client.aclose()

    async def process_outbox_batch(self, limit: int = 10) -> int:
        """Process pending outbox notifications."""
        pending = await self.repo.fetch_pending_notifications(limit)
        if not pending:
            return 0

        dispatched = 0
        for item in pending:
            outbox_id = item["id"]
            payload = item.get("payload", {})
            incident_id = item.get("incident_id")
            rev = item.get("revision")

            if self.dry_run or not self.webhook_url:
                logger.info(
                    "[DRY-RUN / SIMULATED GCHAT] Incident %s (Rev %s) Outbox ID %s:\n%s",
                    incident_id, rev, outbox_id, payload.get("text", "")
                )
                await self.repo.mark_notification_simulated(outbox_id)
                dispatched += 1
                await asyncio.sleep(0.05)
                continue

            try:
                resp = await self._client.post(self.webhook_url, json=payload)
                resp.raise_for_status()
                await self.repo.mark_notification_sent(outbox_id)
                logger.info("Successfully delivered Google Chat alert for Incident %s (Rev %s)", incident_id, rev)
                OUTBOX_DELIVERED_TOTAL.inc()
                dispatched += 1
            except httpx.HTTPStatusError as e:
                body_clean = re.sub(r'https?://\S+', '[URL_REDACTED]', e.response.text)[:200]
                err_msg = f"HTTP {e.response.status_code}: {body_clean}"
                logger.error("Failed to send Google Chat message for Incident %s: %s", incident_id, err_msg)
                await self.repo.mark_notification_failed(outbox_id, err_msg)
                OUTBOX_FAILURES_TOTAL.inc()
            except Exception as e:
                err_clean = re.sub(r'https?://\S+', '[URL_REDACTED]', str(e))[:200]
                err_msg = f"Network error: {err_clean}"
                logger.error("Network error sending Google Chat message for Incident %s: %s", incident_id, err_msg)
                await self.repo.mark_notification_failed(outbox_id, err_msg)
                OUTBOX_FAILURES_TOTAL.inc()

            # Honor per-space rate limiter
            await asyncio.sleep(self.delay)

        return dispatched
