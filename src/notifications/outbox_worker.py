"""Durable outbox dispatcher for Google Chat with priority ordering, backoff, and dead-letter safety."""

import re
import json
import random
import asyncio
import logging
from typing import Optional, Dict, Any
import httpx
from src.storage.repository import Repository
from src.observability.metrics import (
    OUTBOX_DELIVERED_TOTAL,
    OUTBOX_FAILURES_TOTAL,
    OUTBOX_DEAD_LETTER_TOTAL,
    CHAT_LAST_SUCCESS_AGE_SECONDS,
)

logger = logging.getLogger(__name__)

# Documented maximum payload limit for Google Chat webhook API (~30 KB)
MAX_PAYLOAD_BYTES = 30000


class OutboxWorker:
    def __init__(
        self,
        repository: Repository,
        webhook_url: Optional[str] = None,
        dry_run: bool = True,
        rate_limit_delay_seconds: float = 2.0,
        thread_by_incident: bool = True,
    ):
        self.repo = repository
        self.webhook_url = webhook_url
        self.dry_run = dry_run
        self.delay = rate_limit_delay_seconds
        self.thread_by_incident = thread_by_incident

        if not dry_run and not webhook_url:
            logger.warning("GCHAT_DRY_RUN is false but GCHAT_WEBHOOK_URL is not set. Outbox will mark items as SIMULATED.")
        self._client = httpx.AsyncClient(timeout=10.0)

    async def close(self):
        await self._client.aclose()

    def _get_target_webhook_url(self) -> Optional[str]:
        if not self.webhook_url:
            return None
        if not self.thread_by_incident:
            return self.webhook_url
        if "messageReplyOption=" in self.webhook_url:
            return self.webhook_url
        sep = "&" if "?" in self.webhook_url else "?"
        return f"{self.webhook_url}{sep}messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"

    async def process_outbox_batch(self, limit: int = 10) -> int:
        """Process pending outbox notifications with priority ordering (urgent first)."""
        pending = await self.repo.fetch_pending_notifications(limit)
        if not pending:
            return 0

        dispatched = 0
        target_url = self._get_target_webhook_url()

        for item in pending:
            outbox_id = item["id"]
            payload = item.get("payload", {})
            incident_id = item.get("incident_id")
            rev = item.get("revision")
            attempts = item.get("attempts", 0)

            # Payload size validation
            try:
                payload_str = json.dumps(payload)
                if len(payload_str.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                    err_msg = f"Payload size ({len(payload_str)} bytes) exceeds Google Chat limit of {MAX_PAYLOAD_BYTES} bytes"
                    logger.error("Quarantining outbox item %s: %s", outbox_id, err_msg)
                    OUTBOX_DEAD_LETTER_TOTAL.inc()
                    await self.repo.mark_notification_failed(outbox_id, err_msg, dead_letter=True)
                    continue
            except Exception as e:
                logger.error("Failed to serialize outbox payload %s: %s", outbox_id, e)
                OUTBOX_DEAD_LETTER_TOTAL.inc()
                await self.repo.mark_notification_failed(outbox_id, f"JSON serialization error: {e}", dead_letter=True)
                continue

            # Dry-run handling
            if self.dry_run or not target_url:
                logger.info(
                    "[DRY-RUN / SIMULATED GCHAT] Incident %s (Rev %s) Outbox ID %s:\n%s",
                    incident_id, rev, outbox_id, payload.get("text", "")
                )
                await self.repo.mark_notification_simulated(outbox_id)
                dispatched += 1
                await asyncio.sleep(0.05)
                continue

            # Live webhook delivery
            try:
                resp = await self._client.post(target_url, json=payload)
                resp.raise_for_status()
                await self.repo.mark_notification_sent(outbox_id)
                logger.info("Successfully delivered Google Chat alert for Incident %s (Rev %s)", incident_id, rev)
                OUTBOX_DELIVERED_TOTAL.inc()
                CHAT_LAST_SUCCESS_AGE_SECONDS.set(0)
                dispatched += 1
            except httpx.HTTPStatusError as e:
                status_code = e.response.status_code
                body_clean = re.sub(r'https?://\S+', '[URL_REDACTED]', e.response.text)[:200]
                err_msg = f"HTTP {status_code}: {body_clean}"
                OUTBOX_FAILURES_TOTAL.inc()

                # Permanent 4xx client errors (excluding 429 rate limits)
                if 400 <= status_code < 500 and status_code != 429:
                    logger.error("Permanent HTTP %s error delivering alert %s; moving to DEAD_LETTER: %s", status_code, outbox_id, err_msg)
                    OUTBOX_DEAD_LETTER_TOTAL.inc()
                    await self.repo.mark_notification_failed(outbox_id, err_msg, dead_letter=True)
                elif status_code == 429:
                    # Rate limit with Retry-After header
                    retry_header = e.response.headers.get("Retry-After")
                    try:
                        retry_delay = float(retry_header) if retry_header else 3.0
                    except ValueError:
                        retry_delay = 3.0
                    logger.warning("Google Chat rate limited (429); backoff for %s s on alert %s", retry_delay, outbox_id)
                    await self.repo.mark_notification_failed(outbox_id, err_msg, retry_after_seconds=retry_delay)
                else:
                    # 5xx server errors: exponential backoff with jitter
                    backoff = min(900.0, 30.0 * (2 ** attempts)) + random.uniform(0.5, 3.0)
                    logger.warning("Temporary HTTP %s on alert %s; retry in %.1f s", status_code, outbox_id, backoff)
                    await self.repo.mark_notification_failed(outbox_id, err_msg, retry_after_seconds=backoff)

            except Exception as e:
                OUTBOX_FAILURES_TOTAL.inc()
                err_clean = re.sub(r'https?://\S+', '[URL_REDACTED]', str(e))[:200]
                err_msg = f"Network error: {err_clean}"
                backoff = min(900.0, 30.0 * (2 ** attempts)) + random.uniform(0.5, 3.0)
                logger.error("Network failure delivering Google Chat message for Incident %s; retry in %.1f s: %s", incident_id, backoff, err_msg)
                await self.repo.mark_notification_failed(outbox_id, err_msg, retry_after_seconds=backoff)

            # Honor per-space rate limiter
            await asyncio.sleep(self.delay)

        return dispatched
