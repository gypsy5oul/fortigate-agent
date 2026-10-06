"""Poller orchestration managing durable checkpoints, overlap lookback, and event ingestion."""

import time
import logging
from typing import List, Dict, Any, Tuple
from src.sources.loki_client import LokiClient
from src.storage.repository import Repository
from src.parsing.normalizer import normalize_event

logger = logging.getLogger(__name__)


class PollerOrchestrator:
    def __init__(
        self,
        loki_client: LokiClient,
        repository: Repository,
        selector: str,
        overlap_seconds: int = 120,
        query_end_delay_seconds: int = 15,
        default_bootstrap_seconds: int = 600,
        slice_seconds: int = 30,
        limit: int = 1000,
    ):
        self.client = loki_client
        self.repo = repository
        self.selector = selector
        self.overlap_ns = overlap_seconds * 1_000_000_000
        self.end_delay_ns = query_end_delay_seconds * 1_000_000_000
        self.bootstrap_ns = default_bootstrap_seconds * 1_000_000_000
        self.slice_ns = slice_seconds * 1_000_000_000
        self.limit = limit
        self.stream_name = selector

    async def poll_once(self) -> Tuple[int, int]:
        """Execute one polling cycle.
        
        Returns:
            (raw_entries_count, saved_normalized_events_count)
        """
        now_ns = time.time_ns()
        end_ns = now_ns - self.end_delay_ns

        last_checkpoint = await self.repo.get_checkpoint(self.stream_name)
        if last_checkpoint is None:
            # First run: bootstrap looking back default_bootstrap_seconds
            start_ns = end_ns - self.bootstrap_ns
            logger.info("No existing checkpoint for %s. Bootstrapping from %s ns ago",
                        self.stream_name, self.bootstrap_ns // 1_000_000_000)
        else:
            # Overlap lookback for late arrival recovery
            start_ns = last_checkpoint - self.overlap_ns

        # Apply budgeted time slice
        target_end_ns = min(end_ns, start_ns + self.slice_ns)

        if start_ns >= target_end_ns:
            logger.debug("Query start >= target_end, skipping cycle.")
            return 0, 0

        logger.debug("Polling Loki %s: [%s, %s]", self.stream_name, start_ns, target_end_ns)
        raw_records, had_saturation = await self.client.query_range_safe(
            self.selector,
            start_ns,
            target_end_ns,
            limit=self.limit,
        )

        if had_saturation:
            await self.repo.record_coverage_gap(
                self.stream_name,
                start_ns,
                target_end_ns,
                "Unresolvable query saturation exceeding limit",
            )

        # Normalize and filter
        normalized_events: List[Dict[str, Any]] = []
        for ts_ns, raw_line in raw_records:
            ev = normalize_event(ts_ns, raw_line)
            if ev:
                normalized_events.append(ev)

        # Persist events idempotently (propagates errors on failure)
        saved_count = await self.repo.save_events(normalized_events)

        # Advance durable checkpoint
        if not had_saturation:
            await self.repo.save_checkpoint(self.stream_name, target_end_ns)
        elif raw_records:
            highest_ts = max(ts_ns for ts_ns, _ in raw_records)
            await self.repo.save_checkpoint(self.stream_name, highest_ts)
            logger.warning(
                "Query saturation detected: checkpoint advanced only to %s (not interval end %s)",
                highest_ts, target_end_ns,
            )
        else:
            logger.warning("Query saturation detected with no records: checkpoint retained at %s", last_checkpoint)

        logger.info(
            "Poll cycle completed: %s raw lines, %s normalized events newly inserted",
            len(raw_records), saved_count,
        )
        return len(raw_records), saved_count
