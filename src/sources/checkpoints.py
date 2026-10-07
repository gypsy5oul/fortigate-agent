"""Poller orchestration managing durable checkpoints, overlap lookback, and event ingestion."""

import time
import logging
from typing import List, Dict, Any, Tuple, Optional, Callable
from src.sources.loki_client import LokiClient
from src.storage.repository import Repository
from src.parsing.normalizer import normalize_event
from src.sources.query_profiles import QueryProfile, UTM_DETECTIONS_PROFILE

logger = logging.getLogger(__name__)


class PollerOrchestrator:
    def __init__(
        self,
        loki_client: LokiClient,
        repository: Repository,
        selector: str,
        query_profile: Optional[QueryProfile] = None,
        overlap_seconds: int = 120,
        query_end_delay_seconds: int = 15,
        default_bootstrap_seconds: int = 600,
        slice_seconds: int = 30,
        limit: int = 1000,
        max_slices_per_cycle: int = 10,
        now_fn: Optional[Callable[[], int]] = None,
    ):
        self.client = loki_client
        self.repo = repository
        self.selector = selector
        self.query_profile = query_profile
        self.overlap_ns = overlap_seconds * 1_000_000_000
        self.end_delay_ns = query_end_delay_seconds * 1_000_000_000
        self.bootstrap_ns = default_bootstrap_seconds * 1_000_000_000
        self.slice_ns = slice_seconds * 1_000_000_000
        self.limit = limit
        self.max_slices_per_cycle = max_slices_per_cycle
        self.now_fn = now_fn or time.time_ns
        self.stream_name = query_profile.stream_key(selector) if query_profile else selector

    async def poll_once(self) -> Tuple[int, int]:
        """Execute one polling cycle with bounded catch-up slices.
        
        Returns:
            (raw_entries_count, saved_normalized_events_count)
        """
        total_raw = 0
        total_saved = 0

        for slice_idx in range(self.max_slices_per_cycle):
            now_ns = self.now_fn()
            end_bound_ns = now_ns - self.end_delay_ns

            last_checkpoint = await self.repo.get_checkpoint(self.stream_name)
            if last_checkpoint is None:
                # First run: bootstrap looking back default_bootstrap_seconds
                start_ns = end_bound_ns - self.bootstrap_ns
                target_end_ns = min(end_bound_ns, start_ns + self.slice_ns)
                checkpoint_basis = start_ns
                logger.info(
                    "No existing checkpoint for %s. Bootstrapping from %s ns ago",
                    self.stream_name, self.bootstrap_ns // 1_000_000_000
                )
            else:
                # Overlap lookback for late arrival recovery, target advances forward from checkpoint
                start_ns = last_checkpoint - self.overlap_ns
                target_end_ns = min(end_bound_ns, last_checkpoint + self.slice_ns)
                checkpoint_basis = last_checkpoint

            if target_end_ns <= checkpoint_basis:
                logger.debug("Query target_end_ns (%s) <= checkpoint_basis (%s), caught up.", target_end_ns, checkpoint_basis)
                break

            logger.debug(
                "Polling Loki %s (slice %d): [%s, %s] (window: %s s)",
                self.stream_name, slice_idx, start_ns, target_end_ns,
                (target_end_ns - start_ns) / 1_000_000_000,
            )

            # Query Loki (raises exception if Loki failed or returned non-success envelope)
            query_str = self.query_profile.render(self.selector) if self.query_profile else self.selector
            raw_records, had_saturation = await self.client.query_range_safe(
                query_str,
                start_ns,
                target_end_ns,
                limit=self.limit,
            )

            # Normalize and filter
            normalized_events: List[Dict[str, Any]] = []
            for ts_ns, raw_line in raw_records:
                ev = normalize_event(ts_ns, raw_line)
                if ev:
                    normalized_events.append(ev)

            # Persist events idempotently (propagates errors on failure)
            saved_count = await self.repo.save_events(normalized_events)
            total_raw += len(raw_records)
            total_saved += saved_count

            # Advance durable checkpoint monotonically
            if had_saturation:
                highest_ts = max((ts_ns for ts_ns, _ in raw_records), default=0)
                adv_ts = max(checkpoint_basis, highest_ts)
                if adv_ts > checkpoint_basis:
                    await self.repo.record_coverage_gap(
                        self.stream_name,
                        start_ns,
                        target_end_ns,
                        "Unresolvable query saturation exceeding limit",
                    )
                    await self.repo.save_checkpoint(self.stream_name, adv_ts)
                    checkpoint_basis = adv_ts
                    logger.warning(
                        "Query saturation detected: checkpoint advanced only to %s (not interval end %s)",
                        adv_ts, target_end_ns,
                    )
                else:
                    # Saturated with no forward ts or no records: advance to target_end_ns to prevent livelock
                    await self.repo.record_coverage_gap(
                        self.stream_name,
                        checkpoint_basis,
                        target_end_ns,
                        "Unresolvable query saturation with no progress, advancing past window",
                    )
                    await self.repo.save_checkpoint(self.stream_name, target_end_ns)
                    checkpoint_basis = target_end_ns
                    logger.warning(
                        "Query saturation with no forward ts: forced checkpoint advancement to %s to prevent livelock",
                        target_end_ns,
                    )
            else:
                await self.repo.save_checkpoint(self.stream_name, target_end_ns)
                checkpoint_basis = target_end_ns

            # If this slice reached end_bound_ns, we have caught up to real-time
            if target_end_ns >= end_bound_ns:
                break

        logger.info(
            "Poll cycle completed: %s raw lines, %s normalized events newly inserted",
            total_raw, total_saved,
        )
        return total_raw, total_saved
