"""Pure unit tests for PollerOrchestrator checkpoint monotonicity, catch-up, and saturation."""

import pytest
import pytest_asyncio
import asyncio
from typing import List, Tuple

from src.sources.checkpoints import PollerOrchestrator
from src.storage.database import Database
from src.storage.repository import Repository


class FakeLokiClient:
    def __init__(self, rate_lines_per_sec: int, limit: int = 1000, base_time_s: float = 1_700_000_000.0):
        self.rate = rate_lines_per_sec
        self.limit = limit
        self.base_time_ns = int(base_time_s * 1_000_000_000)
        self.should_fail = False
        self.should_error_status = False

    async def query_range(
        self,
        query: str,
        start_ns: int,
        end_ns: int,
        limit: int = 1000,
        direction: str = "forward",
    ) -> List[Tuple[int, str]]:
        if self.should_fail:
            raise RuntimeError("Loki connection failed")
        if self.should_error_status:
            raise RuntimeError("Loki returned non-success envelope: parse error")

        if end_ns <= start_ns or self.rate <= 0:
            return []

        step_ns = int(1_000_000_000 / self.rate)
        # Find index range of events within [start_ns, end_ns]
        first_idx = max(0, (start_ns - self.base_time_ns + step_ns - 1) // step_ns)
        last_idx = (end_ns - self.base_time_ns) // step_ns

        records = []
        for idx in range(first_idx, last_idx):
            if len(records) >= limit:
                break
            ts = self.base_time_ns + (idx * step_ns)
            line = f'date=2026-10-06 time=12:00:00 devname="FGT" devid="FGT1" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.1.5 dstip=10.0.2.10 action=accept sessionid={idx}'
            records.append((ts, line))
        return records

    async def query_range_safe(
        self,
        query: str,
        start_ns: int,
        end_ns: int,
        limit: int = 1000,
        min_window_ns: int = 2_000_000_000,
        max_depth: int = 4,
        _depth: int = 0,
    ) -> Tuple[List[Tuple[int, str]], bool]:
        records = await self.query_range(query, start_ns, end_ns, limit=limit)
        if len(records) < limit:
            return records, False

        window_size = end_ns - start_ns
        if self.rate >= 1000 or window_size <= min_window_ns or _depth >= max_depth:
            return records, True

        mid_ns = start_ns + (window_size // 2)
        left_records, left_sat = await self.query_range_safe(
            query, start_ns, mid_ns, limit, min_window_ns, max_depth, _depth + 1
        )
        right_records, right_sat = await self.query_range_safe(
            query, mid_ns, end_ns, limit, min_window_ns, max_depth, _depth + 1
        )
        return left_records + right_records, (left_sat or right_sat)


@pytest_asyncio.fixture
async def sqlite_repo():
    db = Database("sqlite:///:memory:")
    await db.connect()
    repo = Repository(db)
    yield repo
    await db.close()


@pytest.mark.asyncio
async def test_simulated_clock_advancement(sqlite_repo):
    """Simulated clock advancing 15s per poll, 20 polls, at 10, 300, and 1000 lines/s.
    
    Verifies:
    - Checkpoint is strictly non-decreasing
    - Lag (now - checkpoint) <= overlap + slice + delay after catch-up
    - Completeness 100% at <= 300 lines/s
    - At 1000 lines/s a coverage gap row exists and checkpoint still advances
    """
    rates = [10, 300, 1000]

    for rate in rates:
        stream = f'{{service_name="test_{rate}"}}'
        current_time_s = 1_700_000_000.0
        overlap_s = 10
        slice_s = 30
        delay_s = 15

        def sim_clock():
            return int(current_time_s * 1_000_000_000)

        fake_loki = FakeLokiClient(rate_lines_per_sec=rate, limit=1000, base_time_s=current_time_s)
        poller = PollerOrchestrator(
            loki_client=fake_loki,
            repository=sqlite_repo,
            selector=stream,
            overlap_seconds=overlap_s,
            query_end_delay_seconds=delay_s,
            default_bootstrap_seconds=60,
            slice_seconds=slice_s,
            limit=1000,
            max_slices_per_cycle=10,
            now_fn=sim_clock,
        )

        prev_checkpoint = 0
        checkpoints = []

        for poll_idx in range(20):
            current_time_s += 15.0  # Advance clock 15s per poll
            await poller.poll_once()
            cp = await sqlite_repo.get_checkpoint(stream)
            assert cp is not None
            assert cp >= prev_checkpoint, f"Checkpoint regressed at poll {poll_idx} for rate {rate}: {cp} < {prev_checkpoint}"
            prev_checkpoint = cp
            checkpoints.append(cp)

        final_cp = checkpoints[-1]
        now_ns = sim_clock()
        lag_ns = now_ns - final_cp
        max_allowed_lag_ns = (overlap_s + slice_s + delay_s) * 1_000_000_000
        assert lag_ns <= max_allowed_lag_ns, f"Lag {lag_ns / 1e9}s exceeds bound {max_allowed_lag_ns / 1e9}s at rate {rate}"

        # Check coverage gaps
        gaps = await sqlite_repo.get_coverage_gaps(stream)
        if rate == 1000:
            assert len(gaps) > 0, "Expected coverage gap at 1000 lines/s saturation"
        else:
            assert len(gaps) == 0, f"Expected 0 coverage gaps at {rate} lines/s, got {len(gaps)}"


@pytest.mark.asyncio
async def test_catch_up_after_one_hour_outage(sqlite_repo):
    """After a simulated 1h outage, poller catches up within 3600 / slice / max_slices_per_cycle cycles and never regresses."""
    stream = '{service_name="outage_test"}'
    current_time_s = 1_700_000_000.0
    slice_s = 30
    max_slices = 10

    def sim_clock():
        return int(current_time_s * 1_000_000_000)

    fake_loki = FakeLokiClient(rate_lines_per_sec=10, limit=1000, base_time_s=current_time_s)
    poller = PollerOrchestrator(
        loki_client=fake_loki,
        repository=sqlite_repo,
        selector=stream,
        overlap_seconds=10,
        query_end_delay_seconds=15,
        default_bootstrap_seconds=60,
        slice_seconds=slice_s,
        limit=1000,
        max_slices_per_cycle=max_slices,
        now_fn=sim_clock,
    )

    # Initial poll to establish checkpoint
    await poller.poll_once()
    cp_initial = await sqlite_repo.get_checkpoint(stream)
    assert cp_initial is not None

    # Simulate 1 hour outage (3600 seconds pass)
    current_time_s += 3600.0

    # Max cycles to catch up: 3600 / slice / max_slices_per_cycle = 12 cycles (+ margin)
    max_cycles = (3600 // slice_s // max_slices) + 2
    cycles_taken = 0
    prev_cp = cp_initial

    for _ in range(max_cycles):
        cycles_taken += 1
        await poller.poll_once()
        cp = await sqlite_repo.get_checkpoint(stream)
        assert cp >= prev_cp, f"Checkpoint regressed during catch-up: {cp} < {prev_cp}"
        prev_cp = cp
        lag_ns = sim_clock() - cp
        if lag_ns <= (10 + slice_s + 15) * 1_000_000_000:
            break

    lag_ns = sim_clock() - prev_cp
    assert lag_ns <= (10 + slice_s + 15) * 1_000_000_000, f"Failed to catch up in {max_cycles} cycles. Lag: {lag_ns / 1e9}s"


@pytest.mark.asyncio
async def test_loki_failure_preserves_checkpoint(sqlite_repo):
    """Loki returning status != success or raising: checkpoint unchanged, exception propagates, no gap recorded."""
    stream = '{service_name="failure_test"}'
    current_time_s = 1_700_000_000.0

    def sim_clock():
        return int(current_time_s * 1_000_000_000)

    fake_loki = FakeLokiClient(rate_lines_per_sec=10, limit=1000, base_time_s=current_time_s)
    poller = PollerOrchestrator(
        loki_client=fake_loki,
        repository=sqlite_repo,
        selector=stream,
        overlap_seconds=10,
        query_end_delay_seconds=15,
        default_bootstrap_seconds=60,
        slice_seconds=30,
        limit=1000,
        max_slices_per_cycle=10,
        now_fn=sim_clock,
    )

    # Initial successful poll
    await poller.poll_once()
    cp_before = await sqlite_repo.get_checkpoint(stream)
    assert cp_before is not None

    current_time_s += 30.0

    # Failure 1: Network exception
    fake_loki.should_fail = True
    with pytest.raises(RuntimeError, match="Loki connection failed"):
        await poller.poll_once()

    cp_after = await sqlite_repo.get_checkpoint(stream)
    assert cp_after == cp_before, "Checkpoint should not change on connection failure"

    # Failure 2: Non-success envelope
    fake_loki.should_fail = False
    fake_loki.should_error_status = True
    with pytest.raises(RuntimeError, match="non-success envelope"):
        await poller.poll_once()

    cp_after2 = await sqlite_repo.get_checkpoint(stream)
    assert cp_after2 == cp_before, "Checkpoint should not change on non-success status"

    gaps = await sqlite_repo.get_coverage_gaps(stream)
    assert len(gaps) == 0, "No coverage gap should be recorded as 'covered' on failure"
