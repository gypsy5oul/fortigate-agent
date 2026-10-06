"""Deterministic replay and load-testing CLI harness for firewall intelligence service."""

import asyncio
import time
import argparse
import logging
from src.storage.database import Database
from src.storage.repository import Repository
from src.parsing.normalizer import normalize_event
from src.correlator.session_aggregator import SessionAggregator
from src.rules.engine import RuleEngine
from tests.fixtures.fortios_logs import (
    SAMPLE_IPS_NONBLOCKED_EXPLOIT,
    SAMPLE_TRAFFIC_DENY,
    SAMPLE_WAF_SQLI_PASSTHROUGH,
    SAMPLE_WEBFILTER_BLOCKED,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("replay")


async def run_replay(event_count: int, burst_size: int, delay_between_bursts: float):
    logger.info("Starting deterministic log replay: count=%s, burst=%s", event_count, burst_size)
    db = Database("sqlite:///:memory:")
    await db.connect()
    repo = Repository(db)
    aggregator = SessionAggregator(idle_timeout_seconds=60)
    rule_engine = RuleEngine()

    test_samples = [
        SAMPLE_IPS_NONBLOCKED_EXPLOIT,
        SAMPLE_TRAFFIC_DENY,
        SAMPLE_WAF_SQLI_PASSTHROUGH,
        SAMPLE_WEBFILTER_BLOCKED,
    ]

    total_ingested = 0
    total_incidents = 0
    t0 = time.time()

    for i in range(0, event_count, burst_size):
        burst_events = []
        batch_limit = min(burst_size, event_count - i)
        for j in range(batch_limit):
            sample = test_samples[(i + j) % len(test_samples)]
            now_ns = int((time.time() + (i + j) * 0.01) * 1e9)
            ev = normalize_event(now_ns, sample)
            if ev:
                burst_events.append(ev)

        # Ingest into DB
        saved = await repo.save_events(burst_events)
        total_ingested += saved

        # Correlate into episodes
        episodes = aggregator.process_events(burst_events)

        # Rule evaluation
        for ep in episodes:
            eval_res = rule_engine.evaluate_episode(ep)
            if eval_res["matched_rule_ids"]:
                total_incidents += 1
                logger.info(
                    "Replay Triggered: Incident %s -> %s (Floor: %s)",
                    ep["incident_id"], eval_res["matched_rule_ids"], eval_res["severity_floor"]
                )

        if delay_between_bursts > 0:
            await asyncio.sleep(delay_between_bursts)

    elapsed = time.time() - t0
    eps = total_ingested / max(elapsed, 0.001)
    logger.info("=== REPLAY BENCHMARK COMPLETE ===")
    logger.info("Total Events Processed: %s in %.2fs (%.2f events/sec)", total_ingested, elapsed, eps)
    logger.info("Total Incidents Flagged: %s", total_incidents)

    await db.close()


def main():
    parser = argparse.ArgumentParser(description="Deterministic Firewall Replay Harness")
    parser.add_argument("--count", type=int, default=100, help="Total events to replay")
    parser.add_argument("--burst", type=int, default=20, help="Burst batch size")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between bursts (seconds)")
    args = parser.parse_args()

    asyncio.run(run_replay(args.count, args.burst, args.delay))


if __name__ == "__main__":
    main()
