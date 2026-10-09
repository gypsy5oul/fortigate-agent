"""C2.3 comparison harness on PostgreSQL: scripts/shadow_report.py over seeded agent_runs,
agent_events and shadow_assessments rows gives exactly the expected numbers, honours the mode and
time window, renders them as Markdown, gates on the C2.5 criteria and writes nothing."""

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
import pytest

from src.storage.database import Database

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "shadow_report.py"
TEST_PG_URL = os.getenv("TEST_DATABASE_URL", "postgresql://forti_intel:forti_ci_test_password@localhost:5432/forti_test")

spec = importlib.util.spec_from_file_location("shadow_report", SCRIPT)
shadow_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shadow_report)

# Ten shadow runs in the window: (outcome, reason codes, latency ms, input tokens, output tokens, llm calls)
RUNS = [
    ("VALID", [], 1000, 100, 10, 8),
    ("VALID", ["ENFORCEMENT_PINNED_OVERRIDE"], 2000, 200, 20, 8),
    ("VALID", [], 3000, 300, 30, 8),
    ("VALID", [], 4000, 400, 40, 8),
    ("VALID", [], 5000, 500, 50, 8),
    ("VALID", [], 6000, 600, 60, 8),
    ("VALID", [], 7000, 700, 70, 8),
    ("REJECTED", ["AGENT_VALIDATION_REJECTED", "FORBIDDEN_CLAIM_UNGROUNDED"], 8000, 800, 80, 8),
    ("BUDGET_EXHAUSTED", ["AGENT_BUDGET_EXHAUSTED"], 9000, 900, 90, 8),
    ("TIMEOUT", ["AGENT_TIMEOUT"], 10000, 1000, 100, 6),
]
# (severity_equal, action_set_equal, exploitation_equal) for the first eight runs
AGREEMENT = [(True, True, True)] * 5 + [(True, False, True), (False, False, False), (True, True, True)]


async def _seed():
    db = Database(TEST_PG_URL)  # applies the migrations
    await db.connect()
    await db.close()
    conn = await asyncpg.connect(TEST_PG_URL)
    try:
        await conn.execute("TRUNCATE TABLE agent_runs, agent_events, shadow_assessments RESTART IDENTITY CASCADE")
        insert = (
            "INSERT INTO agent_runs (incident_id, revision, session_id, mode, adk_version, model_id, total_llm_calls, "
            "total_tool_calls, input_tokens, output_tokens, latency_ms, outcome, reason_codes, created_at) "
            "VALUES ($1, 2, $10, $2, '2.11.0', 'm', $3, 0, $4, $5, $6, $7, $8, $9) RETURNING id"
        )
        now = datetime.now(timezone.utc)
        ids = []
        for i, (outcome, codes, latency, tin, tout, calls) in enumerate(RUNS):
            ids.append(await conn.fetchval(insert, f"INC-SR-{i}", "shadow", calls, tin, tout, latency, outcome, codes, now, f"INC-SR-{i}:2"))
        # Outside the report: a live run, and a shadow run ten days old (excluded by --hours 24).
        await conn.fetchval(insert, "INC-SR-LIVE", "live", 8, 1, 1, 99000, "REJECTED", ["AGENT_VALIDATION_REJECTED"], now, "INC-SR-LIVE:2")
        old = await conn.fetchval(
            insert, "INC-SR-OLD", "shadow", 8, 1, 1, 99000, "REJECTED", ["AGENT_VALIDATION_REJECTED"], now - timedelta(days=10), "INC-SR-OLD:2"
        )

        events = []
        for run_id in ids:
            seq = 0
            for tool in ("evidence_agent", "get_incident_packet", "context_agent", "lookup_asset", "lookup_asset", "get_action_catalog"):
                seq += 1
                events.append((run_id, seq, "x", "tool", tool, False))
        # Refusals: lookup_asset once in run 0, get_action_catalog's 4th call in run 1, and the budget run's refused model call.
        events.append((ids[0], 50, "context_agent", "tool", "lookup_asset", True))
        events.append((ids[1], 50, "context_agent", "tool", "get_action_catalog", True))
        events.append((ids[8], 50, "context_agent", "llm", None, True))
        events.append((old, 1, "context_agent", "tool", "lookup_asset", True))
        await conn.executemany(
            "INSERT INTO agent_events (run_id, seq, agent_name, kind, tool_name, refused) VALUES ($1, $2, $3, $4, $5, $6)", events
        )
        for run_id, (sev, act, exp) in zip(ids, AGREEMENT):
            await conn.execute(
                "INSERT INTO shadow_assessments (incident_id, revision, run_id, assessment_json, assessment_source, "
                "severity_equal, action_set_equal, exploitation_equal, findings_count, legacy_findings_count) "
                "VALUES ('INC', 2, $1, '{}', 'MODEL_VALIDATED', $2, $3, $4, 1, 1)",
                run_id, sev, act, exp,
            )
        await conn.execute(
            "INSERT INTO shadow_assessments (incident_id, revision, run_id, assessment_json, assessment_source, "
            "severity_equal, action_set_equal, exploitation_equal, findings_count, legacy_findings_count, created_at) "
            "VALUES ('INC-OLD', 2, $1, '{}', 'MODEL_REJECTED_FALLBACK', false, false, false, 1, 1, $2)",
            old, now - timedelta(days=10),
        )
    finally:
        await conn.close()


async def _counts():
    conn = await asyncpg.connect(TEST_PG_URL)
    try:
        return [await conn.fetchval(f"SELECT COUNT(*) FROM {t}") for t in ("agent_runs", "agent_events", "shadow_assessments")]
    finally:
        await conn.close()


def _run(*args):
    env = dict(os.environ, DATABASE_URL=TEST_PG_URL)
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)


@pytest.fixture(scope="module")
def seeded():
    asyncio.run(_seed())
    return asyncio.run(_counts())


def test_shadow_report_numbers_on_postgresql(seeded):
    out = _run("--hours", "24", "--json")
    assert out.returncode == 0, out.stderr
    stats = json.loads(out.stdout)

    assert stats["runs"] == 10 and stats["window"]["mode"] == "shadow"
    assert stats["outcomes"] == {"VALID": 7, "REJECTED": 1, "BUDGET_EXHAUSTED": 1, "TIMEOUT": 1, "SCHEMA_INVALID": 0, "ERROR": 0}
    assert stats["hard_rejects"] == 1 and stats["hard_reject_rate"] == pytest.approx(0.1)
    assert stats["hard_reject_reason_codes"] == {"FORBIDDEN_CLAIM_UNGROUNDED": 1}
    assert stats["fallback_rate"] == pytest.approx(0.3) and stats["budget_exhausted_rate"] == pytest.approx(0.1)

    a = stats["agreement"]
    assert a["comparisons"] == 8
    assert (a["severity"], a["action_set"], a["exploitation"]) == pytest.approx((7 / 8, 6 / 8, 7 / 8))

    # PERCENTILE_CONT over 1..10 s: p50 5.5, p95 9.55.
    assert stats["latency_seconds"] == pytest.approx({"p50": 5.5, "p95": 9.55, "max": 10.0})
    assert stats["tokens_per_run"]["input_mean"] == pytest.approx(550.0)
    assert stats["tokens_per_run"]["output_mean"] == pytest.approx(55.0)
    assert stats["tokens_per_run"]["total_mean"] == pytest.approx(605.0)
    assert stats["tokens_per_run"]["total_p95"] == pytest.approx(1050.5)
    assert stats["llm_calls_per_run"] == pytest.approx({"mean": 7.8, "max": 8})

    assert stats["tool_calls"] == {
        "context_agent": {"calls": 10, "refused": 0},
        "evidence_agent": {"calls": 10, "refused": 0},
        "get_action_catalog": {"calls": 11, "refused": 1},
        "get_incident_packet": {"calls": 10, "refused": 0},
        "lookup_asset": {"calls": 21, "refused": 1},
    }
    assert stats["refusals"] == {
        "tool_calls_refused": 2, "by_tool": {"get_action_catalog": 1, "lookup_asset": 1},
        "lookup_asset": 1, "model_calls_refused": 1,
    }

    met = {(s, c["name"]): c["met"] for s in ("golden", "lab") for c in stats["criteria"][s]}
    assert met == {
        ("golden", "validator hard rejects"): False,
        ("golden", "severity agreement"): False,
        ("golden", "action-set agreement"): False,
        ("lab", "shadow runs"): False,
        ("lab", "hard-reject rate"): False,
        ("lab", "p95 latency (s)"): True,
        ("lab", "budget exhaustion"): False,
        ("lab", "lookup_asset refusals"): False,
    }


def test_shadow_report_window_mode_markdown_and_check(seeded):
    everything = json.loads(_run("--json", "--mode", "all").stdout)
    assert everything["runs"] == 12 and everything["agreement"]["comparisons"] == 9
    live = json.loads(_run("--json", "--mode", "live").stdout)
    assert live["runs"] == 1 and live["agreement"]["comparisons"] == 0 and live["agreement"]["severity"] is None

    md = _run("--since", (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
    assert md.returncode == 0, md.stderr
    text = md.stdout
    assert text.startswith("# Shadow comparison report\n")
    assert "| Agent runs | 10 |" in text and "| Shadow comparisons | 8 |" in text
    assert "| Severity | 7/8 | 87.5% |" in text and "| Action set | 6/8 | 75.0% |" in text
    assert "| REJECTED | 1 | 10.0% |" in text and "Validator hard-reject rate (`REJECTED`): 10.0%." in text
    assert "| Latency p95 (s) | 9.55 |" in text and "| `lookup_asset` | 21 | 1 |" in text
    assert "| lab | p95 latency (s) | < 90 | 9.55 | yes |" in text
    assert TEST_PG_URL not in text and "postgresql://" not in text

    assert _run("--hours", "24", "--check", "golden").returncode == 1
    assert _run("--hours", "24", "--check", "lab").returncode == 1
    assert _run("--json").returncode == 0  # no --check: always 0


def test_shadow_report_is_read_only_and_needs_a_database(seeded):
    assert asyncio.run(_counts()) == seeded
    out = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True,
                         env={k: v for k, v in os.environ.items() if k != "DATABASE_URL"}, timeout=60)
    assert out.returncode == 2 and "DATABASE_URL" in out.stderr


def test_percentile_matches_percentile_cont():
    assert shadow_report.percentile([], 0.5) is None
    assert shadow_report.percentile([4.0], 0.95) == 4.0
    assert shadow_report.percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.5
    assert shadow_report.percentile([1.0, 2.0, 3.0, 4.0], 0.95) == pytest.approx(3.85)
