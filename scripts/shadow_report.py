#!/usr/bin/env python3
"""Shadow comparison harness (plan C2.3): how the ADK investigator compares with the legacy call.

Reads ``agent_runs``, ``agent_events`` and ``shadow_assessments`` (migration 006) in one read-only
PostgreSQL transaction and prints, for the runs in the window: agreement rates with the legacy
assessment (severity, action set, exploitation assessment), the run outcomes with the validator
hard-reject rate, p50/p95 latency, tokens and model calls per run, the tool call distribution and
the refusal counts, and the plan C2.5 promotion criteria with what was measured.

    DATABASE_URL=postgresql://... python scripts/shadow_report.py [--since 2026-10-10T00:00:00Z | --hours 72]
        [--mode shadow|live|all] [--json] [--check golden|lab]

``--check`` exits 1 when the named criteria set is not met (``lab``: at least 50 runs, hard-reject
rate under 5%, p95 latency under 90 s, budget exhaustion under 2%, no ``lookup_asset`` refusal;
``golden``: no hard reject, severity agreement 100%, action-set agreement at least 90%). The
database URL is read from ``--database-url`` or ``DATABASE_URL`` and never printed.
"""

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import asyncpg

OUTCOMES = ("VALID", "REJECTED", "BUDGET_EXHAUSTED", "TIMEOUT", "SCHEMA_INVALID", "ERROR")
LAB_MIN_RUNS = 50


def percentile(values: List[float], q: float) -> Optional[float]:
    """Linear interpolation between closest ranks (PostgreSQL's PERCENTILE_CONT)."""
    if not values:
        return None
    ordered = sorted(values)
    pos = q * (len(ordered) - 1)
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def rate(part: int, whole: int) -> Optional[float]:
    return part / whole if whole else None


def mean(values: List[float]) -> Optional[float]:
    return sum(values) / len(values) if values else None


async def fetch(dsn: str, since: Optional[datetime], mode: str) -> Dict[str, List[Dict[str, Any]]]:
    conn = await asyncpg.connect(dsn)
    try:
        async with conn.transaction(readonly=True):
            runs = await conn.fetch(
                "SELECT id, incident_id, revision, mode, outcome, reason_codes, latency_ms, input_tokens, "
                "output_tokens, total_llm_calls, total_tool_calls FROM agent_runs "
                "WHERE ($1::timestamptz IS NULL OR created_at >= $1) AND ($2 = 'all' OR mode = $2) ORDER BY id",
                since, mode,
            )
            run_ids = [r["id"] for r in runs]
            events = await conn.fetch(
                "SELECT run_id, agent_name, kind, tool_name, refused FROM agent_events WHERE run_id = ANY($1::int[]) "
                "ORDER BY run_id, seq",
                run_ids,
            )
            shadows = await conn.fetch(
                "SELECT s.incident_id, s.revision, s.run_id, s.assessment_source, s.severity_equal, s.action_set_equal, "
                "s.exploitation_equal FROM shadow_assessments s LEFT JOIN agent_runs r ON r.id = s.run_id "
                "WHERE ($1::timestamptz IS NULL OR s.created_at >= $1) AND ($2 = 'all' OR r.mode = $2) ORDER BY s.id",
                since, mode,
            )
    finally:
        await conn.close()
    return {"runs": [dict(r) for r in runs], "events": [dict(e) for e in events], "shadows": [dict(s) for s in shadows]}


def summarize(data: Dict[str, List[Dict[str, Any]]], since: Optional[datetime], mode: str) -> Dict[str, Any]:
    runs, events, shadows = data["runs"], data["events"], data["shadows"]
    n = len(runs)
    outcomes = Counter(r["outcome"] for r in runs)
    rejected_codes = Counter(c for r in runs if r["outcome"] == "REJECTED" for c in (r["reason_codes"] or []) if c != "AGENT_VALIDATION_REJECTED")
    latencies = [r["latency_ms"] / 1000.0 for r in runs]
    totals = [r["input_tokens"] + r["output_tokens"] for r in runs]

    tools: Dict[str, Dict[str, int]] = {}
    for e in events:
        if e["kind"] == "tool":
            entry = tools.setdefault(e["tool_name"], {"calls": 0, "refused": 0})
            entry["calls"] += 1
            entry["refused"] += int(bool(e["refused"]))
    refused_by_tool = {t: v["refused"] for t, v in sorted(tools.items()) if v["refused"]}
    model_refusals = sum(1 for e in events if e["kind"] == "llm" and e["refused"])

    m = len(shadows)
    agree = {k: sum(1 for s in shadows if s[f"{k}_equal"]) for k in ("severity", "action_set", "exploitation")}
    stats: Dict[str, Any] = {
        "window": {"since": since.isoformat() if since else None, "mode": mode},
        "runs": n,
        "outcomes": {o: outcomes.get(o, 0) for o in OUTCOMES} | {o: c for o, c in outcomes.items() if o not in OUTCOMES},
        "hard_rejects": outcomes.get("REJECTED", 0),
        "hard_reject_rate": rate(outcomes.get("REJECTED", 0), n),
        "hard_reject_reason_codes": dict(rejected_codes.most_common()),
        "fallback_rate": rate(n - outcomes.get("VALID", 0), n),
        "budget_exhausted_rate": rate(outcomes.get("BUDGET_EXHAUSTED", 0), n),
        "agreement": {
            "comparisons": m,
            "severity": rate(agree["severity"], m),
            "action_set": rate(agree["action_set"], m),
            "exploitation": rate(agree["exploitation"], m),
            "agreeing": agree,
        },
        "latency_seconds": {"p50": percentile(latencies, 0.5), "p95": percentile(latencies, 0.95), "max": max(latencies) if latencies else None},
        "tokens_per_run": {
            "input_mean": mean([r["input_tokens"] for r in runs]),
            "output_mean": mean([r["output_tokens"] for r in runs]),
            "total_mean": mean(totals),
            "total_p95": percentile(totals, 0.95),
        },
        "llm_calls_per_run": {"mean": mean([r["total_llm_calls"] for r in runs]), "max": max((r["total_llm_calls"] for r in runs), default=None)},
        "tool_calls": dict(sorted(tools.items())),
        "refusals": {
            "tool_calls_refused": sum(refused_by_tool.values()),
            "by_tool": refused_by_tool,
            "lookup_asset": refused_by_tool.get("lookup_asset", 0),
            "model_calls_refused": model_refusals,
        },
    }
    stats["criteria"] = criteria(stats)
    return stats


def _bar(name: str, bar: str, value: Any, met: bool) -> Dict[str, Any]:
    return {"name": name, "bar": bar, "value": value, "met": bool(met)}


def criteria(stats: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Plan C2.5. A criterion with nothing to measure is not met."""
    a, n = stats["agreement"], stats["runs"]
    p95 = stats["latency_seconds"]["p95"]
    golden = [
        _bar("validator hard rejects", "0", stats["hard_rejects"], n > 0 and stats["hard_rejects"] == 0),
        _bar("severity agreement", "100%", a["severity"], a["severity"] == 1.0),
        _bar("action-set agreement", ">= 90%", a["action_set"], a["action_set"] is not None and a["action_set"] >= 0.9),
    ]
    lab = [
        _bar("shadow runs", f">= {LAB_MIN_RUNS}", n, n >= LAB_MIN_RUNS),
        _bar("hard-reject rate", "< 5%", stats["hard_reject_rate"], stats["hard_reject_rate"] is not None and stats["hard_reject_rate"] < 0.05),
        _bar("p95 latency (s)", "< 90", p95, p95 is not None and p95 < 90),
        _bar("budget exhaustion", "< 2%", stats["budget_exhausted_rate"], stats["budget_exhausted_rate"] is not None and stats["budget_exhausted_rate"] < 0.02),
        _bar("lookup_asset refusals", "0", stats["refusals"]["lookup_asset"], n > 0 and stats["refusals"]["lookup_asset"] == 0),
    ]
    return {"golden": golden, "lab": lab}


def _pct(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _num(value: Optional[float], digits: int = 1) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _measured(c: Dict[str, Any]) -> str:
    v = c["value"]
    if v is None:
        return "n/a"
    if "%" in c["bar"]:
        return _pct(v)
    return _num(v, 2) if isinstance(v, float) else str(v)


def render_markdown(stats: Dict[str, Any]) -> str:
    n, a = stats["runs"], stats["agreement"]
    m = a["comparisons"]
    lines = [
        "# Shadow comparison report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Window | {'runs created at or after ' + stats['window']['since'] if stats['window']['since'] else 'all runs'} |",
        f"| Mode | {stats['window']['mode']} |",
        f"| Agent runs | {n} |",
        f"| Shadow comparisons | {m} |",
        "",
        "## Agreement with the legacy assessment",
        "",
        "| Field | Agreeing | Rate |",
        "|---|---|---|",
    ]
    for key, label in (("severity", "Severity"), ("action_set", "Action set"), ("exploitation", "Exploitation assessment")):
        lines.append(f"| {label} | {a['agreeing'][key]}/{m} | {_pct(a[key])} |")
    lines += ["", "## Run outcomes", "", "| Outcome | Runs | Rate |", "|---|---|---|"]
    for outcome, count in stats["outcomes"].items():
        lines.append(f"| {outcome} | {count} | {_pct(rate(count, n))} |")
    lines += [
        "",
        f"Validator hard-reject rate (`REJECTED`): {_pct(stats['hard_reject_rate'])}. "
        f"Fallback rate (any outcome but `VALID`): {_pct(stats['fallback_rate'])}. "
        f"Budget exhaustion: {_pct(stats['budget_exhausted_rate'])}.",
    ]
    if stats["hard_reject_reason_codes"]:
        lines.append("Hard-reject reason codes: " + ", ".join(f"`{c}` {k}" for c, k in stats["hard_reject_reason_codes"].items()) + ".")
    lat, tok, calls = stats["latency_seconds"], stats["tokens_per_run"], stats["llm_calls_per_run"]
    lines += [
        "",
        "## Latency, tokens and model calls per run",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Latency p50 (s) | {_num(lat['p50'], 2)} |",
        f"| Latency p95 (s) | {_num(lat['p95'], 2)} |",
        f"| Latency max (s) | {_num(lat['max'], 2)} |",
        f"| Input tokens per run (mean) | {_num(tok['input_mean'])} |",
        f"| Output tokens per run (mean) | {_num(tok['output_mean'])} |",
        f"| Total tokens per run (mean / p95) | {_num(tok['total_mean'])} / {_num(tok['total_p95'])} |",
        f"| Model calls per run (mean / max) | {_num(calls['mean'])} / {calls['max'] if calls['max'] is not None else 'n/a'} |",
        "",
        "## Tool calls",
        "",
        "| Tool | Calls | Refused |",
        "|---|---|---|",
    ]
    for tool, entry in stats["tool_calls"].items():
        lines.append(f"| `{tool}` | {entry['calls']} | {entry['refused']} |")
    if not stats["tool_calls"]:
        lines.append("| (none) | 0 | 0 |")
    ref = stats["refusals"]
    lines += [
        "",
        f"Refusals: {ref['tool_calls_refused']} tool calls"
        + (" (" + ", ".join(f"`{t}` {k}" for t, k in ref["by_tool"].items()) + ")" if ref["by_tool"] else "")
        + f"; `lookup_asset` {ref['lookup_asset']}; model calls refused by the budget {ref['model_calls_refused']}.",
        "",
        "## Promotion criteria (plan C2.5)",
        "",
        "| Set | Criterion | Bar | Measured | Met |",
        "|---|---|---|---|---|",
    ]
    for set_name in ("golden", "lab"):
        for c in stats["criteria"][set_name]:
            lines.append(f"| {set_name} | {c['name']} | {c['bar']} | {_measured(c)} | {'yes' if c['met'] else 'no'} |")
    lines += ["", "No-write evidence is not in these tables: it comes from the tool contract tests and the e2e repository spy."]
    return "\n".join(lines) + "\n"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shadow comparison harness for the ADK investigator (plan C2.3).")
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL"), help="PostgreSQL URL (default: DATABASE_URL)")
    window = parser.add_mutually_exclusive_group()
    window.add_argument("--since", help="only runs created at or after this ISO 8601 timestamp")
    window.add_argument("--hours", type=float, help="only runs created in the last N hours")
    parser.add_argument("--mode", choices=("shadow", "live", "all"), default="shadow", help="agent_runs.mode to report (default shadow)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    parser.add_argument("--check", choices=("golden", "lab"), help="exit 1 unless this C2.5 criteria set is met")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if not args.database_url:
        print("shadow_report: set DATABASE_URL or pass --database-url", file=sys.stderr)
        return 2
    since = None
    if args.since:
        since = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
        since = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
    elif args.hours is not None:
        since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    stats = summarize(asyncio.run(fetch(args.database_url, since, args.mode)), since, args.mode)
    print(json.dumps(stats, indent=2, sort_keys=True) if args.json else render_markdown(stats), end="" if not args.json else "\n")
    if args.check:
        return 0 if all(c["met"] for c in stats["criteria"][args.check]) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
