#!/usr/bin/env python3
"""Export one real, investigated incident from the service database as a redacted golden case
(plan C2.2: "two real redacted incidents from the lab") in the EvalSet format of evals/golden.

    DATABASE_URL=postgresql://... python scripts/export_golden_incident.py <incident_id> <revision> \\
        [--name <case name>] > evals/lab/<case name>.test.json

What it reads, in one read-only transaction: the ADK session ``<incident_id>:<revision>`` (schema
``adk``), whose state holds the incident identity and the redacted packet exactly as the agents saw
it; the committed assessment of that revision (``incident_revisions``; in shadow mode the legacy
one), used as the reference answer; and the incidents from the same source in the 24 h before it,
which ``recent_incidents_for_source`` would return. Traffic-context lines live in Loki, not in the
database, so the case's traffic fixture is empty.

What it redacts: every IPv4 and IPv6 address outside the documentation ranges becomes a
documentation-range placeholder (the incident's source 198.51.100.x, its target 192.0.2.x, any other
203.0.113.x or 2001:db8::x), consistently across the whole case; every URL host becomes
``redacted.example``; incident ids become ``INC-LAB-<hash>``. Usernames are already hashed in the
packet. The script refuses to print a case that still contains an address outside the documentation
ranges or an internal-looking host name, and the operator reviews the file before committing it.
"""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import asyncpg

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.storage.timeutil import to_utc_datetime  # noqa: E402

APP_NAME = "forti-investigator"   # src/investigation/agent/runtime.py
USER_ID = "system"
EVAL_APP_NAME = "forti_investigator"  # src/investigation/agent/evaluation.py
EVAL_FIXTURE_KEY = "eval_fixture"
KICKOFF = "Investigate the incident bound to this session."
EXPECTED_TOOL_USES = ["evidence_agent", "context_agent"]
WRITER_FIELDS = (
    "incident_id", "incident_revision", "severity", "attack_category", "exploitation_assessment", "enforcement",
    "summary", "findings", "cve_references", "visibility_gaps", "recommended_action_ids", "analyst_follow_up",
)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
# Boundaries: an address may end a sentence ("... against 192.0.2.7.") but is never part of a longer
# dotted number or hex group.
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
INTERNAL_HOST = re.compile(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:internal|local|lan|corp|intra|intranet|home|localdomain)\b", re.I)


def _address(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def addresses(text: str) -> List[str]:
    """Every valid IPv4/IPv6 address in ``text``, in order of first appearance."""
    found: Dict[str, None] = {}
    for pattern in (IPV4, IPV6):
        for m in pattern.finditer(text):
            if _address(m.group(0)) is not None:
                found.setdefault(m.group(0), None)
    return sorted(found, key=text.index)


def is_documentation(addr: str) -> bool:
    ip = _address(addr)
    return ip is not None and (ip.is_loopback or any(ip.version == n.version and ip in n for n in DOC_NETS))


def leaks(text: str) -> List[str]:
    """Addresses outside the documentation ranges and internal-looking host names left in ``text``."""
    return [a for a in addresses(text) if not is_documentation(a)] + sorted(set(INTERNAL_HOST.findall(text)))


class Pseudonymizer:
    def __init__(self) -> None:
        self.mapping: Dict[str, str] = {}
        self._next = {"source": 10, "target": 10, "other": 10, "v6": 1}

    def _placeholder(self, role: str, version: int) -> str:
        if version == 6:
            n = self._next["v6"]
            self._next["v6"] += 1
            return f"2001:db8::{n:x}"
        prefix = {"source": "198.51.100", "target": "192.0.2", "other": "203.0.113"}[role]
        while True:
            candidate = f"{prefix}.{self._next[role]}"
            self._next[role] += 1
            if candidate not in self.mapping.values():
                return candidate

    def map(self, addr: str, role: str = "other") -> str:
        if is_documentation(addr):
            return addr
        if addr not in self.mapping:
            self.mapping[addr] = self._placeholder(role, _address(addr).version)
        return self.mapping[addr]

    def apply(self, text: str) -> str:
        for addr in addresses(text):
            self.map(addr)
        for addr in sorted(self.mapping, key=len, reverse=True):
            if ":" in addr:
                pattern = r"(?<![0-9A-Fa-f:])" + re.escape(addr) + r"(?![0-9A-Fa-f:])"
            else:
                pattern = r"(?<![\d.])" + re.escape(addr) + r"(?!\.?\d)"
            text = re.sub(pattern, self.mapping[addr], text)
        return text


def _redact_url(url: Any) -> Any:
    if not isinstance(url, str) or "://" not in url:
        return url
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, "redacted.example", parts.path, parts.query, ""))


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


async def fetch(dsn: str, incident_id: str, revision: int) -> Dict[str, Any]:
    conn = await asyncpg.connect(dsn)
    try:
        async with conn.transaction(readonly=True):
            session = await conn.fetchrow(
                "SELECT state FROM adk.sessions WHERE app_name = $1 AND user_id = $2 AND id = $3",
                APP_NAME, USER_ID, f"{incident_id}:{revision}",
            )
            committed = await conn.fetchrow(
                "SELECT assessment_json, assessment_source FROM incident_revisions WHERE incident_id = $1 AND revision = $2",
                incident_id, revision,
            )
            recent: List[Dict[str, Any]] = []
            if session is not None:
                state = _json(session["state"])
                end = to_utc_datetime(int(state["window_end_ns"]))
                rows = await conn.fetch(
                    "SELECT id, source_ip, target_ip, severity, enforcement, last_seen, deterministic_rule_ids FROM incidents "
                    "WHERE source_ip = $1 AND id <> $2 AND last_seen <= $3 AND last_seen >= $4 ORDER BY last_seen DESC LIMIT 10",
                    state["source_ip"], incident_id, end, end - timedelta(hours=24),
                )
                recent = [dict(r) for r in rows]
    finally:
        await conn.close()
    return {
        "state": _json(session["state"]) if session else None,
        "committed": _json(committed["assessment_json"]) if committed else None,
        "committed_source": committed["assessment_source"] if committed else None,
        "recent": recent,
    }


def build_case(data: Dict[str, Any], incident_id: str, revision: int, name: str) -> Dict[str, Any]:
    state = {k: v for k, v in data["state"].items() if not k.startswith(("temp:", "app:", "user:"))}
    state.pop("investigation_notes", None)
    state.pop("evidence_notes", None)
    state.pop("context_notes", None)
    state.pop("assessment_json", None)
    packet = state["packet"]
    for event in packet.get("evidence_events") or []:
        if "url" in event:
            event["url"] = _redact_url(event["url"])
    state[EVAL_FIXTURE_KEY] = {
        "traffic_lines": [],
        "recent_incidents": [
            {
                "id": r["id"], "source_ip": r["source_ip"], "target_ip": r["target_ip"], "severity": r["severity"],
                "enforcement": r["enforcement"], "last_seen": to_utc_datetime(r["last_seen"]).isoformat(),
                "deterministic_rule_ids": list(r["deterministic_rule_ids"] or []),
            }
            for r in data["recent"]
        ],
    }
    reference = {k: data["committed"][k] for k in WRITER_FIELDS if k in data["committed"]}
    case = {
        "eval_set_id": f"lab_{name}",
        "name": f"lab {name}",
        "description": (
            f"Real incident exported from the lab database by scripts/export_golden_incident.py (revision {revision}). "
            f"Reference answer: the committed assessment of that revision ({data['committed_source']}); review it before committing. "
            "Addresses, URL hosts and the incident id are pseudonymized; the traffic-context fixture is empty."
        ),
        "eval_cases": [{
            "eval_id": name,
            "conversation": [{
                "invocation_id": f"lab-{name}",
                "user_content": {"role": "user", "parts": [{"text": KICKOFF}]},
                "final_response": {"role": "model", "parts": [{"text": json.dumps(reference, sort_keys=False)}]},
                "intermediate_data": {
                    "tool_uses": [{"name": n, "args": {}} for n in EXPECTED_TOOL_USES],
                    "tool_responses": [],
                    "intermediate_responses": [],
                },
                "creation_timestamp": 0.0,
            }],
            "session_input": {"app_name": EVAL_APP_NAME, "user_id": USER_ID, "state": state},
            "creation_timestamp": 0.0,
        }],
        "creation_timestamp": 0.0,
    }

    # Pseudonymize: the incident's own addresses first, so they get the role ranges.
    pseudo = Pseudonymizer()
    pseudo.map(state["source_ip"], "source")
    pseudo.map(state["target_ip"], "target")
    text = pseudo.apply(json.dumps(case, indent=2))
    for real_id in [incident_id] + [r["id"] for r in data["recent"]]:
        text = text.replace(real_id, lab_incident_id(real_id))
    return json.loads(text)


def lab_incident_id(real_id: str) -> str:
    return "INC-LAB-" + hashlib.sha256(real_id.encode("utf-8")).hexdigest()[:8].upper()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Export a real incident as a redacted golden case (plan C2.2).")
    parser.add_argument("incident_id")
    parser.add_argument("revision", type=int, help="the investigated revision (the ADK session is <incident_id>:<revision>)")
    parser.add_argument("--name", help="case name (default: lab_<revision>_<hash>)")
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL"), help="PostgreSQL URL (default: DATABASE_URL)")
    args = parser.parse_args(argv)
    if not args.database_url:
        print("export_golden_incident: set DATABASE_URL or pass --database-url", file=sys.stderr)
        return 2
    data = asyncio.run(fetch(args.database_url, args.incident_id, args.revision))
    if data["state"] is None:
        print(f"export_golden_incident: no ADK session {args.incident_id}:{args.revision} (never investigated by the agent, "
              "or pruned from schema adk)", file=sys.stderr)
        return 1
    if data["committed"] is None:
        print(f"export_golden_incident: incident {args.incident_id} has no revision {args.revision}", file=sys.stderr)
        return 1
    name = args.name or f"incident_{hashlib.sha256(args.incident_id.encode('utf-8')).hexdigest()[:8]}_r{args.revision}"
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        print("export_golden_incident: --name may contain letters, digits and underscores only", file=sys.stderr)
        return 2
    text = json.dumps(build_case(data, args.incident_id, args.revision, name), indent=2) + "\n"
    found = leaks(text)
    if found:
        print("export_golden_incident: refusing to print, site data left after redaction: " + ", ".join(found), file=sys.stderr)
        return 3
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
