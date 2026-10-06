"""Stateful correlation engine grouping security events into attack episodes."""

import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class Episode:
    def __init__(
        self,
        source_ip: str,
        target_ip: str,
        first_seen_ts: float,
        vdom: str = "root",
        direction: str = "INBOUND",
    ):
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.first_seen_ts = first_seen_ts
        self.last_seen_ts = first_seen_ts
        self.vdom = vdom
        self.direction = direction
        self.events: List[Dict[str, Any]] = []
        self.seen_event_ids: Set[str] = set()
        self.signatures: Set[str] = set()
        self.target_ports: Set[int] = set()
        self.services: Set[str] = set()
        self.enforcement_counts: Dict[str, int] = {
            "BLOCKED": 0,
            "ALLOWED_OR_DETECTED": 0,
            "SESSION_CLOSED": 0,
            "UNKNOWN": 0,
        }
        # Deterministic incident ID scoped by VDOM, direction, IPs and start timestamp
        seed = f"{vdom}|{direction}|{source_ip}|{target_ip}|{int(first_seen_ts)}"
        self.incident_id = f"INC-{hashlib.sha256(seed.encode()).hexdigest()[:12].upper()}"

    def add_event(self, event: Dict[str, Any], event_ts: float) -> bool:
        """Add event to episode with identity deduplication.
        
        Returns:
            True if event was new and added, False if duplicate.
        """
        ev_id = event.get("id")
        if ev_id:
            if ev_id in self.seen_event_ids:
                return False  # Already counted in this episode
            self.seen_event_ids.add(ev_id)

        self.last_seen_ts = max(self.last_seen_ts, event_ts)
        self.events.append(event)

        # Cap retained event evidence to 25 most severe/representative lines
        if len(self.events) > 25:
            # Sort keeping non-blocked and high-severity first
            self.events.sort(key=lambda e: (e.get("action_normalized") != "BLOCKED", e.get("id", "")), reverse=True)
            self.events = self.events[:25]

        sig = event.get("signature")
        if sig:
            self.signatures.add(sig)

        port = event.get("dstport")
        if port:
            self.target_ports.add(port)

        svc = event.get("service")
        if svc:
            self.services.add(svc)

        action_norm = event.get("action_normalized", "UNKNOWN")
        if action_norm in self.enforcement_counts:
            self.enforcement_counts[action_norm] += 1
        else:
            self.enforcement_counts["UNKNOWN"] += 1

        return True

    @property
    def event_count(self) -> int:
        return sum(self.enforcement_counts.values())

    @property
    def overall_enforcement(self) -> str:
        blocked = self.enforcement_counts["BLOCKED"]
        allowed = self.enforcement_counts["ALLOWED_OR_DETECTED"]
        if blocked > 0 and allowed > 0:
            return "MIXED"
        if allowed > 0:
            return "ALLOWED_OR_DETECTED"
        if blocked > 0:
            return "BLOCKED"
        if self.enforcement_counts.get("SESSION_CLOSED", 0) > 0:
            return "ALLOWED_OR_DETECTED"
        return "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        primary_port = next(iter(self.target_ports)) if self.target_ports else None
        primary_svc = next(iter(self.services)) if self.services else None
        return {
            "incident_id": self.incident_id,
            "vdom": self.vdom,
            "direction": self.direction,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": primary_port,
            "target_service": primary_svc,
            "target_ports": sorted(list(self.target_ports)),
            "services": sorted(list(self.services)),
            "first_seen": datetime.fromtimestamp(self.first_seen_ts, tz=timezone.utc),
            "last_seen": datetime.fromtimestamp(self.last_seen_ts, tz=timezone.utc),
            "event_count": self.event_count,
            "enforcement": self.overall_enforcement,
            "enforcement_counts": dict(self.enforcement_counts),
            "signatures": sorted(list(self.signatures)),
            "events": self.events,
            "evidence_ids": [e["id"] for e in self.events if "id" in e],
        }


class SessionAggregator:
    def __init__(self, idle_timeout_seconds: int = 120, max_episode_seconds: int = 600):
        self.idle_timeout = idle_timeout_seconds
        self.max_episode = max_episode_seconds
        self.active_episodes: Dict[str, Episode] = {}

    def _get_key(self, vdom: str, direction: str, source_ip: str, target_ip: str) -> str:
        return f"{vdom}:{direction}:{source_ip}->{target_ip}"

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ingest events and return active/closed episode summaries for rule evaluation."""
        now = time.time()
        for ev in events:
            src = ev["srcip"]
            dst = ev["dstip"]
            vdom = ev.get("vd", "root")
            direction = ev.get("direction", "INBOUND")
            key = self._get_key(vdom, direction, src, dst)

            ev_ts = (ev.get("eventtime_ns") or ev.get("loki_ts_ns") or int(now * 1e9)) / 1e9

            if key not in self.active_episodes:
                self.active_episodes[key] = Episode(src, dst, ev_ts, vdom=vdom, direction=direction)
            else:
                ep = self.active_episodes[key]
                # If idle timeout or max length exceeded, reset window with new episode ID
                if (ev_ts - ep.last_seen_ts > self.idle_timeout) or (ev_ts - ep.first_seen_ts > self.max_episode):
                    self.active_episodes[key] = Episode(src, dst, ev_ts, vdom=vdom, direction=direction)

            self.active_episodes[key].add_event(ev, ev_ts)

        # Return snapshot of all active episodes touched
        return [ep.to_dict() for ep in self.active_episodes.values()]

    def prune_stale_episodes(self, current_time: Optional[float] = None) -> int:
        """Remove episodes exceeding idle timeout."""
        now = current_time or time.time()
        stale_keys = [
            k for k, ep in self.active_episodes.items()
            if (now - ep.last_seen_ts > self.idle_timeout)
        ]
        for k in stale_keys:
            del self.active_episodes[k]
        return len(stale_keys)
