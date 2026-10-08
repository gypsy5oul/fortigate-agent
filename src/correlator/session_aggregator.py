"""Stateful correlation engine grouping security events into attack episodes with stable incident identity."""

import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class Episode:
    def __init__(
        self,
        source_ip: str,
        target_ip: Optional[str],
        first_seen_ts: float,
        vdom: str = "root",
        direction: str = "INBOUND",
        service: Optional[str] = None,
        incident_id: Optional[str] = None,
        status: str = "OPEN",
        restored: bool = False,
    ):
        self.source_ip = source_ip
        self.target_ip = target_ip or "*"
        self.first_seen_ts = first_seen_ts
        self.last_seen_ts = first_seen_ts
        self.last_event_ts_ns = int(first_seen_ts * 1e9)
        self.vdom = vdom
        self.direction = direction
        self.service = service
        self.status = status
        self.restored = restored
        self.events: List[Dict[str, Any]] = []
        self.seen_event_ids: Set[str] = set()
        self.signatures: Set[str] = set()
        self.utm_subtypes: Set[str] = set()
        self.target_ports: Set[int] = set()
        self.services: Set[str] = {service} if service else set()
        self.enforcement_counts: Dict[str, int] = {
            "BLOCKED": 0,
            "ALLOWED": 0,
            "ALLOWED_OR_DETECTED": 0,
            "SESSION_CLOSED": 0,
            "UNKNOWN": 0,
        }
        self.blocked_session_ids: Set[int] = set()
        self.session_ids: Set[int] = set()

        if incident_id:
            self.incident_id = incident_id
        else:
            seed = f"{vdom}|{direction}|{source_ip}|{self.target_ip}|{int(first_seen_ts)}"
            self.incident_id = f"INC-{hashlib.sha256(seed.encode()).hexdigest()[:12].upper()}"

        # Durable episode primary key: vdom + direction + source + target + start
        self.episode_id = f"EP-{hashlib.sha256(f'{vdom}|{direction}|{source_ip}|{self.target_ip}|{int(first_seen_ts)}'.encode()).hexdigest()[:16].upper()}"

    def add_event(self, event: Dict[str, Any], event_ts: float) -> bool:
        """Add event to episode with identity deduplication."""
        ev_id = event.get("id")
        if ev_id:
            if ev_id in self.seen_event_ids:
                return False
            self.seen_event_ids.add(ev_id)

        self.last_seen_ts = max(self.last_seen_ts, event_ts)
        self.last_event_ts_ns = max(self.last_event_ts_ns, int(event_ts * 1e9))
        self.events.append(event)

        # Cap retained event evidence to 25 most severe/representative lines
        if len(self.events) > 25:
            self.events.sort(key=lambda e: (e.get("action_normalized") != "BLOCKED", e.get("id", "")), reverse=True)
            self.events = self.events[:25]

        sig = event.get("signature") or event.get("attack") or event.get("virus") or event.get("vuln_name")
        if sig:
            self.signatures.add(sig)

        port = event.get("dstport")
        if port:
            try:
                self.target_ports.add(int(port))
            except ValueError:
                pass

        svc = event.get("service")
        if svc:
            self.services.add(svc)

        sid = event.get("sessionid")
        if sid is not None:
            try:
                self.session_ids.add(int(sid))
            except ValueError:
                pass

        log_type = event.get("log_type")
        action_norm = event.get("action_normalized", "UNKNOWN")

        if log_type == "utm":
            subtype = (event.get("subtype") or "").lower()
            if subtype:
                self.utm_subtypes.add(subtype)

        # UTM events that were blocked mark this sessionid as blocked
        if log_type == "utm" and action_norm == "BLOCKED" and sid is not None:
            try:
                sid_int = int(sid)
                if sid_int not in self.blocked_session_ids:
                    self.blocked_session_ids.add(sid_int)
                    for prev_ev in self.events:
                        if prev_ev.get("log_type") == "traffic" and prev_ev.get("sessionid") == sid:
                            if prev_ev.get("action_normalized") == "ALLOWED":
                                if self.enforcement_counts["ALLOWED"] > 0:
                                    self.enforcement_counts["ALLOWED"] -= 1
                                    self.enforcement_counts["BLOCKED"] += 1
                            elif prev_ev.get("action_normalized") == "ALLOWED_OR_DETECTED":
                                if self.enforcement_counts["ALLOWED_OR_DETECTED"] > 0:
                                    self.enforcement_counts["ALLOWED_OR_DETECTED"] -= 1
                                    self.enforcement_counts["BLOCKED"] += 1
            except ValueError:
                pass

        # Traffic logs whose sessionid matches a UTM log that was BLOCKED do not count as ALLOWED
        if log_type == "traffic" and sid is not None and sid in self.blocked_session_ids:
            self.enforcement_counts["BLOCKED"] += 1
        elif action_norm in self.enforcement_counts:
            self.enforcement_counts[action_norm] += 1
        else:
            self.enforcement_counts["UNKNOWN"] += 1

        return True

    @property
    def event_count(self) -> int:
        return sum(self.enforcement_counts.values())

    @property
    def overall_enforcement(self) -> str:
        utm_blocked = any(ev.get("log_type") == "utm" and ev.get("action_normalized") == "BLOCKED" for ev in self.events)
        utm_allowed = any(ev.get("log_type") == "utm" and ev.get("action_normalized") == "ALLOWED_OR_DETECTED" for ev in self.events)
        if utm_blocked and utm_allowed:
            return "MIXED"

        blocked = self.enforcement_counts["BLOCKED"]
        allowed = self.enforcement_counts["ALLOWED_OR_DETECTED"] + self.enforcement_counts["ALLOWED"]
        if blocked > 0 and allowed > 0:
            return "MIXED"
        if allowed > 0:
            return "ALLOWED_OR_DETECTED"
        if blocked > 0:
            return "BLOCKED"
        if self.enforcement_counts.get("SESSION_CLOSED", 0) > 0:
            return "SESSION_CLOSED"
        return "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        primary_port = next(iter(self.target_ports)) if self.target_ports else None
        primary_svc = self.service or (next(iter(self.services)) if self.services else None)
        return {
            "episode_id": self.episode_id,
            "incident_id": self.incident_id,
            "vdom": self.vdom,
            "direction": self.direction,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "service": primary_svc,
            "target_port": primary_port,
            "target_service": primary_svc,
            "target_ports": sorted(list(self.target_ports)),
            "services": sorted(list(self.services)),
            "first_seen": datetime.fromtimestamp(self.first_seen_ts, tz=timezone.utc),
            "last_seen": datetime.fromtimestamp(self.last_seen_ts, tz=timezone.utc),
            "last_event_ts_ns": self.last_event_ts_ns,
            "status": self.status,
            "event_count": self.event_count,
            "enforcement": self.overall_enforcement,
            "enforcement_counts": dict(self.enforcement_counts),
            "signatures": sorted(list(self.signatures)),
            "utm_subtypes": sorted(list(self.utm_subtypes)),
            "events": self.events,
            "evidence_ids": [str(e["id"]) for e in self.events if "id" in e],
            "session_ids": sorted(list(self.session_ids)),
            "restored": getattr(self, "restored", False),
        }


class SessionAggregator:
    def __init__(
        self,
        idle_timeout_seconds: int = 120,
        max_episode_seconds: int = 600,
        campaign_window_seconds: int = 1800,
    ):
        self.idle_timeout = idle_timeout_seconds
        self.max_episode = max_episode_seconds
        self.campaign_window = campaign_window_seconds
        self.active_episodes: Dict[str, Episode] = {}
        self.recent_incidents: Dict[str, Tuple[str, float]] = {}
        self.latest_event_ts: float = 0.0
        self._closed_episode_ids: List[str] = []

    def _get_key(self, vdom: str, direction: str, source_ip: str, target_ip: Optional[str]) -> str:
        tgt = target_ip if target_ip is not None else "*"
        return f"{vdom}:{direction}:{source_ip}->{tgt}"

    def pop_closed_episode_ids(self) -> List[str]:
        ids = list(self._closed_episode_ids)
        self._closed_episode_ids.clear()
        return ids

    def load_open_episodes(self, records: List[Dict[str, Any]]):
        """Restore active episodes from the persistent episodes database table on startup."""
        for rec in records:
            vdom = rec.get("vdom", "root")
            direction = rec.get("direction", "INBOUND")
            src = rec["source_ip"]
            dst = rec.get("target_ip")
            svc = rec.get("service")
            key = self._get_key(vdom, direction, src, dst)

            first_seen_dt = rec.get("first_seen")
            first_ts = first_seen_dt.timestamp() if isinstance(first_seen_dt, datetime) else time.time()
            last_seen_dt = rec.get("last_seen")
            last_ts = last_seen_dt.timestamp() if isinstance(last_seen_dt, datetime) else first_ts

            ep = Episode(
                source_ip=src,
                target_ip=dst,
                first_seen_ts=first_ts,
                vdom=vdom,
                direction=direction,
                service=svc,
                incident_id=rec.get("incident_id"),
                status="OPEN",
                restored=True,
            )
            ep.last_seen_ts = last_ts
            ep.last_event_ts_ns = rec.get("last_event_ts_ns", int(last_ts * 1e9))
            ep.episode_id = rec.get("id", ep.episode_id)

            # Restore enforcement counts
            enf_counts = rec.get("enforcement_counts")
            if isinstance(enf_counts, str):
                try:
                    enf_counts = json.loads(enf_counts)
                except Exception:
                    enf_counts = {}
            if isinstance(enf_counts, dict) and enf_counts:
                ep.enforcement_counts.update(enf_counts)

            # Restore signatures
            sigs = rec.get("signatures")
            if isinstance(sigs, str):
                try:
                    sigs = json.loads(sigs)
                except Exception:
                    sigs = []
            if isinstance(sigs, (list, set)):
                ep.signatures = set(sigs)

            # Restore UTM subtypes seen (migration 005)
            subtypes = rec.get("utm_subtypes")
            if isinstance(subtypes, str):
                try:
                    subtypes = json.loads(subtypes)
                except Exception:
                    subtypes = []
            if isinstance(subtypes, (list, set)):
                ep.utm_subtypes = {str(s).lower() for s in subtypes if s}

            # Restore evidence IDs if present
            ev_ids = rec.get("evidence_ids")
            if isinstance(ev_ids, str):
                try:
                    ev_ids = json.loads(ev_ids)
                except Exception:
                    ev_ids = []
            if isinstance(ev_ids, list):
                ep.seen_event_ids = set(ev_ids)

            # Reconcile event count if stored event_count exceeds enforcement counts sum
            rec_ev_count = rec.get("event_count", 0)
            cur_sum = sum(ep.enforcement_counts.values())
            if rec_ev_count > cur_sum:
                ep.enforcement_counts["UNKNOWN"] += (rec_ev_count - cur_sum)

            self.active_episodes[key] = ep
            self.recent_incidents[key] = (ep.incident_id, last_ts)
            self.latest_event_ts = max(self.latest_event_ts, last_ts)

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ingest events using event timestamps for window boundaries and campaign linking."""
        now = time.time()
        touched_episodes: List[Episode] = []

        for ev in events:
            src = ev["srcip"]
            dst = ev.get("dstip")
            vdom = ev.get("vd", "root")
            direction = ev.get("direction", "INBOUND")
            svc = ev.get("service")
            key = self._get_key(vdom, direction, src, dst)

            ev_ts = (ev.get("eventtime_ns") or ev.get("loki_ts_ns") or int(now * 1e9)) / 1e9
            self.latest_event_ts = max(self.latest_event_ts, ev_ts)

            assigned_inc_id = None

            if key in self.active_episodes:
                ep = self.active_episodes[key]
                # Check idle timeout (120 s) or max duration (600 s) based on event time
                if (ev_ts - ep.last_seen_ts > self.idle_timeout) or (ev_ts - ep.first_seen_ts > self.max_episode):
                    ep.status = "CLOSED"
                    self._closed_episode_ids.append(ep.episode_id)
                    # Campaign window check (30 min) for same target key
                    if (ev_ts - ep.last_seen_ts) <= self.campaign_window:
                        assigned_inc_id = ep.incident_id
                    new_ep = Episode(src, dst, ev_ts, vdom=vdom, direction=direction, service=svc, incident_id=assigned_inc_id)
                    self.active_episodes[key] = new_ep
            else:
                # Check campaign window across recent incidents for this specific target key
                recent_info = self.recent_incidents.get(key)
                if recent_info and (ev_ts - recent_info[1] <= self.campaign_window):
                    assigned_inc_id = recent_info[0]
                new_ep = Episode(src, dst, ev_ts, vdom=vdom, direction=direction, service=svc, incident_id=assigned_inc_id)
                self.active_episodes[key] = new_ep

            current_ep = self.active_episodes[key]
            current_ep.add_event(ev, ev_ts)
            self.recent_incidents[key] = (current_ep.incident_id, ev_ts)
            if current_ep not in touched_episodes:
                touched_episodes.append(current_ep)

        return [ep.to_dict() for ep in touched_episodes]

    def prune_stale_episodes(self, current_event_time: Optional[float] = None) -> List[str]:
        """Close episodes exceeding idle timeout using event timestamp progression."""
        ref_time = current_event_time or self.latest_event_ts
        stale_keys = [
            k for k, ep in self.active_episodes.items()
            if (ref_time - ep.last_seen_ts > self.idle_timeout)
        ]
        closed_ids = []
        for k in stale_keys:
            ep = self.active_episodes[k]
            ep.status = "CLOSED"
            closed_ids.append(ep.episode_id)
            del self.active_episodes[k]
        return closed_ids
