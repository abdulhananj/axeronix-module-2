"""
Shared data model for the Correlation Engine.

Everything downstream (dedup, rules, grouping, sessions, kill-chain
mapping) passes these same objects around, so this file is the
"agreed schema" the docs insist on freezing early.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import itertools

_id_counter = itertools.count(1)


def _next_id(prefix: str) -> str:
    return f"{prefix}-{next(_id_counter):06d}"


@dataclass
class Event:
    """
    One normalized log event, matching Module 1's shared JSON schema.

    Required fields: timestamp, host, source_type, event_id, raw_message
    Optional: user, process
    """
    timestamp: datetime
    host: str
    source_type: str
    event_id: str
    raw_message: str
    user: Optional[str] = None
    process: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def key(self) -> tuple:
        """Identity used for exact-duplicate detection."""
        return (self.host, self.event_id, self.user, self.raw_message)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        """
        Build an Event from a plain dict — the shape Module 1's JSON
        schema (or your own log export) produces: timestamp, host,
        source_type, event_id, raw_message, plus optional user/process.

        Accepts timestamp as either an ISO 8601 string or a datetime.
        Any fields beyond the known ones are kept in `extra` so
        signals like `new_geo` or `parent_process` survive the trip.
        """
        known = {"timestamp", "host", "source_type", "event_id",
                 "raw_message", "user", "process"}

        ts = d["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))

        return cls(
            timestamp=ts,
            host=d["host"],
            source_type=d.get("source_type", "unknown"),
            event_id=str(d["event_id"]),
            raw_message=d.get("raw_message", ""),
            user=d.get("user"),
            process=d.get("process"),
            extra={k: v for k, v in d.items() if k not in known},
        )



@dataclass
class Alert:
    """
    One fired detection — the output of a correlation rule matching
    against one or more events.
    """
    rule_name: str
    description: str
    events: list[Event]
    host: str
    user: Optional[str] = None
    severity: str = "medium"
    alert_id: str = field(default_factory=lambda: _next_id("ALERT"))
    count: int = 1  # bumped by dedup when repeats collapse into this alert

    @property
    def start_time(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def end_time(self) -> datetime:
        return max(e.timestamp for e in self.events)

    def dedup_key(self, window_seconds: int) -> tuple:
        """
        Same rule + same host + same user, bucketed into a coarse time
        window, so repeats of the same alert collapse together.
        """
        bucket = int(self.start_time.timestamp() // window_seconds)
        return (self.rule_name, self.host, self.user, bucket)


@dataclass
class Session:
    """
    One user, one host, a start/end time, and every event that
    happened inside that window. The unit of investigation the rest
    of the platform consumes.
    """
    host: str
    events: list[Event]
    user: Optional[str] = None
    session_id: str = field(default_factory=lambda: _next_id("SESSION"))

    @property
    def start_time(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def end_time(self) -> datetime:
        return max(e.timestamp for e in self.events)


@dataclass
class KillChainStep:
    """One event, labeled with the attack stage it represents."""
    event: Event
    stage: str
    technique_hint: Optional[str] = None


@dataclass
class Incident:
    """
    Final output of the engine: one or more related alerts, grouped,
    time-ordered, and mapped onto kill-chain stages. This is what
    Module 3 (AI Investigation), Module 6 (Timeline), and Module 7
    (Attack Graph) all consume.
    """
    alerts: list[Alert]
    incident_id: str = field(default_factory=lambda: _next_id("INC"))
    kill_chain: list[KillChainStep] = field(default_factory=list)

    @property
    def hosts(self) -> set[str]:
        return {a.host for a in self.alerts}

    @property
    def users(self) -> set[str]:
        return {a.user for a in self.alerts if a.user}

    @property
    def start_time(self) -> datetime:
        return min(a.start_time for a in self.alerts)

    @property
    def end_time(self) -> datetime:
        return max(a.end_time for a in self.alerts)

    @property
    def severity(self) -> str:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return max((a.severity for a in self.alerts), key=lambda s: order.get(s, 0))

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly representation for handoff to other modules."""
        return {
            "incident_id": self.incident_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "hosts": sorted(self.hosts),
            "users": sorted(u for u in self.users if u),
            "severity": self.severity,
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "rule_name": a.rule_name,
                    "description": a.description,
                    "host": a.host,
                    "user": a.user,
                    "severity": a.severity,
                    "count": a.count,
                    "start_time": a.start_time.isoformat(),
                    "end_time": a.end_time.isoformat(),
                    "evidence": [
                        {
                            "timestamp": e.timestamp.isoformat(),
                            "host": e.host,
                            "event_id": e.event_id,
                            "raw_message": e.raw_message,
                        }
                        for e in a.events
                    ],
                }
                for a in self.alerts
            ],
            "kill_chain": [
                {
                    "stage": step.stage,
                    "technique_hint": step.technique_hint,
                    "timestamp": step.event.timestamp.isoformat(),
                    "event_id": step.event.event_id,
                    "raw_message": step.event.raw_message,
                }
                for step in self.kill_chain
            ],
        }
