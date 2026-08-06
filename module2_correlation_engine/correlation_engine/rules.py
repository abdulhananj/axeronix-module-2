"""
Step 3 — Hand-authored correlation rules

Per the build guide: pick a handful of well-known attack patterns and
encode each as an explicit if-this-then-that rule. Resist making this
generic/ML-driven yet — rules you can explain in one sentence are more
valuable at this stage than a black box.

Each Rule takes a Session (events already on one host/user, already
time-windowed) and returns zero or more Alerts. One extra rule
(LateralMovementRule) looks across sessions, since "same user on many
hosts" is inherently a cross-session pattern.

Reference event_id convention this module assumes (Module 1's schema):
  4625 = failed logon              4624 = successful logon
  4720 = new user account created  4732 = member added to admin group
  1    = process creation (Sysmon) — event.process holds the exe name,
         event.extra["parent_process"] holds the parent exe name
  event.extra["new_geo"] = True    -> logon from a location new for that user
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import timedelta

from .schema import Event, Session, Alert


class Rule(ABC):
    name: str
    description: str
    severity: str = "medium"

    @abstractmethod
    def evaluate(self, session: Session) -> list[Alert]:
        ...

    def _make_alert(self, events: list[Event], host: str, user: str | None) -> Alert:
        return Alert(
            rule_name=self.name,
            description=self.description,
            events=events,
            host=host,
            user=user,
            severity=self.severity,
        )


class BruteForceRule(Rule):
    """Failed logins followed by a success = possible brute force."""

    name = "brute_force_then_success"
    description = "Multiple failed logon attempts followed by a successful logon"
    severity = "high"
    min_failures = 3

    def evaluate(self, session: Session) -> list[Alert]:
        alerts = []
        failures: list[Event] = []
        for event in session.events:
            if event.event_id == "4625":
                failures.append(event)
            elif event.event_id == "4624" and len(failures) >= self.min_failures:
                alerts.append(self._make_alert(failures + [event], session.host, session.user))
                failures = []
            elif event.event_id == "4624":
                failures = []  # success without enough prior failures resets the count
        return alerts


class PhishingPayloadRule(Rule):
    """PowerShell spawned by Word = possible phishing payload."""

    name = "office_spawned_powershell"
    description = "A scripting interpreter was spawned by an Office application"
    severity = "high"
    _office_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    _scripting_children = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"}

    def evaluate(self, session: Session) -> list[Alert]:
        alerts = []
        for event in session.events:
            if event.event_id != "1" or not event.process:
                continue
            parent = (event.extra.get("parent_process") or "").lower()
            child = event.process.lower()
            if parent in self._office_parents and child in self._scripting_children:
                alerts.append(self._make_alert([event], session.host, session.user))
        return alerts


class PrivilegeEscalationRule(Rule):
    """New account creation immediately followed by admin-group membership."""

    name = "new_account_added_to_admins"
    description = "A newly created account was added to a privileged group"
    severity = "critical"
    max_gap = timedelta(minutes=30)

    def evaluate(self, session: Session) -> list[Alert]:
        alerts = []
        created: Event | None = None
        for event in session.events:
            if event.event_id == "4720":
                created = event
            elif event.event_id == "4732" and created is not None:
                if event.timestamp - created.timestamp <= self.max_gap:
                    alerts.append(self._make_alert([created, event], session.host, session.user))
                created = None
        return alerts


class ImpossibleTravelRule(Rule):
    """Logon from a new/unusual location followed by suspicious activity."""

    name = "new_location_then_execution"
    description = "Logon from a location new for this user, followed by process execution"
    severity = "high"
    max_gap = timedelta(minutes=15)

    def evaluate(self, session: Session) -> list[Alert]:
        alerts = []
        new_geo_logon: Event | None = None
        for event in session.events:
            if event.event_id == "4624" and event.extra.get("new_geo"):
                new_geo_logon = event
            elif event.event_id == "1" and new_geo_logon is not None:
                if event.timestamp - new_geo_logon.timestamp <= self.max_gap:
                    alerts.append(self._make_alert([new_geo_logon, event], session.host, session.user))
                new_geo_logon = None
        return alerts


class LateralMovementRule:
    """
    Same user authenticating successfully on several distinct hosts in
    a short overall window — a cross-session pattern, so it operates
    on all sessions at once rather than one session in isolation.
    """

    name = "lateral_movement_multi_host_logon"
    description = "The same user authenticated on multiple distinct hosts in a short window"
    severity = "critical"
    min_hosts = 3
    window = timedelta(minutes=20)

    def evaluate_all(self, sessions: list[Session]) -> list[Alert]:
        by_user: dict[str, list[Event]] = {}
        for session in sessions:
            if not session.user:
                continue
            for event in session.events:
                if event.event_id == "4624":
                    by_user.setdefault(session.user, []).append(event)

        alerts = []
        for user, logons in by_user.items():
            logons.sort(key=lambda e: e.timestamp)
            i = 0
            for j in range(len(logons)):
                while logons[j].timestamp - logons[i].timestamp > self.window:
                    i += 1
                window_events = logons[i:j + 1]
                hosts = {e.host for e in window_events}
                if len(hosts) >= self.min_hosts:
                    alerts.append(
                        Alert(
                            rule_name=self.name,
                            description=self.description,
                            events=list(window_events),
                            host=window_events[-1].host,
                            user=user,
                            severity=self.severity,
                        )
                    )
                    i = j + 1  # avoid overlapping re-alerts on the same run
        return alerts


DEFAULT_RULES: list[Rule] = [
    BruteForceRule(),
    PhishingPayloadRule(),
    PrivilegeEscalationRule(),
    ImpossibleTravelRule(),
]

DEFAULT_CROSS_SESSION_RULES = [LateralMovementRule()]


def run_rules(
    sessions: list[Session],
    rules: list[Rule] = None,
    cross_session_rules: list = None,
) -> list[Alert]:
    """Run every per-session rule against every session, plus any
    cross-session rules against the full set of sessions."""
    rules = rules if rules is not None else DEFAULT_RULES
    cross_session_rules = (
        cross_session_rules if cross_session_rules is not None else DEFAULT_CROSS_SESSION_RULES
    )

    alerts: list[Alert] = []
    for session in sessions:
        for rule in rules:
            alerts.extend(rule.evaluate(session))

    for rule in cross_session_rules:
        alerts.extend(rule.evaluate_all(sessions))

    return alerts
