"""
CorrelationEngine — orchestrates the full pipeline in build order:

  1. Time-window grouping  -> sessions.build_sessions
  2. Deduplication          -> dedup.deduplicate_alerts   (applied to alerts)
  3. Hand-authored rules    -> rules.run_rules
  4. Alert grouping         -> grouping.group_alerts_into_incidents
  5. Session creation       -> (folded into step 1's build_sessions)
  6. Kill-chain generation  -> killchain.build_kill_chain

Runtime order differs slightly from build order because rules need
sessions to exist before they can fire, and dedup makes more sense
applied to the alerts rules produce than to raw events. The build
guide itself builds dedup before rules for learning purposes; running
it after rules is the correct place for it in the live pipeline.
"""

from __future__ import annotations

from .schema import Event, Session, Alert, Incident
from .sessions import build_sessions, DEFAULT_WINDOW_SECONDS
from .dedup import deduplicate_alerts, DEFAULT_DEDUP_WINDOW_SECONDS
from .rules import run_rules, DEFAULT_RULES, DEFAULT_CROSS_SESSION_RULES
from .grouping import group_alerts_into_incidents, DEFAULT_GROUPING_WINDOW
from .killchain import build_kill_chain


class CorrelationEngine:
    """
    Usage:
        engine = CorrelationEngine()
        incidents = engine.run(events)
        for inc in incidents:
            print(inc.to_dict())
    """

    def __init__(
        self,
        session_window_seconds: int = DEFAULT_WINDOW_SECONDS,
        dedup_window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
        grouping_window=DEFAULT_GROUPING_WINDOW,
        rules=None,
        cross_session_rules=None,
    ):
        self.session_window_seconds = session_window_seconds
        self.dedup_window_seconds = dedup_window_seconds
        self.grouping_window = grouping_window
        self.rules = rules if rules is not None else DEFAULT_RULES
        self.cross_session_rules = (
            cross_session_rules if cross_session_rules is not None else DEFAULT_CROSS_SESSION_RULES
        )

        # last-run intermediate state, exposed for debugging / tests
        self.last_sessions: list[Session] = []
        self.last_raw_alerts: list[Alert] = []
        self.last_deduped_alerts: list[Alert] = []

    def run(self, events: list[Event]) -> list[Incident]:
        # Step 1 / 5 — time-window grouping into sessions
        sessions = build_sessions(events, window_seconds=self.session_window_seconds)
        self.last_sessions = sessions

        # Step 3 — hand-authored rules fire against each session
        raw_alerts = run_rules(sessions, rules=self.rules, cross_session_rules=self.cross_session_rules)
        self.last_raw_alerts = raw_alerts

        # Step 2 — dedup repeats of the same alert
        deduped_alerts = deduplicate_alerts(raw_alerts, window_seconds=self.dedup_window_seconds)
        self.last_deduped_alerts = deduped_alerts

        # Step 4 — group related alerts into incidents
        incidents = group_alerts_into_incidents(deduped_alerts, window=self.grouping_window)

        # Step 6 — kill-chain mapping, built last
        for incident in incidents:
            incident.kill_chain = build_kill_chain(incident)

        return incidents
