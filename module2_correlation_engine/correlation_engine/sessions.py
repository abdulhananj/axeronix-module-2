"""
Step 1 — Time-window grouping
Step 5 — Session creation (the formalized version of Step 1)

Before anything clever: group events from the same host within a
short window into one "session." This alone removes a huge amount of
noise and is the foundation everything else builds on.
"""

from __future__ import annotations

from .schema import Event, Session

DEFAULT_WINDOW_SECONDS = 5 * 60  # 5-minute window, per the build guide


def build_sessions(
    events: list[Event],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[Session]:
    """
    Group events into sessions: same host, and — if present — same
    user, where consecutive events are no more than `window_seconds`
    apart. A gap larger than the window starts a new session even on
    the same host, so a quiet host from yesterday doesn't get merged
    with new activity today.

    Events must already be timestamp-normalized to UTC (Module 1's
    job) — this function trusts `event.timestamp` as comparable.
    """
    if not events:
        return []

    ordered = sorted(events, key=lambda e: e.timestamp)

    # group key: (host, user) — None user still buckets consistently
    open_sessions: dict[tuple, list[Event]] = {}
    sessions: list[Session] = []

    for event in ordered:
        key = (event.host, event.user)
        bucket = open_sessions.get(key)

        if bucket is None:
            open_sessions[key] = [event]
            continue

        gap = (event.timestamp - bucket[-1].timestamp).total_seconds()
        if gap <= window_seconds:
            bucket.append(event)
        else:
            sessions.append(Session(host=key[0], user=key[1], events=bucket))
            open_sessions[key] = [event]

    for (host, user), bucket in open_sessions.items():
        sessions.append(Session(host=host, user=user, events=bucket))

    return sorted(sessions, key=lambda s: s.start_time)
