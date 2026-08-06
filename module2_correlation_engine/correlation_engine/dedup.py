"""
Step 2 — Deduplication

The same alert often fires many times for the same underlying
activity (a scanner probing 200 ports triggers 200 near-identical
alerts). Collapse repeats of the same alert type, same host, same
short time window into one entry with a count.
"""

from __future__ import annotations

from .schema import Alert

DEFAULT_DEDUP_WINDOW_SECONDS = 60


def deduplicate_alerts(
    alerts: list[Alert],
    window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
) -> list[Alert]:
    """
    Collapse alerts that share the same rule, host, user, and a coarse
    time bucket into a single Alert, folding in all underlying events
    as evidence and incrementing `count`.
    """
    buckets: dict[tuple, Alert] = {}
    ordered = sorted(alerts, key=lambda a: a.start_time)

    for alert in ordered:
        dkey = alert.dedup_key(window_seconds)
        existing = buckets.get(dkey)

        if existing is None:
            buckets[dkey] = alert
            continue

        existing.events.extend(alert.events)
        existing.count += alert.count
        # keep the more severe label if duplicates disagree
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if severity_order.get(alert.severity, 0) > severity_order.get(existing.severity, 0):
            existing.severity = alert.severity

    return sorted(buckets.values(), key=lambda a: a.start_time)
