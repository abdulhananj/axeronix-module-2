"""
Step 4 — Alert grouping

Take the individual alerts the rules generated and group ones that
share a host, user, or time window into a single incident object —
this is what Module 3 (AI Investigation) and Module 6 (Timeline)
actually consume.
"""

from __future__ import annotations

from datetime import timedelta

from .schema import Alert, Incident

DEFAULT_GROUPING_WINDOW = timedelta(hours=1)


def group_alerts_into_incidents(
    alerts: list[Alert],
    window: timedelta = DEFAULT_GROUPING_WINDOW,
) -> list[Incident]:
    """
    Union-find style grouping: two alerts merge into the same incident
    if they share a host OR a user AND their time ranges are within
    `window` of each other. Transitive merges are followed (if A links
    to B and B links to C, all three end up in one incident) so a
    multi-stage attack that touches several hosts still becomes one
    story instead of splintering by host.
    """
    if not alerts:
        return []

    ordered = sorted(alerts, key=lambda a: a.start_time)
    parent = list(range(len(ordered)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    def related(a: Alert, b: Alert) -> bool:
        shares_entity = a.host == b.host or (a.user is not None and a.user == b.user)
        if not shares_entity:
            return False
        gap = max(a.start_time, b.start_time) - min(a.end_time, b.end_time)
        return gap <= window

    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            # once alert j starts more than `window` past alert i's end
            # with no shared entity possible in between, later j's will
            # only be farther away — but hosts/users vary, so just cap
            # the search distance instead of a hard break for simplicity
            if ordered[j].start_time - ordered[i].end_time > window * 4:
                break
            if related(ordered[i], ordered[j]):
                union(i, j)

    groups: dict[int, list[Alert]] = {}
    for idx, alert in enumerate(ordered):
        groups.setdefault(find(idx), []).append(alert)

    incidents = [Incident(alerts=group) for group in groups.values()]
    return sorted(incidents, key=lambda inc: inc.start_time)
