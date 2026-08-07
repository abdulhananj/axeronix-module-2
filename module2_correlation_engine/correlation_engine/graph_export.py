"""
Export adapter: Module 2's `Incident` -> Module 7's expected input shape.

Module 7's `engine/adapter.py` (their code, not ours) expects two dicts:

  incident  = {"incident_id", "title", "kill_chain_summary", "severity",
               "events": [{"event_id", "event_type", "timestamp",
                           "kill_chain_stage", "host", "user", ...}, ...]}

  timeline  = {"incident_id", "timeline": [{"seq", "event_id", "timestamp",
                                             "host", "label", "description"}, ...]}

That's a different shape than `Incident.to_dict()` (which is organized by
alert, not by flat timeline). This module is the translation layer — nothing
in the rest of the engine changes, per the "engine emits its own honest
shape, adapters translate at the boundary" approach.

Two things Module 7 needs that our internal Event doesn't naturally carry:

1. **A unique event_id per event instance.** Our `Event.event_id` holds the
   *type* code (e.g. "4625" for every failed logon), not a unique instance
   ID — multiple events legitimately share it. Module 7 needs one ID per
   event instance (their mocks use "evt-1001", "evt-1002", ...), so this
   adapter mints one per event, in kill-chain order, and keeps the original
   type code under `event_type` instead.

2. **`event_type` values from their vocabulary**, not ours. We map our
   Windows-style `event_id` codes (plus Sysmon process-creation context) onto
   their rule-table vocabulary (`logon_failed`, `logon_success`,
   `process_create`, ...). An event_id with no mapping still gets exported
   (as `event_type: "unclassified"`) rather than dropped — Module 7's own
   adapter already logs and skips unknown event_types without erroring, so
   under-mapping degrades gracefully instead of losing evidence.
"""

from __future__ import annotations

from .schema import Event, Incident, KillChainStep

# --------------------------------------------------------------------------
# Windows/Sysmon event_id -> Module 7's event_type vocabulary.
# Only event_ids this engine's rules.py actually produces are mapped; add to
# this table as new rules are added to rules.py.
# --------------------------------------------------------------------------
_EVENT_TYPE_MAP: dict[str, str] = {
    "4625": "logon_failed",
    "4624": "logon_success",
    "4720": "account_created",           # no Module 7 rule yet — still exported
    "4732": "group_membership_changed",  # no Module 7 rule yet — still exported
    "1": "process_create",               # Sysmon process creation
}

# --------------------------------------------------------------------------
# Our kill-chain stage labels -> MITRE-style snake_case slugs, matching the
# convention Module 7's mocks use (credential_access, initial_access, ...).
# --------------------------------------------------------------------------
_STAGE_SLUG_MAP: dict[str, str] = {
    "Reconnaissance": "reconnaissance",
    "Initial Access": "initial_access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege_escalation",
    "Uncategorized": "unknown",
}

# Extra fields Module 7's rules read off individual events, by event_type.
# Only pulled from `event.extra` if present — everything is optional, per
# their adapter's own tolerance for missing fields.
_EXTRA_FIELDS_BY_TYPE: dict[str, list[str]] = {
    "logon_failed": ["src_ip", "logon_type", "failure_count"],
    "logon_success": ["src_ip", "src_host", "logon_type"],
    "process_create": ["parent_process", "parent_process_id", "process_id", "cmdline"],
    "account_created": [],
    "group_membership_changed": ["target_group"],
}


def _event_type_for(event: Event) -> str:
    return _EVENT_TYPE_MAP.get(event.event_id, "unclassified")


def _stage_slug_for(stage: str) -> str:
    return _STAGE_SLUG_MAP.get(stage, "unknown")


def _label_for(event: Event, stage: str) -> str:
    """Short human label for the timeline entry — Module 6's job normally,
    approximated here so the exported timeline is immediately readable."""
    return f"{stage}: {event.raw_message}"[:80]


def _auto_title(incident: Incident) -> str:
    """'<first rule> to <last rule>', matching the style of Module 7's own
    mock incident titles (e.g. 'VPN Brute Force to Privilege Escalation')."""
    alerts_by_time = sorted(incident.alerts, key=lambda a: a.start_time)
    first = alerts_by_time[0].rule_name.replace("_", " ").title()
    last = alerts_by_time[-1].rule_name.replace("_", " ").title()
    return first if first == last else f"{first} to {last}"


def _auto_summary(incident: Incident) -> str:
    alerts_by_time = sorted(incident.alerts, key=lambda a: a.start_time)
    return "; then ".join(a.description for a in alerts_by_time)


def to_module7_input(incident: Incident, title: str | None = None) -> tuple[dict, dict]:
    """
    Convert one Incident into (incident_dict, timeline_dict) matching
    Module 7's `engine.adapter.build(incident, timeline)` signature exactly.
    """
    events_out: list[dict] = []
    timeline_out: list[dict] = []

    for seq, step in enumerate(incident.kill_chain, start=1):
        event: Event = step.event
        event_id = f"evt-{incident.incident_id.split('-')[-1]}-{seq:04d}"
        event_type = _event_type_for(event)
        stage_slug = _stage_slug_for(step.stage)
        ts = event.timestamp.isoformat()

        entry: dict = {
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": ts,
            "kill_chain_stage": stage_slug,
            "host": event.host,
        }
        if event.user:
            entry["user"] = event.user
        if event.process:
            entry["process"] = event.process

        for field in _EXTRA_FIELDS_BY_TYPE.get(event_type, []):
            if field in event.extra and event.extra[field] is not None:
                entry[field] = event.extra[field]

        events_out.append(entry)
        timeline_out.append({
            "seq": seq,
            "event_id": event_id,
            "timestamp": ts,
            "host": event.host,
            "label": _label_for(event, step.stage),
            "description": event.raw_message,
        })

    incident_out = {
        "incident_id": incident.incident_id,
        "title": title or _auto_title(incident),
        "kill_chain_summary": _auto_summary(incident),
        "severity": incident.severity,
        "events": events_out,
    }
    timeline_dict = {"incident_id": incident.incident_id, "timeline": timeline_out}

    return incident_out, timeline_dict
