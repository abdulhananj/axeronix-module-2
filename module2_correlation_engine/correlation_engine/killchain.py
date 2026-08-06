"""
Step 6 — Kill-chain generation (built last, on top of stable grouping)

Map each event inside an incident to a stage of the Cyber Kill Chain /
MITRE ATT&CK tactic. This turns a pile of grouped events into a
labeled attack narrative — the payoff step.

Kept as an explicit lookup table (event_id / process signature ->
stage), not a model, per the "explainable over clever" ground rule.
"""

from __future__ import annotations

from .schema import Event, Incident, KillChainStep

# (event_id, condition) -> (kill-chain stage, MITRE technique hint)
_EVENT_ID_STAGES: dict[str, tuple[str, str]] = {
    "4625": ("Reconnaissance", "T1110 Brute Force (attempt)"),
    "4624": ("Initial Access", "T1078 Valid Accounts"),
    "4720": ("Persistence", "T1136 Create Account"),
    "4732": ("Privilege Escalation", "T1098 Account Manipulation"),
}

_PROCESS_STAGES: dict[str, tuple[str, str]] = {
    "powershell.exe": ("Execution", "T1059.001 PowerShell"),
    "cmd.exe": ("Execution", "T1059.003 Windows Command Shell"),
    "wscript.exe": ("Execution", "T1059.005 Visual Basic"),
    "mshta.exe": ("Execution", "T1218.005 Mshta"),
}


def _classify(event: Event) -> tuple[str, str | None]:
    if event.event_id in _EVENT_ID_STAGES:
        return _EVENT_ID_STAGES[event.event_id]

    if event.event_id == "1" and event.process:
        proc = event.process.lower()
        if proc in _PROCESS_STAGES:
            stage, technique = _PROCESS_STAGES[proc]
            parent = (event.extra.get("parent_process") or "").lower()
            if parent in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}:
                return "Initial Access", "T1566 Phishing"
            return stage, technique

    if event.extra.get("new_geo"):
        return "Initial Access", "T1078 Valid Accounts (anomalous geo)"

    return "Uncategorized", None


def build_kill_chain(incident: Incident) -> list[KillChainStep]:
    """Label every event in an incident with a kill-chain stage,
    ordered chronologically."""
    all_events = [e for alert in incident.alerts for e in alert.events]
    # de-dupe by identity while preserving order
    seen = set()
    unique_events = []
    for e in sorted(all_events, key=lambda ev: ev.timestamp):
        k = (e.timestamp, e.host, e.event_id, e.raw_message)
        if k not in seen:
            seen.add(k)
            unique_events.append(e)

    steps = []
    for event in unique_events:
        stage, technique = _classify(event)
        steps.append(KillChainStep(event=event, stage=stage, technique_hint=technique))
    return steps
