"""
Small, fake sample dataset — the "small, fake sample dataset" the
ground rules ask every module to have, so this module can be tested
without waiting on a real Module 1 feed.

Scenario matches the doc's own "Expected Output" for Module 2:
failed logins, then a successful login, then PowerShell execution
(spawned by Word), then a new admin user creation — which should
collapse into ONE correlated incident, not four separate alerts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .schema import Event

_T0 = datetime(2026, 7, 29, 8, 0, 0, tzinfo=timezone.utc)


def brute_force_then_compromise() -> list[Event]:
    """failed logins -> success -> phishing payload -> privilege escalation"""
    host = "WKSTN-042"
    user = "jsmith"
    events = []

    # 4 failed logons, 20s apart
    for i in range(4):
        events.append(Event(
            timestamp=_T0 + timedelta(seconds=20 * i),
            host=host, source_type="windows", event_id="4625",
            raw_message="An account failed to log on",
            user=user,
        ))

    # successful logon, flagged as a new geo for this user
    events.append(Event(
        timestamp=_T0 + timedelta(seconds=100),
        host=host, source_type="windows", event_id="4624",
        raw_message="An account was successfully logged on",
        user=user, extra={"new_geo": True},
    ))

    # Word opens, then spawns PowerShell (phishing payload)
    events.append(Event(
        timestamp=_T0 + timedelta(minutes=2),
        host=host, source_type="windows_sysmon", event_id="1",
        raw_message="Process Create: WINWORD.EXE",
        user=user, process="winword.exe",
    ))
    events.append(Event(
        timestamp=_T0 + timedelta(minutes=2, seconds=10),
        host=host, source_type="windows_sysmon", event_id="1",
        raw_message="Process Create: powershell.exe -enc <base64>",
        user=user, process="powershell.exe",
        extra={"parent_process": "winword.exe"},
    ))

    # new account created, then added to the local admins group
    events.append(Event(
        timestamp=_T0 + timedelta(minutes=4),
        host=host, source_type="windows", event_id="4720",
        raw_message="A user account was created: svc_update",
        user=user,
    ))
    events.append(Event(
        timestamp=_T0 + timedelta(minutes=4, seconds=30),
        host=host, source_type="windows", event_id="4732",
        raw_message="A member was added to a security-enabled local group: Administrators",
        user=user,
    ))

    return events


def noisy_port_scan() -> list[Event]:
    """A scanner probing many ports — should collapse via dedup, not
    become 40 separate incidents."""
    host = "FW-EDGE-01"
    events = []
    for i in range(40):
        events.append(Event(
            timestamp=_T0 + timedelta(seconds=2 * i),
            host=host, source_type="firewall", event_id="4625",
            raw_message=f"Connection blocked to port {5000 + i}",
            user=None,
        ))
    return events


def lateral_movement() -> list[Event]:
    """Same user, successful logons on 4 distinct hosts within minutes —
    should trigger the cross-session lateral-movement rule."""
    user = "asmith-svc"
    hosts = ["HOST-A", "HOST-B", "HOST-C", "HOST-D"]
    events = []
    for i, host in enumerate(hosts):
        events.append(Event(
            timestamp=_T0 + timedelta(hours=6, minutes=3 * i),
            host=host, source_type="windows", event_id="4624",
            raw_message="An account was successfully logged on",
            user=user,
        ))
    return events


def full_sample_dataset() -> list[Event]:
    """The combined dataset used by demo.py and the test suite."""
    return brute_force_then_compromise() + noisy_port_scan() + lateral_movement()
