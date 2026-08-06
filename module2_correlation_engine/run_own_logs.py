"""
Run the Correlation Engine against YOUR OWN logs instead of the
built-in sample dataset.

Your logs need to already be in Module 1's normalized shape:
  timestamp, host, source_type, event_id, raw_message, [user], [process]

Two input formats are supported out of the box:

  1. JSON — a file containing a JSON array of objects, e.g.:
     [
       {"timestamp": "2026-07-29T08:00:00Z", "host": "WKSTN-042",
        "source_type": "windows", "event_id": "4625",
        "raw_message": "An account failed to log on", "user": "jsmith"},
       ...
     ]

  2. CSV — a file with a header row matching the same field names:
     timestamp,host,source_type,event_id,raw_message,user,process
     2026-07-29T08:00:00Z,WKSTN-042,windows,4625,An account failed...,jsmith,

Usage:
    python run_own_logs.py path/to/your_logs.json
    python run_own_logs.py path/to/your_logs.csv
"""

import csv
import json
import sys
from pathlib import Path

from correlation_engine import CorrelationEngine
from correlation_engine.schema import Event
from correlation_engine.store import IncidentStore


def load_events_from_json(path: Path) -> list[Event]:
    with open(path) as f:
        raw = json.load(f)
    return [Event.from_dict(row) for row in raw]


def load_events_from_csv(path: Path) -> list[Event]:
    events = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            # drop empty optional fields so they come through as None,
            # not empty strings
            cleaned = {k: (v if v not in ("", None) else None) for k, v in row.items()}
            events.append(Event.from_dict(cleaned))
    return events


def load_events(path: Path) -> list[Event]:
    if path.suffix.lower() == ".json":
        return load_events_from_json(path)
    elif path.suffix.lower() == ".csv":
        return load_events_from_csv(path)
    else:
        raise ValueError(f"Unsupported file type: {path.suffix} (use .json or .csv)")


def main():
    if len(sys.argv) != 2:
        print("Usage: python run_own_logs.py path/to/your_logs.(json|csv)")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    events = load_events(path)
    print(f"Loaded {len(events)} events from {path}\n")

    engine = CorrelationEngine()
    incidents = engine.run(events)

    print(f"Sessions built:        {len(engine.last_sessions)}")
    print(f"Raw alerts fired:      {len(engine.last_raw_alerts)}")
    print(f"Alerts after dedup:    {len(engine.last_deduped_alerts)}")
    print(f"Correlated incidents:  {len(incidents)}\n")

    for inc in incidents:
        d = inc.to_dict()
        print(f"INCIDENT {d['incident_id']}  [{d['severity'].upper()}]")
        print(f"  hosts: {d['hosts']}   users: {d['users']}")
        for a in d["alerts"]:
            print(f"    - [{a['severity']}] {a['rule_name']}: {a['description']}")
        print()

    # save + also dump full JSON so you can inspect/hand off the exact
    # payload another module would receive
    store = IncidentStore()
    store.save_all(incidents)

    out_path = path.with_name(path.stem + "_incidents.json")
    with open(out_path, "w") as f:
        json.dump([inc.to_dict() for inc in incidents], f, indent=2)
    print(f"Full incident JSON written to: {out_path}")


if __name__ == "__main__":
    main()
