"""
Export Module 2's incidents as the incident/timeline file pairs Module 7's
`engine.data_source._load_from_files()` expects — same naming convention as
their own mocks/ directory (`incident_<name>.json` +
`incident_<name>_timeline.json`), so the output of this script can be
dropped straight into their `mocks/` folder and picked up with zero changes
on their side.

Usage:
    python export_to_module7.py                      # uses the built-in sample attack
    python export_to_module7.py your_logs.json        # uses your own log file
    python export_to_module7.py your_logs.json my_incident   # custom output name
"""

import json
import sys
from pathlib import Path

from correlation_engine import CorrelationEngine
from correlation_engine.schema import Event
from correlation_engine.sample_data import full_sample_dataset
from correlation_engine.module7_export import to_module7_input

OUTPUT_DIR = Path(__file__).parent / "module7_export"


def load_events_from_file(path: Path) -> list[Event]:
    with open(path) as f:
        raw = json.load(f)
    return [Event.from_dict(row) for row in raw]


def main():
    if len(sys.argv) >= 2:
        events = load_events_from_file(Path(sys.argv[1]))
        print(f"Loaded {len(events)} events from {sys.argv[1]}")
    else:
        events = full_sample_dataset()
        print(f"Using built-in sample dataset ({len(events)} events)")

    name_override = sys.argv[2] if len(sys.argv) >= 3 else None

    engine = CorrelationEngine()
    incidents = engine.run(events)
    print(f"Correlated into {len(incidents)} incident(s)\n")

    OUTPUT_DIR.mkdir(exist_ok=True)

    for i, incident in enumerate(incidents):
        incident_dict, timeline_dict = to_module7_input(incident)

        if name_override:
            stem = name_override if len(incidents) == 1 else f"{name_override}_{i+1}"
        else:
            stem = f"incident_{incident.incident_id.lower()}"

        incident_path = OUTPUT_DIR / f"{stem}.json"
        timeline_path = OUTPUT_DIR / f"{stem}_timeline.json"

        incident_path.write_text(json.dumps(incident_dict, indent=2))
        timeline_path.write_text(json.dumps(timeline_dict, indent=2))

        print(f"  {incident_dict['title']}")
        print(f"    -> {incident_path}")
        print(f"    -> {timeline_path}")

    print(f"\nDrop these into module7-engine/mocks/ (or point their")
    print(f"engine.data_source at this folder) to load them by name, e.g.:")
    print(f"  from engine.data_source import load_incident")
    print(f"  incident, timeline = load_incident('<stem above>', source='files')")


if __name__ == "__main__":
    main()
