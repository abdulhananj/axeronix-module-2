"""
Unified Command Line Interface for Module 2.
Run the engine on custom logs or sample data, and choose the output format.

Usage:
  python cli.py                               # Runs sample data, prints detailed incident & kill chain to screen
  python cli.py logs.json                     # Runs custom logs, saves standard incident JSON, prints 1-line summary
  python cli.py logs.json --format module7    # Runs custom logs, saves Module 7 graph files
"""

import argparse
import json
import csv
import sys
from pathlib import Path

from correlation_engine import CorrelationEngine
from correlation_engine.schema import Event
from correlation_engine.sample_data import full_sample_dataset
from correlation_engine.graph_export import to_module7_input

def load_events_from_file(path: Path) -> list[Event]:
    """Load events from a JSON or CSV file."""
    with open(path) as f:
        if path.suffix.lower() == ".json":
            raw = json.load(f)
        elif path.suffix.lower() == ".csv":
            reader = csv.DictReader(f)
            # Convert empty strings to None for optional fields
            raw = [{k: (v if v != "" else None) for k, v in row.items()} for row in reader]
        else:
            raise ValueError("Unsupported file type. Use .json or .csv")
    return [Event.from_dict(row) for row in raw]

def main():
    parser = argparse.ArgumentParser(description="AXERONIX Module 2: Event Correlation Engine CLI")
    parser.add_argument("file", nargs="?", help="Path to logs file (JSON or CSV). If omitted, runs built-in sample data.")
    parser.add_argument("--format", choices=["standard", "module7"], default="standard", 
                        help="Output format: 'standard' for AI/Timeline modules, 'module7' for Attack Graph module.")
    
    args = parser.parse_args()

    # 1. Load Events
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: File not found at {path}")
            sys.exit(1)
        print(f"\nLoading logs from {path}...")
        events = load_events_from_file(path)
    else:
        print("\nNo file provided. Using built-in sample attack data...")
        events = full_sample_dataset()

    # 2. Run Engine
    print(f"Feeding {len(events)} events to the Correlation Engine...")
    engine = CorrelationEngine()
    incidents = engine.run(events)
    print(f"Engine generated {len(incidents)} correlated incident(s).\n")

    # 3. Handle Output Format
    if args.format == "module7":
        print("Exporting to Module 7 (Attack Graph) format...")
        output_dir = Path("module7_export")
        output_dir.mkdir(exist_ok=True)
        
        for inc in incidents:
            inc_dict, timeline_dict = to_module7_input(inc)
            stem = f"incident_{inc.incident_id.lower()}"
            
            inc_path = output_dir / f"{stem}.json"
            tl_path = output_dir / f"{stem}_timeline.json"
            
            inc_path.write_text(json.dumps(inc_dict, indent=2))
            tl_path.write_text(json.dumps(timeline_dict, indent=2))
            
            print(f"  -> {inc_path}")
            print(f"  -> {tl_path}")
            
    else: # standard
        if not args.file:
            # If just running sample data with no file, print detailed output to screen
            print("=" * 70)
            for inc in incidents:
                d = inc.to_dict()
                print(f"INCIDENT {d['incident_id']}  [{d['severity'].upper()}]")
                print(f"  Hosts: {d['hosts']} | Users: {d['users']}")
                for a in d["alerts"]:
                    print(f"  - [{a['severity']}] {a['rule_name']}")
                
                # Print the Kill Chain Narrative
                if d.get("kill_chain"):
                    print("\n  Kill Chain Narrative:")
                    for step in d["kill_chain"]:
                        tech = f"  ({step['technique_hint']})" if step.get("technique_hint") else ""
                        print(f"    [{step['stage']:<23}] {tech}")
                        print(f"      -> {step['raw_message']}")
                print("=" * 70)
        else:
            # If a file was provided, save the full JSON output for downstream modules
            out_path = Path(args.file).with_name(Path(args.file).stem + "_incidents.json")
            with open(out_path, "w") as f:
                json.dump([inc.to_dict() for inc in incidents], f, indent=2)
            
            # Print a clean, smart summary to the terminal to prevent wrapping/fatigue
            print("=" * 70)
            print(f"Saved full JSON to: {out_path}")
            print(f"Summary of {len(incidents)} incident(s):")
            print("-" * 70)
            for inc in incidents:
                d = inc.to_dict()
                
                # 1. Deduplicate rules (if a rule fired 5 times, only show it once)
                unique_rules = list(set(a['rule_name'] for a in d['alerts']))
                rules_str = ", ".join(unique_rules)
                
                # 2. Truncate hosts list so it doesn't wrap and break the terminal
                if len(d['hosts']) > 3:
                    hosts_str = ", ".join(d['hosts'][:3]) + f" (+{len(d['hosts'])-3} more)"
                else:
                    hosts_str = ", ".join(d['hosts'])
                
                print(f" [{d['severity'].upper():<8}] {d['incident_id']} | Hosts: {hosts_str}")
                print(f"           Rules: {rules_str}")
            print("=" * 70)

if __name__ == "__main__":
    main()
