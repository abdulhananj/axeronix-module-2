"""
Run this to see Module 2 do its job end to end:

    python demo.py

It feeds the engine the exact scenario from the module documentation's
"Expected Output" box (failed logins -> success -> PowerShell ->
new admin account) plus a noisy port scan and a lateral-movement
pattern, and prints what comes out: correlated incidents, not a pile
of raw alerts.
"""

from correlation_engine import CorrelationEngine
from correlation_engine.sample_data import full_sample_dataset
from correlation_engine.store import IncidentStore


def main():
    events = full_sample_dataset()
    print(f"Fed the engine {len(events)} raw events.\n")

    engine = CorrelationEngine()
    incidents = engine.run(events)

    print(f"Sessions built:        {len(engine.last_sessions)}")
    print(f"Raw alerts fired:      {len(engine.last_raw_alerts)}")
    print(f"Alerts after dedup:    {len(engine.last_deduped_alerts)}")
    print(f"Correlated incidents:  {len(incidents)}\n")
    print("=" * 70)

    for inc in incidents:
        d = inc.to_dict()
        print(f"\nINCIDENT {d['incident_id']}  [{d['severity'].upper()}]")
        print(f"  hosts: {d['hosts']}   users: {d['users']}")
        print(f"  window: {d['start_time']} -> {d['end_time']}")
        print(f"  {len(d['alerts'])} alert(s):")
        for a in d["alerts"]:
            count_note = f" (x{a['count']})" if a["count"] > 1 else ""
            print(f"    - [{a['severity']}] {a['rule_name']}{count_note}: {a['description']}")
        if d["kill_chain"]:
            print("  kill chain:")
            for step in d["kill_chain"]:
                tech = f"  ({step['technique_hint']})" if step["technique_hint"] else ""
                print(f"    {step['timestamp']}  {step['stage']:<20}{tech}")
                print(f"        -> {step['raw_message']}")

    print("\n" + "=" * 70)
    store = IncidentStore()  # no redis_url given -> in-memory fallback
    store.save_all(incidents)
    print(f"\nSaved {len(incidents)} incident(s) to the '{store.backend}' store.")


if __name__ == "__main__":
    main()
