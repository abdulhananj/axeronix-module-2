# module_2_correlation_engine/worker.py
"""
The continuous service loop for Module 2.
Pulls events from Module 1, runs the CorrelationEngine, 
and pushes Incidents to downstream modules (3, 6, 7, 10).
"""
import time
import json
import redis
from datetime import datetime, timezone

from correlation_engine import CorrelationEngine
from correlation_engine.schema import Event
from correlation_engine.graph_export import to_module7_input

# Connect to the central platform Redis (used by all modules for message passing)
r = redis.Redis(host='localhost', port=6379, decode_responses=True)
engine = CorrelationEngine()

INPUT_QUEUE = "axeronix:module_1:events"
OUTPUT_QUEUE_3 = "axeronix:module_3:incidents"  # AI Investigation
OUTPUT_QUEUE_6 = "axeronix:module_6:incidents"  # Timeline
OUTPUT_QUEUE_7 = "axeronix:module_7:incidents"  # Attack Graph

def run_micro_batch():
    """Pulls all waiting events from Module 1 and processes them."""
    events_to_process = []
    
    # Pull up to 500 events at a time so we don't overload memory
    while True:
        packed = r.lpop(INPUT_QUEUE)
        if not packed:
            break
        event_dict = json.loads(packed)
        events_to_process.append(Event.from_dict(event_dict))
        
    if not events_to_process:
        return 0

    # Run your excellent engine logic
    incidents = engine.run(events_to_process)

    # Emit the resulting incidents to the downstream modules
    for inc in incidents:
        # 1. Standard JSON output (for Modules 3, 6, and 10)
        standard_json = json.dumps(inc.to_dict())
        r.lpush(OUTPUT_QUEUE_3, standard_json)
        r.lpush(OUTPUT_QUEUE_6, standard_json)
        
        # 2. Module 7 specific output (using your brilliant adapter!)
        inc_dict, timeline_dict = to_module7_input(inc)
        module7_payload = json.dumps({"incident": inc_dict, "timeline": timeline_dict})
        r.lpush(OUTPUT_QUEUE_7, module7_payload)
        
        print(f"[+] Emitted Incident {inc.incident_id} to downstream modules.")

    return len(incidents)

if __name__ == "__main__":
    print("Module 2 Worker started. Listening for events from Module 1...")
    while True:
        incidents_found = run_micro_batch()
        if incidents_found == 0:
            # Sleep briefly if no events to prevent 100% CPU usage
            time.sleep(1)