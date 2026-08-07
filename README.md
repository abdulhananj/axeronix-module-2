# AXERONIX XDR COPILOT — Module 2: Event Correlation Engine

> **"The Brain" of the AXERONIX platform. Transforming thousands of disconnected raw logs into a low volume of high-confidence, actionable incident objects mapped to attack narratives.**

## 🧠 Overview
A single log line rarely tells you anything dangerous by itself. "User logged in" happens a thousand times a day. "PowerShell executed" is occasionally legitimate. But when those events share a thread—same `host`, same `user`, within a narrow time window—they stop being harmless lines and become **one attack story**.

Module 2 is the highest-leverage component in the AXERONIX platform. It consumes normalized JSON log streams from Module 1 (Universal Log Collector) and outputs structured `Incident` objects. Every downstream module—including AI Investigation (Module 3), Timeline Reconstruction (Module 6), and Attack Graphing (Module 7)—depends on Module 2 having already done the reasoning work of converting noise into narrative.

## 🏗️ Architecture & The 6-Step Pipeline
This engine is built strictly to the Principal Architect's specification, prioritizing **explainable logic** over black-box ML. It processes data through a deterministic 6-step pipeline:

1. **Time-Window Grouping (`sessions.py`):** Groups events from the same host/user within a 5-minute sliding window into formal `Session` objects.
2. **Deduplication (`dedup.py`):** Collapses high-frequency repetitive alerts (e.g., port scans, repeated login failures) into single entries with active counters and timestamp ranges.
3. **Hand-Authored Rules (`rules.py`):** Explicit, deterministic if-this-then-that rules (Brute Force, Phishing Payload, Privilege Escalation, Lateral Movement) that are fully debuggable and explainable.
4. **Alert Grouping (`grouping.py`):** Uses a union-find algorithm to cluster individual rule matches sharing common telemetry pivots (`host_id`, `user_id`) into a single `Incident` object.
5. **Session Creation (`schema.py`):** Formalizes correlated state into persistent objects tracking session start, end, total events, and involved entities.
6. **Kill Chain / MITRE Mapping (`killchain.py`):** Tags each event within a correlated session to Cyber Kill Chain stages and MITRE ATT&CK Tactic IDs, turning grouped events into a labeled attack narrative.

## 📁 Project Structure
```text
module2_correlation_engine/
├── correlation_engine/           # Core Python Package
│   ├── __init__.py
│   ├── schema.py                 # Strict dataclasses (Event, Alert, Session, Incident)
│   ├── sessions.py               # Step 1 & 5: Time-window grouping
│   ├── rules.py                  # Step 3: Hand-authored deterministic rules
│   ├── dedup.py                  # Step 2: Alert deduplication
│   ├── grouping.py               # Step 4: Union-find alert grouping
│   ├── killchain.py              # Step 6: MITRE ATT&CK mapping
│   ├── graph_export.py           # Boundary adapter for Attack Graph output
│   ├── store.py                  # In-memory or Redis-backed incident storage
│   └── sample_data.py            # Fake dataset for standalone testing
│
├── worker.py                     # PRODUCTION: Continuous Redis microservice loop
├── cli.py                        # CLI: Unified tool for testing logs & exporting formats
├── generate_logs.py              # TESTING: Generates 3,000+ fake logs for scale testing
├── demo.py                       # LOCAL: Runs engine on fake sample data
└── README.md
```

## 🚀 Getting Started

### Option 1: Quick Local Demo (No Redis Required)
Run the engine against a built-in simulated 4-stage attack (Failed Logins → Success → PowerShell → Admin Creation) to see it generate a correlated incident and print the Kill Chain narrative.
```bash
python cli.py
```

### Option 2: Process Custom Logs (Standard Output)
Test the engine against your own CSV or JSON log files. This saves the full incident JSON for downstream modules (like AI and Timeline) and prints a clean 1-line summary to your terminal to prevent alert fatigue.
```bash
python cli.py path/to/your_logs.json
```

### Option 3: Process Logs for Module 7 (Attack Graph Output)
Run your logs through the engine and format the output specifically for Student G's Attack Graph module.
```bash
python cli.py path/to/your_logs.json --format module7
```

### Option 4: Live Platform Worker (Requires Redis)
Run the module as a continuous microservice inside the 12-module AXERONIX platform. It will listen to Module 1's output queue and dispatch incidents to Modules 3, 6, and 7.
```bash
python worker.py
```

## 🔗 Integration Contracts (For AXERONIX Team)

### Input (From Module 1)
The worker listens to the Redis list: `axeronix:module_1:events`
It expects JSON payloads matching the shared schema:
```json
{
  "timestamp": "2026-07-29T08:00:00Z",
  "host": "WKSTN-042",
  "source_type": "windows",
  "event_id": "4625",
  "raw_message": "An account failed to log on",
  "user": "jsmith"
}
```

### Output (To Modules 3, 6, & 7)
When an incident is correlated, the worker pushes to three queues:
* `axeronix:module_3:incidents` (Standard JSON dict via `Incident.to_dict()`)
* `axeronix:module_6:incidents` (Standard JSON dict via `Incident.to_dict()`)
* `axeronix:module_7:incidents` (Custom flattened timeline format via `graph_export.py`)

## 🛡️ Design Principles
* **Explainable over Clever:** Every risk score and rule match can be traced back to exact event IDs. No black-box ML.
* **Adapter Pattern:** Internal `Incident` objects are kept pure. Translation to the Attack Graph's expected schema happens at the boundary in `graph_export.py`.
* **Stateless Workers:** All state (time windows, dedup buckets) is offloaded to Redis, allowing the worker to be killed, restarted, or scaled horizontally without losing in-flight correlations.

---
**Owner:** Student B(Abdul Hanan) | **Difficulty:** Advanced | **Stack:** Python 3.11+, Redis
