AXERONIX XDR COPILOT - Module 2: Event Correlation Engine
This module acts as "the brain" of the AXERONIX XDR platform. It consumes normalized JSON log streams from Module 1, groups raw noise into meaningful incidents via time-windowing, deduplication, and hand-authored correlation rules, and maps them to the Cyber Kill Chain / MITRE ATT&CK framework.

Architecture & Features
Stateful Processing: Utilizes Redis for sliding-window state management.
Explainable Logic: Uses deterministic, hand-authored rules (Brute Force, Phishing Payload, Privilege Escalation, Lateral Movement) instead of black-box ML.
Schema Enforcement: Strict Python dataclasses for Event, Alert, Session, and Incident objects.
Adapter Pattern: Includes module7_export.py to translate internal Incident objects into the exact format Module 7 (Attack Graph) expects.
How to Run
Standalone Demo: python demo.py
Live Platform Worker: python worker.py (Requires Redis running on localhost:6379)
