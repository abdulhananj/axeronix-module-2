import json
import random
from datetime import datetime, timedelta

# --- Configuration ---
NUM_NORMAL_EVENTS = 3000
OUTPUT_FILE = "large_security_logs.json"

# --- Fake Data Pools ---
HOSTS = [f"WKSTN-{i:03d}" for i in range(1, 101)] + [f"SRV-DC-{i:02d}" for i in range(1, 6)]
USERS = ["j.smith", "a.miller", "b.johnson", "svc_backup", "admin", "helpdesk", "c.davis"]
NORMAL_PROCESSES = ["chrome.exe", "notepad.exe", "excel.exe", "outlook.exe", "teams.exe"]
EVENT_TYPES = [
    {"event_id": "4624", "raw_message": "An account was successfully logged on", "source_type": "windows"},
    {"event_id": "4625", "raw_message": "An account failed to log on", "source_type": "windows"},
    {"event_id": "1", "raw_message": "Process Create", "source_type": "windows_sysmon"},
]

def generate_logs():
    logs = []
    base_time = datetime(2026, 10, 27, 8, 0, 0)
    
    print(f"Generating {NUM_NORMAL_EVENTS} normal daily logs...")
    for _ in range(NUM_NORMAL_EVENTS):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        event_template = random.choice(EVENT_TYPES)
        
        # Randomly distribute events over an 8-hour window
        random_seconds = random.randint(0, 8 * 3600)
        ts = base_time + timedelta(seconds=random_seconds)
        
        log = {
            "timestamp": ts.isoformat() + "Z",
            "host": host,
            "source_type": event_template["source_type"],
            "event_id": event_template["event_id"],
            "raw_message": event_template["raw_message"],
            "user": user
        }
        
        if event_template["event_id"] == "1":
            log["process"] = random.choice(NORMAL_PROCESSES)
            log["extra"] = {"parent_process": "explorer.exe"}
            
        logs.append(log)

    print("Injecting noisy port scan (40 identical alerts for dedup testing)...")
    fw_host = "FW-EDGE-01"
    scan_time = base_time + timedelta(hours=2)
    for i in range(40):
        logs.append({
            "timestamp": (scan_time + timedelta(seconds=i*2)).isoformat() + "Z",
            "host": fw_host,
            "source_type": "firewall",
            "event_id": "4625",
            "raw_message": f"Connection blocked to port {5000 + i}",
            "user": None
        })

    print("Injecting hidden multi-stage attack (Brute Force -> Phishing -> Priv Esc)...")
    attack_host = "SRV-DC-01"
    attack_user = "admin"
    attack_time = base_time + timedelta(hours=4, minutes=15)
    
    # 1. Brute Force (3 failures + 1 success)
    for i in range(3):
        logs.append({
            "timestamp": (attack_time + timedelta(seconds=i*10)).isoformat() + "Z",
            "host": attack_host, "source_type": "windows", "event_id": "4625",
            "raw_message": "An account failed to log on", "user": attack_user
        })
    logs.append({
        "timestamp": (attack_time + timedelta(seconds=40)).isoformat() + "Z",
        "host": attack_host, "source_type": "windows", "event_id": "4624",
        "raw_message": "An account was successfully logged on", "user": attack_user,
        "extra": {"new_geo": True}
    })
    
    # 2. Phishing Payload
    logs.append({
        "timestamp": (attack_time + timedelta(minutes=2)).isoformat() + "Z",
        "host": attack_host, "source_type": "windows_sysmon", "event_id": "1",
        "raw_message": "Process Create: powershell.exe -enc SQBFAFgA...",
        "user": attack_user, "process": "powershell.exe",
        "extra": {"parent_process": "winword.exe"}
    })
    
    # 3. Privilege Escalation
    logs.append({
        "timestamp": (attack_time + timedelta(minutes=4)).isoformat() + "Z",
        "host": attack_host, "source_type": "windows", "event_id": "4720",
        "raw_message": "A user account was created: svc_backdoor", "user": attack_user
    })
    logs.append({
        "timestamp": (attack_time + timedelta(minutes=4, seconds=30)).isoformat() + "Z",
        "host": attack_host, "source_type": "windows", "event_id": "4732",
        "raw_message": "A member was added to a security-enabled local group: Administrators",
        "user": attack_user
    })

    print("Sorting logs chronologically...")
    logs.sort(key=lambda x: x["timestamp"])
    
    print(f"Saving {len(logs)} logs to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w") as f:
        json.dump(logs, f, indent=2)
        
    print("Done!")

if __name__ == "__main__":
    generate_logs()