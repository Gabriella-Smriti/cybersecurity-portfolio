"""
Generates two additional datasets for the APT simulation task:
  - endpoint_logs.json   (email delivery, process creation, scheduled task creation)
  - rdp_logs_append.json (RDP lateral-movement authentication events, appended to auth-logs)

These build on the auth-logs / dns-logs / powershell-logs indices already created in
the earlier correlation-rules and dashboard exercises, connecting them into one attack narrative:
  Phishing email -> malicious process creation -> scheduled task persistence
  -> RDP lateral movement attempts -> (existing) credential-stuffing-style auth failures
  -> (existing) DNS tunneling exfiltration
  -> (existing) encoded PowerShell execution
"""

import json
import random
from datetime import datetime, timedelta

random.seed(7)

# Same "attack day" used in the earlier sample data, so everything lines up in one timeline
DAY = datetime(2026, 7, 20, 0, 0, 0)


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------------------
# 1. ENDPOINT LOGS: phishing email -> process creation -> scheduled task
# ---------------------------------------------------------------------------
endpoint_logs = []

# --- Baseline normal process creation activity (for realism / false-positive testing) ---
normal_processes = [
    ("explorer.exe", "notepad.exe"),
    ("explorer.exe", "chrome.exe"),
    ("services.exe", "svchost.exe"),
    ("explorer.exe", "outlook.exe"),
    ("cmd.exe", "ping.exe"),
]
cur = DAY
for _ in range(60):
    cur += timedelta(minutes=random.randint(10, 45))
    parent, proc = random.choice(normal_processes)
    endpoint_logs.append({
        "@timestamp": ts(cur),
        "event_type": "process_creation",
        "hostname": "WORKSTATION-{:03d}".format(random.randint(1, 50)),
        "user": random.choice(["jsmith", "agupta", "mchen", "rpatel"]),
        "parent_process": parent,
        "process_name": proc,
        "command_line": proc,
        "is_encoded": False,
    })

# --- Attack narrative: phishing email received ---
phish_time = DAY + timedelta(hours=8, minutes=34)  # 08:34
endpoint_logs.append({
    "@timestamp": ts(phish_time),
    "event_type": "email_received",
    "hostname": "WORKSTATION-010",
    "user": "kwilliams",
    "sender": "attacker@phishing-domain.example",
    "recipient": "kwilliams@corp.example",
    "attachment_name": "Q3_Financial_Summary.xlsm",
    "attachment_flagged": True,
})

# --- Attack narrative: malicious macro spawns PowerShell ---
macro_exec_time = phish_time + timedelta(minutes=15)  # 08:49
endpoint_logs.append({
    "@timestamp": ts(macro_exec_time),
    "event_type": "process_creation",
    "hostname": "WORKSTATION-010",
    "user": "kwilliams",
    "parent_process": "excel.exe",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...",
    "is_encoded": True,
})

# --- Attack narrative: scheduled task created for persistence ---
task_time = macro_exec_time + timedelta(minutes=15)  # 09:04
endpoint_logs.append({
    "@timestamp": ts(task_time),
    "event_type": "scheduled_task_creation",
    "event_id": 4698,
    "hostname": "WORKSTATION-010",
    "user": "SYSTEM",
    "task_name": "Windows Defender Update Check",
    "task_command": "C:\\Windows\\System32\\powershell.exe -NoProfile -Enc SQBFAFgA...",
})

endpoint_logs.sort(key=lambda x: x["@timestamp"])

with open("endpoint_logs.json", "w") as f:
    for entry in endpoint_logs:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# 2. RDP LATERAL MOVEMENT LOGS (appended into the existing auth-logs index)
# ---------------------------------------------------------------------------
rdp_logs = []

# Attack narrative: 47 failed RDP attempts from compromised workstation to the DC
rdp_start = macro_exec_time + timedelta(minutes=30)  # ~09:19, "first lateral movement attempt"
t = rdp_start
for i in range(47):
    t += timedelta(seconds=random.randint(8, 15))
    rdp_logs.append({
        "@timestamp": ts(t),
        "event_type": "rdp_authentication",
        "source_ip": "192.168.1.110",       # workstation10 (compromised)
        "destination_ip": "192.168.1.20",   # Domain Controller
        "username": "domain\\administrator",
        "hostname": "DC-01",
        "auth_status": "failed",
    })

# Then a single successful RDP/PsExec-style authentication once the attempt "succeeds"
success_time = t + timedelta(hours=2)  # roughly matches the 2h30m mark in the narrative
rdp_logs.append({
    "@timestamp": ts(success_time),
    "event_type": "rdp_authentication",
    "source_ip": "192.168.1.110",
    "destination_ip": "192.168.1.20",
    "username": "domain\\administrator",
    "hostname": "DC-01",
    "auth_status": "success",
})

with open("rdp_logs_append.json", "w") as f:
    for entry in rdp_logs:
        f.write(json.dumps(entry) + "\n")

print(f"Generated {len(endpoint_logs)} endpoint logs and {len(rdp_logs)} RDP logs.")
print(f"Phishing email: {ts(phish_time)}")
print(f"Macro/PowerShell execution: {ts(macro_exec_time)}")
print(f"Scheduled task creation: {ts(task_time)}")
print(f"RDP failed-attempt burst starts: {ts(rdp_start)}")
print(f"RDP successful auth: {ts(success_time)}")
