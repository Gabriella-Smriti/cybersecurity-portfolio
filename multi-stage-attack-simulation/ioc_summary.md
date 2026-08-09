# Indicator of Compromise (IoC) Summary

**Incident:** Multi-stage attack simulation — phishing → persistence → lateral movement → data exfiltration
**Date of activity (simulated):** 2026-07-20
**Prepared for:** MISP-style IoC sharing / TheHive-style case documentation

## Attack Timeline

| Time (simulated) | Stage | Event |
|---|---|---|
| 08:34 | Initial Access | Phishing email delivered with macro-enabled attachment |
| 08:49 | Execution | Malicious macro spawns encoded PowerShell command |
| 09:04 | Persistence | Scheduled task "Windows Defender Update Check" created |
| 09:19 – 11:28 | Lateral Movement | 47 failed RDP authentication attempts, then 1 success, from workstation to Domain Controller |
| (ongoing, same window) | Credential Access | 35 failed authentication attempts from external IP against 7 accounts |
| (ongoing, same window) | Exfiltration | 450 abnormally long DNS queries (tunneling pattern) |

## Indicators

| Type | Value | Context |
|---|---|---|
| Hostname (compromised) | WORKSTATION-010 | Initial phishing target; source of persistence and lateral movement |
| Username (targeted) | kwilliams | Recipient of phishing email; account used for initial access |
| Attachment name | Q3_Financial_Summary.xlsm | Malicious macro-enabled Excel delivery mechanism |
| Scheduled task name | Windows Defender Update Check | Disguised persistence mechanism (masquerading as a legitimate Defender task) |
| Source IP (lateral movement) | 192.168.1.110 | Compromised workstation, origin of RDP attempts to DC |
| Destination IP (lateral movement) | 192.168.1.20 | Domain Controller (DC-01), target of lateral movement |
| Source IP (credential stuffing) | 192.168.1.100 | External/untrusted IP, brute-force pattern against 7 accounts |
| Source IP (DNS tunneling) | 192.168.1.105 | Internal host generating high-entropy DNS queries |
| DNS pattern | *.exfil-c2.example (>70 char subdomains) | Suspected covert exfiltration channel |

## Detection Coverage

Each indicator above is covered by a corresponding correlation rule (see the correlation-rules folder in this repo) and by the Sigma and YARA rules included alongside this document:

- `sigma_scheduled_task_persistence.yml` — detects the scheduled task persistence technique generically (not tied to this specific task name), so it would catch similar attacks using a different disguised task name.
- `yara_malicious_macro_document.yar` — detects the macro-enabled document delivery pattern generically (auto-exec VBA + shell/download indicators), not tied to this specific file hash or name.

## Recommended Mitigations

- Enforce macro-blocking policy for Office files received via email from external senders.
- Deploy endpoint detection (EDR) with visibility into PowerShell execution, including encoded command decoding.
- Restrict RDP access to the Domain Controller to a dedicated jump-host/bastion, removing direct workstation-to-DC RDP.
- Monitor and alert on DNS queries exceeding a defined length threshold, particularly to newly-observed or non-categorized domains.
- Rotate credentials and enable multi-factor authentication for privileged/administrator accounts.
