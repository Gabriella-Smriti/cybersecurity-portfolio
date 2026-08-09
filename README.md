# Cybersecurity Portfolio

Welcome to my cybersecurity portfolio. This repository showcases hands-on cybersecurity projects, technical investigations, and security documentation completed as part of my practical learning and skill development.

---

## About

I am a Computer Science and Engineering student with a strong interest in cybersecurity. This portfolio demonstrates practical experience with security analysis, Open-Source Intelligence (OSINT), phishing investigations, and technical reporting through structured, hands-on projects.

---

## Projects

| Project | Description |
|---------|-------------|
| **[Passive Network Footprint Analysis](./Passive-Network-Footprint-Analysis/)** | Conducted passive reconnaissance using OSINT techniques to analyze the publicly available network footprint of a target domain. |
| **[Phishing Email Analysis](./Phishing-Email-Analysis/)** | Analyzed a phishing email, identified indicators of compromise (IOCs), assessed potential threats, and documented the investigation process. |

> Additional projects will be added as I continue expanding my cybersecurity knowledge and practical experience.

---

## Skills Demonstrated

- Open-Source Intelligence (OSINT)
- Passive Reconnaissance
- DNS & WHOIS Analysis
- Technology Fingerprinting
- Phishing Email Analysis
- Threat Analysis
- Security Documentation
- Technical Report Writing

---

## Tools Used

- nslookup
- WHOIS
- DNSDumpster
- BuiltWith
- VirusTotal
- CyberChef

---
## SOC Detection Engineering Projects

Hands-on SIEM detection-engineering work built on the Elastic Stack (Elasticsearch + Kibana), covering correlation rule development, dashboard design, and a simulated multi-stage attack chain with supporting threat-intelligence artifacts.

| Folder | Description |
|---|---|
| [`siem-correlation-rules/`](./siem-correlation-rules) | Three correlation rules detecting credential stuffing, DNS tunneling, and malicious PowerShell execution, with a synthetic log generator |
| [`siem-dashboard/`](./siem-dashboard) | A six-panel Kibana dashboard visualizing the detections above |
| [`multi-stage-attack-simulation/`](./multi-stage-attack-simulation) | An extended, log-based simulation of a multi-stage attack chain (phishing → persistence → lateral movement → exfiltration), including generic Sigma/YARA detection rules and IoC documentation |

Rather than requiring live infrastructure or executing real exploit code, the correlation rules and dashboard are built and validated against realistic synthetic log data engineered to reproduce the network/endpoint footprint of specific, well-documented attack techniques (mapped to MITRE ATT&CK). Every rule was independently tested against known "ground truth" attack data before being finalized.

**Tools used:** Elasticsearch, Kibana (Lens, Alerting Rules, Dev Tools Console), Python (synthetic data generation), Sigma, YARA.

**A note on how this was built:** this was a guided learning project. My background and focus is SOC analysis, not software development — the value I was building here is in SIEM configuration, log investigation, and detection logic, not in writing Python. All Kibana configuration — data views, correlation rules, dashboard panels, and troubleshooting along the way — was implemented and independently tested by me, step by step, in my own Elastic Cloud environment. The synthetic data generator scripts, detection-rule content (Sigma/YARA), and documentation in these folders were produced with AI assistance (Claude) as part of that learning process. I'm noting this plainly rather than presenting it as unassisted work.



## Disclaimer

All projects in this repository are intended for educational and portfolio purposes only.

The analyses were conducted using publicly available information or authorized learning environments. No unauthorized scanning, exploitation, or interaction with production systems was performed.

---

## Author

**Gabriella Smriti**

Computer Science & Engineering Student (2023–2027)

Aspiring Cybersecurity Professional
