# SSH Brute Force Detection & Correlation (MITRE ATT&CK T1110)

## Overview
Detection of sustained SSH brute-force activity using Snort IDS alerts correlated in Splunk and mapped to MITRE ATT&CK and D3FEND.

This lab demonstrates how low-level IDS alerts are transformed into a high-confidence SOC detection using SPL correlation.

---

## Lab Environment

**Attacker**
- Kali Linux

**Targets**
- Ubuntu Server (Splunk Enterprise + Snort)
- Windows 10 (Sysmon + Splunk Universal Forwarder)

**Telemetry Sources**
- Snort IDS (network)
- Sysmon (host)
- Windows Security Logs

---

## Attack Simulation

Brute-force style activity generated using Hydra from Kali Linux:

hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://192.168.160.132 -t 4 -V

Repeated authentication attempts triggered Snort brute-force alerts.

---

## Detection Logic (Splunk SPL)

index=snort sourcetype="snort:alert"
| rex field=_raw "(?<attacker>\d+.\d+.\d+.\d+):\d+\s+->\s+(?<target>\d+.\d+.\d+.\d+):(?<port>\d+)"
| lookup mitre_attack_lookup technique_id OUTPUT technique_name, tactic_name
| stats count as attempts, min(_time) as first_attempt, max(_time) as last_attempt
by attacker, target, port, technique_name
| eval duration=last_attempt-first_attempt
| where attempts > 10
| sort -attempts

---

## MITRE Mapping
- T1110 – Brute Force  
- T1021 – Remote Services  

---

## D3FEND Mapping
- Inbound Session Volume Analysis  
- Isolate  

---

## Evidence

See screenshots:

- /screenshots/ssh Brute force.png  
- /screenshots/ssh-bruteforce-correlation.png  

---

## Analyst Triage Steps
1. Validate attacker IP  
2. Identify targeted host  
3. Check duration and attempt count  
4. Enrich IP reputation  
5. Block source IP  
6. Generate incident ticket  

---

## Outcome

Low-level IDS alerts were successfully correlated into a single high-confidence brute-force detection, reducing alert fatigue and improving SOC visibility.
