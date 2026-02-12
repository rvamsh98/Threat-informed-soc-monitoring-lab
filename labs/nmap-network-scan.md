# Network Scan Detection (Nmap) – MITRE ATT&CK T1046

## Overview
Detection of network discovery activity performed using Nmap, identified through Sysmon network connection logs and correlated in Splunk.

This lab demonstrates how reconnaissance behavior is detected and escalated into a high-confidence SOC alert.

---

## Lab Environment

**Attacker**
- Kali Linux

**Target**
- Windows 10 (Sysmon + Splunk Universal Forwarder)

**Telemetry Sources**
- Sysmon (Event ID 3 – Network Connection)
- Windows Security Logs

---

## Attack Simulation

Nmap scan executed from Kali Linux:

nmap -sS -p 1-1000 192.168.160.140

---

## Detection Logic (Splunk SPL)

index=sysmon EventCode=3
| stats count by src_ip, dest_ip, dest_port
| where count > 50
| sort -count


---

## MITRE Mapping
- T1046 – Network Service Discovery  

---

## D3FEND Mapping
- Network Traffic Analysis  
- Detect Network Scanning  

---

## Evidence
See screenshots in:

/screenshots

---

## Analyst Triage Steps
1. Validate source host  
2. Identify scanning pattern  
3. Check asset criticality  
4. Isolate source if malicious  
5. Generate incident ticket  

---

## Outcome
Reconnaissance behavior was detected early, enabling rapid response before lateral movement occurred.
