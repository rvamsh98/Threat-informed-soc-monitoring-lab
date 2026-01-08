# Threat-informed-soc-monitoring-lab
Enterprise-style SOC lab using Splunk, Snort, and Sysmon to detect, correlate,
and investigate attacks mapped to MITRE ATT&CK & D3FEND.

## 🎯 Project Overview
Enterprise-style Security Operations Center (SOC) environment built to practice real-world threat detection, alert triage, and incident response. Ingested 10,000+ security events from Snort IDS and Sysmon, achieving 85% true positive detection rate with 40% false positive reduction through systematic alert tuning.

## 🛠️ Technologies Used
- **SIEM:** Splunk Enterprise
- **Network Detection:** Snort IDS (26 custom rules)
- **Endpoint Detection:** Sysmon (Windows telemetry)
- **Attack Simulation:** Kali Linux, Nmap, Hydra
- **Frameworks:** MITRE ATT&CK, MITRE D3FEND
- **Infrastructure:** VMware Workstation (3-tier architecture)

## 🏗️ Architecture
<img width="553" height="635" alt="Screenshot 2025-12-25 190250" src="https://github.com/user-attachments/assets/caa5cdb3-5dd8-4792-b9e6-a8e9d29e5267" />


**Components:**
- Kali Linux (192.168.160.133) - Attacker
- Windows 10 (192.168.160.131) - Victim with Sysmon + Universal Forwarder
- Ubuntu Server (192.168.160.132) - Splunk Enterprise + Snort IDS

## 🎯 Key Achievements
-  Engineered 26 custom Snort IDS rules mapped to 8 MITRE ATT&CK techniques
-  Built dual-lookup enrichment system (ATT&CK + D3FEND) in Splunk
-  Achieved 85% true positive detection rate through multi-source correlation
- Reduced false positive volume by 40% via baseline analysis and threshold tuning
-  Documented 25+ incident scenarios with IOCs, timelines, and remediation steps

## 📊 Detection Coverage

| Technique | Tactic            | Detection Method      | Log Source     |
| --------- | ----------------- | --------------------- | -------------- |
| T1046     | Reconnaissance    | Snort custom rules    | Snort IDS      |
| T1110     | Credential Access | Correlation search    | Snort + Sysmon |
| T1071     | C2                | HTTP traffic analysis | Snort          |
| T1021     | Lateral Movement  | Port monitoring       | Sysmon         |



## 🔍 Sample Detection Rules

**Snort Rule - Port Scan Detection (T1046):**
```
alert tcp any any -> $HOME_NET any (msg:"MITRE ATT&CK T1046 - Port Scan Detected"; 
flags:S; threshold:type threshold, track by_src, count 10, seconds 5; 
classtype:attempted-recon; sid:1000001; rev:1;)
```

**Splunk Correlation - SSH Brute Force (T1110):**
```spl
index=snort sourcetype="snort:alert" 
| rex field=_raw "(?<attacker>\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(?<target>\d+\.\d+\.\d+\.\d+):(?<port>\d+)"
| stats count as attempts by attacker, target, port
| where attempts > 10
| sort -attempts
```

## 🧪 Attack Simulation & Validation

Validated detections through controlled attack scenarios:
- ✅ Nmap reconnaissance → Detected as T1046
- ✅ SSH brute force (Hydra) → Detected as T1110
- ✅ RDP connection attempts → Detected as T1021
- ✅ Suspicious network traffic → Correlated across sources


## 📚 Full Documentation
Complete technical documentation with architecture, methodology, detection engineering process, and lessons learned: (https://github.com/rvamsh98/threat-informed-soc-monitoring-lab/blob/main/documentation/Threat%20project%20.pdf)

## 🎓 Skills Demonstrated
- Security monitoring and alert triage
- Detection engineering (custom IDS rules + SIEM correlation)
- Threat intelligence mapping (MITRE ATT&CK/D3FEND)
- Incident documentation and investigation
- Log analysis and event correlation
- False positive reduction and alert tuning
- SOC workflow simulation (monitoring → triage → escalation)

## 🚀 Future Enhancements
- [ ] Integrate SOAR for automated response
- [ ] Add threat intelligence feeds (STIX/TAXII)
- [ ] Implement behavioral analytics for anomaly detection

## 📬 Contact
**Vamshi Ramavath**  
📧 vamshiramavath08@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/vamshiramavath/)  
🌐 [Portfolio](https://rvamsh98.github.io/vamshi.github.io/)


