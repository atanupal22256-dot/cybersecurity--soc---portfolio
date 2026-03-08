# Cybersecurity Portfolio – SOC Analyst & Security Research

This repository contains my practical cybersecurity labs, detection engineering projects, and incident investigation exercises performed in a controlled home lab environment.

My work focuses on **Security Operations Center (SOC) analysis, threat detection, incident response, and web security testing**, combining both blue team and offensive security perspectives.

All projects are performed for **educational and defensive security purposes** using vulnerable lab environments and simulated attack scenarios.

---

# Security Lab Environment

My cybersecurity lab environment is designed to simulate real-world enterprise security monitoring and attack scenarios.

Infrastructure includes:

• Virtualization: VirtualBox  
• Operating Systems: Ubuntu Server, Windows 10, Kali Linux  
• SIEM Platform: Wazuh + Splunk Cloud  
• Network Monitoring: Wireshark, Zeek  
• Vulnerability Scanning: OpenVAS, Nmap  
• Memory Forensics: Volatility  
• Threat Intelligence: VirusTotal, AbuseIPDB  
• Frameworks: MITRE ATT&CK Navigator  

The lab environment allows me to simulate attacks, analyze logs, investigate incidents, and build detection rules similar to real SOC workflows.

---

# Projects

## 1. SIEM Deployment & Attack Detection Lab

Technologies: Wazuh, Splunk Cloud, VirtualBox

Deployed a centralized Security Information and Event Management (SIEM) environment using Wazuh and Splunk Cloud.

Key Activities:

• Installed and configured Wazuh server on Ubuntu  
• Integrated Windows 10 and Kali Linux endpoints using Wazuh agents  
• Built custom alert rules to detect suspicious activity  
• Simulated brute force attacks, reconnaissance scans, and file integrity violations  
• Correlated security events across endpoints  
• Mapped detected alerts to MITRE ATT&CK techniques including:

T1110 – Brute Force  
T1046 – Network Service Discovery  
T1083 – File and Directory Discovery

Outcome:

Created a working SOC-style detection pipeline capable of monitoring endpoint activity and identifying attack behaviors.

---

## 2. Phishing Email Investigation

Tools: MXToolbox, VirusTotal, Email Header Analysis

Analyzed multiple suspicious email samples to identify phishing indicators and malicious infrastructure.

Key Activities:

• Extracted and analyzed email headers  
• Investigated SPF, DKIM, and DMARC authentication failures  
• Identified spoofed sender domains  
• Extracted malicious URLs and attachment hashes  
• Cross-referenced IOCs using VirusTotal and AbuseIPDB  
• Documented the full phishing investigation workflow

Outcome:

Developed practical experience performing SOC-level phishing triage and threat intelligence verification.

---

## 3. Network Traffic Analysis (PCAP Investigation)

Tools: Wireshark, Nmap, Zeek

Captured and analyzed packet capture (PCAP) files to investigate suspicious network behavior.

Key Activities:

• Identified port scanning activity  
• Detected ARP spoofing attempts  
• Observed unencrypted credential transmissions  
• Analyzed command-and-control beaconing traffic  
• Reconstructed attack timelines using packet data

Outcome:

Produced a structured incident investigation report identifying compromised hosts, attacker techniques, and recommended mitigation steps.

---

## 4. Incident Response Simulation

Platforms: TryHackMe Blue Team Labs

Performed simulated security incident investigations using blue team training environments.

Key Activities:

• Investigated simulated security breaches  
• Performed log analysis using Splunk queries  
• Conducted memory forensics using Volatility  
• Reconstructed attack timelines  
• Mapped attacker behavior to MITRE ATT&CK tactics

Outcome:

Developed structured incident response workflows including identification, investigation, containment, and reporting.

---

## 5. Vulnerability Assessment Project

Tools: Nmap, OpenVAS  
Target Environment: Metasploitable 2

Performed a full vulnerability assessment against a deliberately vulnerable system.

Key Activities:

• Conducted service enumeration using Nmap  
• Identified exposed services and outdated software versions  
• Executed vulnerability scans with OpenVAS  
• Identified multiple CVEs with risk ratings based on CVSS scores  
• Prioritized vulnerabilities based on exploitability and potential impact

Outcome:

Produced a professional vulnerability assessment report including risk analysis and remediation recommendations.

---

# Detection Engineering Example

Example detection logic used in my SIEM lab.

Brute Force Detection Rule Concept:

Multiple failed authentication attempts from the same IP address within a short time window may indicate a brute force attack.

Detection Strategy:

• Monitor authentication failure events  
• Aggregate repeated failures by source IP  
• Trigger alert when threshold exceeds defined limit  
• Map detection to MITRE ATT&CK technique T1110

This approach helps SOC analysts quickly identify credential attack activity.

---

# Skills Demonstrated

Security Operations (SOC)

• Alert triage  
• Log analysis  
• Incident investigation  
• Threat detection  

Offensive Security

• Web application testing  
• Vulnerability assessment  
• Network scanning  

Security Tools

• Wazuh  
• Splunk  
• Wireshark  
• Burp Suite  
• SQLmap  
• Nmap  
• OpenVAS  

Frameworks

• MITRE ATT&CK  
• OWASP Top 10  

---

# Learning Platforms

TryHackMe – Top 3% Global Ranking  
HackTheBox  
PortSwigger Web Security Academy  
OWASP Juice Shop  
KC7 Cyber Range  

---

# Disclaimer

All projects and attack simulations were conducted in controlled lab environments for educational and defensive cybersecurity learning purposes only.

No unauthorized testing or illegal activity was performed.

---

# Contact

LinkedIn: linkedin.com/in/atanu-pal-cybersecurity
Email: atanupal22256@gmail.com
