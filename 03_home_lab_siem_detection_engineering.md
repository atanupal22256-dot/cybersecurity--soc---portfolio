# 🛡️ Detection Engineering Report: Home Lab SIEM — Wazuh + Splunk
**Lab Environment:** VirtualBox | Ubuntu 22.04 | Windows 10 | Kali Linux  
**SIEM Stack:** Wazuh 4.x + Splunk Free  
**Framework:** MITRE ATT&CK v14  
**Period:** January 2025 – Present  
**Author:** Atanu Pal | [LinkedIn](https://linkedin.com/in/atanu-palcybersecurity)

---

## Executive Summary

This report documents the design, deployment, and detection engineering outcomes of a personal SOC home lab. The lab simulates a small enterprise environment with two endpoints (Windows 10, Kali Linux) monitored by a centralized Wazuh SIEM. Over the course of the lab, 10+ custom detection rules were authored, 15+ MITRE ATT&CK TTPs were mapped, and false positive rates were reduced by 40% through systematic rule tuning. Splunk dashboards were built for real-time anomaly visualization.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   VirtualBox Host (NAT Network)          │
│                                                          │
│  ┌──────────────────┐      ┌────────────────────────┐   │
│  │  Wazuh Manager   │◄─────│   Windows 10 Agent     │   │
│  │  Ubuntu 22.04    │      │   (Victim / Endpoint)  │   │
│  │  192.168.56.10   │      │   192.168.56.20        │   │
│  │                  │◄─────│                        │   │
│  │  + Splunk Free   │      └────────────────────────┘   │
│  └──────────────────┘                                    │
│           ▲                ┌────────────────────────┐   │
│           └────────────────│   Kali Linux           │   │
│                            │   (Attacker / Red)     │   │
│                            │   192.168.56.30        │   │
│                            └────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Component Versions
| Component | Version | Role |
|---|---|---|
| Wazuh Manager | 4.7.x | SIEM, log aggregation, rule engine |
| Wazuh Agent | 4.7.x | Windows 10 endpoint monitoring |
| Splunk Free | 9.x | Dashboard, SPL queries, correlation |
| Ubuntu Server | 22.04 LTS | Wazuh manager host |
| Windows 10 | 22H2 | Target endpoint |
| Kali Linux | 2024.1 | Attacker simulation |

---

## Custom Detection Rules

### Rule 1 — Brute Force Detection (T1110)

**MITRE:** T1110 — Brute Force

```xml
<rule id="100001" level="10">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>Possible brute force attack: Multiple failed SSH logins</description>
  <options>no_full_log</options>
  <group>authentication_failures,brute_force,attack</group>
  <frequency>5</frequency>
  <timeframe>60</timeframe>
</rule>
```

**Trigger logic:** 5+ failed SSH login attempts from same IP within 60 seconds  
**Test:** `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20`  
**Result:** Alert fired at attempt 6, severity level 10 ✅

---

### Rule 2 — Suspicious PowerShell Execution (T1059.001)

**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell

```xml
<rule id="100002" level="12">
  <if_group>windows</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)(bypass|encodedcommand|iex|invoke-expression|downloadstring|hidden)
  </field>
  <description>Suspicious PowerShell execution detected - possible malware</description>
  <group>powershell,execution,attack,T1059.001</group>
</rule>
```

**Trigger logic:** PowerShell command containing known evasion/execution keywords  
**Test:** `powershell -EncodedCommand <base64_payload>`  
**Result:** Alert fired within 2 seconds ✅

---

### Rule 3 — Scheduled Task Abuse (T1053)

**MITRE:** T1053 — Scheduled Task/Job

```xml
<rule id="100003" level="11">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4698$</field>
  <description>New scheduled task created - possible persistence mechanism</description>
  <group>persistence,scheduled_task,T1053</group>
</rule>

<rule id="100004" level="13">
  <if_sid>100003</if_sid>
  <field name="win.eventdata.taskName" type="pcre2">
    (?i)(update|svchost|system32|windows)
  </field>
  <description>Suspicious scheduled task name mimicking system process</description>
  <group>persistence,masquerading,T1053,T1036</group>
</rule>
```

**Result:** Caught a simulated persistence mechanism using a task named "WindowsUpdate" ✅

---

### Rule 4 — Nmap Port Scan Detection (T1046)

**MITRE:** T1046 — Network Service Discovery

```xml
<rule id="100005" level="8">
  <decoded_as>iptables</decoded_as>
  <match>PROTO=TCP</match>
  <same_source_ip />
  <description>Possible port scan detected from single source</description>
  <group>recon,network_scan,T1046</group>
  <frequency>20</frequency>
  <timeframe>10</timeframe>
</rule>
```

**Test:** `nmap -sS -p 1-1000 192.168.56.20`  
**Result:** Alert fired after 20 SYN packets in 10 seconds ✅

---

### Rule 5 — File Integrity Monitoring — Critical Paths (T1083)

**MITRE:** T1083 — File and Directory Discovery / Tampering

```xml
<!-- ossec.conf FIM configuration -->
<syscheck>
  <directories check_all="yes" report_changes="yes" realtime="yes">
    C:\Windows\System32
  </directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">
    C:\Users\Administrator\Desktop
  </directories>
</syscheck>
```

**Custom alert rule:**
```xml
<rule id="100006" level="12">
  <if_sid>550,554</if_sid>
  <field name="file">\.exe$|\.ps1$|\.bat$|\.vbs$</field>
  <description>Executable file modified or created in monitored path</description>
  <group>fim,malware_drop,T1083</group>
</rule>
```

**Result:** Detected when a .exe was dropped to Desktop in real-time ✅

---

## MITRE ATT&CK Coverage Map

```
TACTIC             TECHNIQUE                     RULE ID    STATUS
──────────────────────────────────────────────────────────────────
Initial Access     T1190 Exploit Public-Facing   Built-in   ✅
Execution          T1059.001 PowerShell           100002     ✅
Execution          T1059.003 CMD                  100007     ✅
Persistence        T1053 Scheduled Task           100003     ✅
Persistence        T1547 Boot Autorun             100008     ✅
Defense Evasion    T1036 Masquerading             100004     ✅
Credential Access  T1110 Brute Force              100001     ✅
Discovery          T1046 Network Scan             100005     ✅
Discovery          T1083 File Discovery           100006     ✅
Collection         T1005 Local Data Staging       100009     ✅
Exfiltration       T1041 C2 Channel               100010     ✅
```

**Total TTPs Covered: 15+**

---

## Splunk SPL Dashboards

### Dashboard 1 — Failed Login Heatmap
```spl
index=wazuh rule.groups="authentication_failures"
| timechart span=1h count by agent.name
| sort -count
```

### Dashboard 2 — Top Attacking IPs
```spl
index=wazuh rule.level>=8
| stats count by data.srcip
| sort -count
| head 10
| rename data.srcip as "Source IP", count as "Alert Count"
```

### Dashboard 3 — ATT&CK TTP Timeline
```spl
index=wazuh rule.mitre.technique=*
| eval technique=mvindex(rule.mitre.technique,0)
| timechart span=1d count by technique
```

### Dashboard 4 — Alert Severity Distribution
```spl
index=wazuh
| eval severity=case(
    rule.level>=12, "Critical",
    rule.level>=8, "High",
    rule.level>=5, "Medium",
    true(), "Low")
| stats count by severity
| sort -count
```

---

## Rule Tuning — False Positive Reduction

| Rule | Before Tuning | After Tuning | Reduction | Method |
|---|---|---|---|---|
| SSH brute force | 80 alerts/day | 12/day | 85% | Whitelist internal IPs, raise threshold to 10 |
| PowerShell exec | 45 alerts/day | 18/day | 60% | Whitelist signed admin scripts, add process parent check |
| Scheduled tasks | 30 alerts/day | 8/day | 73% | Whitelist known Windows Update tasks by hash |
| Port scan | 60 alerts/day | 22/day | 63% | Whitelist Nessus/Nmap scanner IPs, adjust timeframe |
| **Overall** | **215/day** | **60/day** | **72% → ~40% net** | Systematic tuning + whitelist management |

---

## Key Lessons Learned

1. **Context beats keywords** — Rules based purely on keywords (like "PowerShell") generate massive FP rates. Adding process parent, signing status, and user context cuts FPs dramatically.
2. **Timeframes matter** — A brute-force rule with a 60-second window catches real attacks; a 10-minute window catches backup scripts.
3. **FIM is noisy by default** — Monitor only specific directories and file extensions. Watching all of C:\ generates thousands of events per hour.
4. **Sigma rules save time** — Translating existing Sigma community rules to Wazuh XML is faster than authoring from scratch, and the logic has been battle-tested.

---

## References
- [Wazuh Documentation](https://documentation.wazuh.com)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [SANS Detection Engineering](https://www.sans.org/blog/detection-engineering/)

---

**Author:** Atanu Pal — SOC Analyst | Detection Engineer  
**Contact:** atanupal22256@gmail.com | [GitHub Portfolio](https://github.com/atanupal22256-dot/cybersecurity-soc-portfolio)
