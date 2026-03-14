# 📧 SOC Triage Walkthrough: Phishing Email Analysis
**Triage Type:** Email Header Analysis + IOC Extraction  
**Tools:** MXToolbox, VirusTotal, AbuseIPDB, CyberChef, Any.run  
**Framework:** MITRE ATT&CK | NIST SP 800-61  
**Author:** Atanu Pal | [LinkedIn](https://linkedin.com/in/atanu-palcybersecurity)

---

## Executive Summary

This walkthrough documents a complete SOC Tier-1 triage process for a suspicious phishing email. The analysis covers full header parsing, SPF/DKIM/DMARC authentication failure investigation, IOC extraction and cross-referencing, attachment sandboxing, and escalation decision with a documented playbook trail.

---

## Scenario

> **Alert source:** User reports email "Your PayPal account has been limited – verify immediately"  
> **Reported by:** finance@company.com  
> **Received:** Triage timestamp 2025-03-10 09:14 UTC  
> **Analyst:** Atanu Pal | Ticket: SOC-2025-0142

---

## Step 1 — Receipt & Initial Triage

**Checklist before opening anything:**
- [x] Email viewed in plain-text mode only (no HTML rendering)
- [x] No attachments executed
- [x] All links extracted as text, not clicked
- [x] Email isolated from production mailbox

**Initial indicators of suspicion:**
```
From:     "PayPal Security" <security@paypa1-verify.com>   ← typosquat domain
To:       finance@company.com
Subject:  Your PayPal account has been limited – verify immediately
Date:     Mon, 10 Mar 2025 08:47:22 +0000
Reply-To: noreply@paypa1-verify.com                        ← same rogue domain
```

**Red flags at a glance:**
- Domain `paypa1-verify.com` — replaces "l" with "1" (typosquatting)
- Urgency language ("limited", "immediately")
- Reply-To matches spoofed From address
- Sender domain ≠ PayPal's legitimate domain (paypal.com)

---

## Step 2 — Full Email Header Analysis

### Raw Header Extraction (key fields)
```
Received: from mail.paypa1-verify.com (185.220.101.47)
          by mx.company.com with ESMTP id abc123
          for <finance@company.com>; Mon, 10 Mar 2025 09:14:11 +0000
X-Originating-IP: 185.220.101.47
X-Mailer: PHPMailer 6.1.8
Authentication-Results: mx.company.com;
       spf=fail (sender IP is 185.220.101.47)
             smtp.mailfrom=paypa1-verify.com;
       dkim=none (message not signed)
             header.d=paypa1-verify.com;
       dmarc=fail action=none
             header.from=paypa1-verify.com;
Message-ID: <xyz789@paypa1-verify.com>
```

### Authentication Results Analysis

| Check | Result | Meaning |
|---|---|---|
| **SPF** | ❌ FAIL | Sending IP (185.220.101.47) NOT authorized by domain's SPF record |
| **DKIM** | ❌ NONE | Email not digitally signed — cannot verify integrity |
| **DMARC** | ❌ FAIL | Both SPF and DKIM failed; domain policy not enforced (action=none) |

**Conclusion:** This email is definitively spoofed/fraudulent. No legitimate authentication passed.

---

## Step 3 — IOC Extraction

### IOC Table

| IOC | Type | Value |
|---|---|---|
| Sender domain | Domain | `paypa1-verify.com` |
| Originating IP | IP Address | `185.220.101.47` |
| Embedded URL | URL | `http://paypa1-verify.com/secure/verify?token=a8f3k2` |
| URL IP | IP Address | `185.220.101.52` |
| X-Mailer | Tool | `PHPMailer 6.1.8` |
| Message-ID domain | Domain | `paypa1-verify.com` |

---

## Step 4 — IOC Cross-Reference (Threat Intel)

### IP: 185.220.101.47 — VirusTotal

```
VirusTotal Results for 185.220.101.47:
─────────────────────────────────────
Detection ratio:   17/94 vendors flagged as malicious
Categories:        Phishing, Spam, Tor Exit Node
Country:           Germany (DE)
ASN:               AS24940 (Hetzner Online GmbH)
Last seen:         2025-03-09 (1 day before attack)
Community score:   -65 (highly suspicious)
Associated files:  3 malicious hashes
```

### IP: 185.220.101.47 — AbuseIPDB

```
AbuseIPDB Report:
─────────────────
Confidence of Abuse: 94%
Total Reports:       847 reports
Last Reported:       2025-03-09
Categories:          Phishing, Web Spam, Email Spam, Port Scan
ISP:                 Hetzner Online GmbH
```

### Domain: paypa1-verify.com — WHOIS + VirusTotal

```
Domain Registration:
Created:    2025-03-07 (3 days before attack — fresh domain!)
Registrar:  Namecheap, Inc.
Registrant: REDACTED (privacy protected)
Name Servers: ns1.digitalocean.com

VirusTotal URL scan:
Detected by 23/94 engines as Phishing
Category: Credential harvesting page
```

**Key finding:** Domain registered 3 days before the attack — classic "aged domain" evasion is NOT used here, suggesting opportunistic attacker.

---

## Step 5 — Attachment / Link Sandbox Analysis

### Embedded URL Behavior (Any.run sandbox)

```
URL: http://paypa1-verify.com/secure/verify?token=a8f3k2

Network Activity:
  → GET /secure/verify?token=a8f3k2   200 OK
  → Loads: /assets/paypal-clone.js
  → POST /capture.php   (form submission endpoint)
  → DNS: paypa1-verify.com → 185.220.101.52

Page behavior:
  - Renders fake PayPal login page (credential harvesting)
  - Captures: email, password, SSN, credit card number
  - Redirects to real paypal.com after submission (to avoid suspicion)

MITRE ATT&CK: T1566.002 (Spearphishing Link)
              T1059.007 (JavaScript)
              T1056.003 (Web Portal Capture)
```

---

## Step 6 — Attack Kill Chain Mapping

```
┌─────────────────────────────────────────────────────────────────┐
│  MITRE ATT&CK Kill Chain                                        │
├──────────────────┬──────────────────────────────────────────────┤
│ Reconnaissance   │ T1598 — Phishing for Information            │
│                  │ Target email harvested from LinkedIn/OSINT   │
├──────────────────┼──────────────────────────────────────────────┤
│ Resource Dev     │ T1583.001 — Acquire Domain (paypa1-verify)  │
│                  │ T1583.004 — Server (Hetzner VPS)            │
├──────────────────┼──────────────────────────────────────────────┤
│ Initial Access   │ T1566.002 — Spearphishing Link              │
│                  │ Credential harvesting via fake PayPal page   │
├──────────────────┼──────────────────────────────────────────────┤
│ Collection       │ T1056.003 — Web Portal Capture              │
│                  │ Credentials, SSN, CC captured via POST       │
├──────────────────┼──────────────────────────────────────────────┤
│ Exfiltration     │ T1041 — Exfil over C2 Channel               │
│                  │ Data POSTed to /capture.php endpoint         │
└──────────────────┴──────────────────────────────────────────────┘
```

---

## Step 7 — Triage Decision & Escalation

### Severity Assessment

| Factor | Value | Score |
|---|---|---|
| Authentication failures (SPF/DKIM/DMARC) | All 3 failed | High |
| IP reputation (VirusTotal/AbuseIPDB) | 94% abuse confidence | Critical |
| Domain age | 3 days | High |
| User interaction | Email opened, no links clicked | Low impact so far |
| Payload type | Credential harvesting | Critical |
| **Overall Severity** | | **HIGH — Escalate P1** |

### Actions Taken

```
[09:25 UTC] Email quarantined from user mailbox
[09:26 UTC] IOCs added to SIEM watchlist:
            - Block IP: 185.220.101.47 at perimeter firewall
            - Block IP: 185.220.101.52 at perimeter firewall
            - Block Domain: paypa1-verify.com at DNS sinkhole
[09:28 UTC] Alert sent to Tier-2 analyst for further investigation
[09:30 UTC] User notified: credentials NOT compromised (no click)
[09:35 UTC] IOCs submitted to VirusTotal community + AbuseIPDB
[09:40 UTC] Incident documented in ticketing system: SOC-2025-0142
[09:45 UTC] SIEM correlation rule updated: flag PHPMailer + SPF fail combination
```

---

## Step 8 — IOC Summary (for Blocklist/SIEM Ingestion)

```
# Block these at firewall/DNS level:
IP:     185.220.101.47
IP:     185.220.101.52
DOMAIN: paypa1-verify.com
URL:    http://paypa1-verify.com/secure/verify

# SIEM watchlist rules:
- Alert on any email from *paypa1-verify.com
- Alert on PHPMailer header + SPF fail combination
- Alert on any outbound connection to 185.220.101.0/24
```

---

## Playbook Reference

| Step | Action | Tool |
|---|---|---|
| 1 | Receive alert, open in text mode | Mail client |
| 2 | Extract full headers | MXToolbox Header Analyzer |
| 3 | Check SPF/DKIM/DMARC | MXToolbox / Google Admin Toolbox |
| 4 | Extract all IOCs | Manual + Regex |
| 5 | Cross-reference IPs | VirusTotal, AbuseIPDB |
| 6 | Cross-reference domains | VirusTotal, WHOIS |
| 7 | Sandbox URL/attachment | Any.run, VirusTotal |
| 8 | Map to MITRE ATT&CK | ATT&CK Navigator |
| 9 | Escalation decision | Severity rubric |
| 10 | Block IOCs, notify user | Firewall, DNS, SIEM |
| 11 | Document in ticket | SOAR/ticketing system |

---

## Key Takeaways

1. **SPF/DKIM/DMARC failures are almost always definitive** — legitimate bulk mail almost always passes at least SPF
2. **Domain age is a strong signal** — phishing infrastructure is often registered days before use
3. **Don't click to confirm** — sandbox tools give you all the behavioral data without risk
4. **IOC sharing matters** — submitting to VirusTotal/AbuseIPDB protects the broader community
5. **SIEM tuning opportunity** — every phishing email should generate at least one new detection rule

---

## References
- [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [VirusTotal](https://www.virustotal.com)
- [AbuseIPDB](https://www.abuseipdb.com)
- [Any.run Sandbox](https://any.run)
- [MITRE ATT&CK — Phishing](https://attack.mitre.org/techniques/T1566/)
- [NIST SP 800-61 Rev 2 — Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

---

**Author:** Atanu Pal — SOC Analyst L1 | Ethical Hacker  
**Contact:** atanupal22256@gmail.com | [GitHub Portfolio](https://github.com/atanupal22256-dot/cybersecurity-soc-portfolio)
