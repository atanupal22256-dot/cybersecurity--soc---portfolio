# 🔴 Bug Report: Magic Link OTP — Pre-Account Takeover
**Platform:** HackerOne  
**Target:** Kayak (kayak.com)  
**Severity:** Critical  
**CWE:** CWE-287 — Improper Authentication  
**OWASP:** A07:2021 — Identification and Authentication Failures  
**Status:** Reported via Responsible Disclosure  
**Author:** Atanu Pal | [LinkedIn](https://linkedin.com/in/atanu-palcybersecurity)

---

## Executive Summary

A critical pre-account takeover vulnerability was identified in Kayak's Magic Link / OTP authentication flow. An unauthenticated attacker can pre-register a victim's email address before the legitimate user signs up, intercept the magic link or OTP token sent to that address, and gain full authenticated access to the victim's account — permanently locking them out.

This vulnerability requires no prior access, no social engineering of the victim, and no brute-force. The entire attack can be executed silently before the victim ever interacts with the platform.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|---|---|---|
| T1078 | Valid Accounts | Attacker establishes a "valid" pre-registered account |
| T1110.001 | Brute Force: Password Guessing | OTP interception as auth bypass |
| T1539 | Steal Web Session Cookie | Post-takeover session persistence |
| T1586.002 | Compromise Accounts: Email Accounts | Pre-registration requires email control |

---

## Vulnerability Details

### Root Cause
The application allows account pre-registration with an email address **before verifying ownership** of that email. When the legitimate owner later attempts to register or log in via Magic Link, the OTP/magic link token is sent to the email — which the attacker already controls (or has pre-registered under their session context).

### Attack Prerequisites
- Attacker knows (or guesses) a target email address
- Target email has not yet registered on Kayak
- Attacker can receive or intercept the magic link/OTP (e.g., if they control the email, or via session fixation)

---

## Proof of Concept (PoC)

> ⚠️ Steps are intentionally abstracted to prevent misuse. Full technical details disclosed privately to Kayak security team via HackerOne.

### Step 1 — Pre-Registration
```
1. Attacker navigates to kayak.com registration/signup flow
2. Attacker enters VICTIM@example.com as the email address
3. Application creates a pending account record for victim email
4. No email ownership verification is enforced at this stage
```

### Step 2 — Magic Link / OTP Interception
```
5. Kayak sends OTP or magic link to victim@example.com
6. Attacker (controlling or monitoring the email) receives the token
7. Attacker clicks magic link / submits OTP before victim
```

### Step 3 — Account Takeover
```
8. Attacker is now authenticated as victim@example.com
9. Attacker sets a new password, changes recovery email
10. Victim attempts to register/login → gets "email already registered" error
11. Victim is permanently locked out of their own account
```

### Attack Flow Diagram
```
ATTACKER                           KAYAK SERVER                    VICTIM
   |                                    |                              |
   |-- Register(victim@email.com) ----> |                              |
   |                                    |-- Send OTP --> victim@email  |
   |<-- OTP token intercepted ----------|                              |
   |                                    |                              |
   |-- Submit OTP ----------------------|                              |
   |<-- Session cookie (authenticated) -|                              |
   |                                    |                              |
   |                                    |         victim tries login --+
   |                                    |<-- "Account exists" error ---|
   |                                    |                              X (locked out)
```

---

## Impact Assessment

| Impact Area | Severity | Details |
|---|---|---|
| Confidentiality | Critical | Full access to victim booking history, payment info, PII |
| Integrity | Critical | Attacker can modify bookings, saved trips, preferences |
| Availability | High | Victim permanently locked out of account |
| Business Impact | High | Reputational damage, GDPR/data breach liability |

**CVSS v3.1 Base Score: 9.1 (Critical)**  
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

## Remediation Recommendations

### Immediate (P0)
1. **Require email verification before account creation** — do not create/reserve the account record until OTP ownership is confirmed
2. **Invalidate pending registrations** — add TTL (e.g., 10 minutes) on unverified account states; purge on expiry

### Short-term (P1)
3. **One-time use tokens** — ensure magic links and OTPs are invalidated after first use or session binding
4. **Session binding** — bind OTP/magic link to the originating IP/device fingerprint to prevent cross-device interception
5. **Rate limiting** — throttle registration attempts per IP/email to slow enumeration

### Long-term (P2)
6. **CAPTCHA on registration** — reduce automated pre-registration attacks
7. **Anomaly detection** — flag accounts where registration email ≠ first-login origin

---

## References
- [OWASP A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)

---

## Disclosure Timeline

| Date | Event |
|---|---|
| Mar 2026 | Vulnerability discovered during bug bounty research |
| Mar 2026 | Report submitted via HackerOne responsible disclosure |
| — | Awaiting vendor response |

---

*This report follows responsible disclosure guidelines. No exploits were used against real user data. All testing was performed on researcher-controlled accounts.*

**Author:** Atanu Pal — SOC Analyst | Ethical Hacker | Bug Bounty Hunter  
**Contact:** atanupal22256@gmail.com | [GitHub Portfolio](https://github.com/atanupal22256-dot/cybersecurity-soc-portfolio)
