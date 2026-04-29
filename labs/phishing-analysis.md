# Phishing Email Analysis — Lab Notes

> **Purpose:** Step-by-step methodology for investigating suspicious emails as a SOC analyst.
> **Source:** Personal lab notes from TryHackMe, LetsDefend, and simulated phishing exercises.

---

## Phishing Investigation Checklist

```
[ ] 1. Retrieve and preserve original email (with headers)
[ ] 2. Analyze email headers (From, Reply-To, Return-Path, Received)
[ ] 3. Verify sender domain and SPF/DKIM/DMARC records
[ ] 4. Analyze email body (urgency language, spoofed branding)
[ ] 5. Extract and analyze all URLs (do NOT click — use sandbox)
[ ] 6. Extract and analyze attachments (do NOT open — use sandbox)
[ ] 7. Identify IOCs (sender IP, URLs, file hashes, domains)
[ ] 8. Check IOCs against threat intelligence
[ ] 9. Determine scope (how many users received this email?)
[ ] 10. Contain, remediate, and document
```

---

## Email Header Analysis

### Key Header Fields

| Header | Description | What to Look For |
|---|---|---|
| `From` | Display name and address | Spoofed name, mismatched domain |
| `Reply-To` | Address replies go to | Different from From address |
| `Return-Path` | Bounce address | Different domain = suspicious |
| `Received` | Server hop chain (read bottom-up) | Originating IP, unexpected relay |
| `X-Originating-IP` | Original sender IP | Check against VirusTotal |
| `Message-ID` | Unique message identifier | Domain in ID should match sender |
| `X-Mailer` | Email client used | PHPMailer, Python = bulk sender |
| `Authentication-Results` | SPF/DKIM/DMARC results | FAIL = spoofed domain |

### How to Read Received Headers
```
Received headers are added by each mail server.
Read from BOTTOM (origin) to TOP (destination).

Example chain:
[3] Received: by mx.victim.com (final destination)
[2] Received: from relay.mailservice.com
[1] Received: from attacker-server.com (ORIGIN)
                 by relay.mailservice.com

The bottom-most Received header = originating IP of attacker.
```

### SPF / DKIM / DMARC Quick Reference
```
SPF   (Sender Policy Framework)  — Did email come from authorized server?
DKIM  (DomainKeys Identified Mail) — Was email signed by sending domain?
DMARC (Domain-based Message Auth.) — Policy: what to do on SPF/DKIM fail?

Results in Authentication-Results header:
  spf=pass   → Authorized sender
  spf=fail   → Spoofed or unauthorized server
  dkim=pass  → Signature valid
  dkim=fail  → Email modified or spoofed
  dmarc=pass → Policy satisfied
  dmarc=fail → Likely phishing/spoofing
```

---

## URL Analysis (Safe Methods)

### NEVER click suspicious links directly. Use these methods:

```
1. URL Defanging: Replace . with [.] and :// with ://
   Example: hxxps://evil[.]com/malware

2. Online Sandboxes:
   - URLScan.io     — Screenshot + DNS + HTTP analysis
   - VirusTotal     — Multi-AV URL check
   - Any.run        — Interactive malware analysis
   - Hybrid Analysis — Detailed behavioral analysis

3. Manual inspection:
   - Check domain registration (WHOIS) — new domain = suspicious
   - Check domain reputation (VirusTotal, Cisco Talos)
   - Look for lookalike domains (paypa1.com, micros0ft.com)
   - Analyze URL structure for redirect chains
```

### Red Flags in URLs
```
- IP address instead of domain: http://185.23.45.67/login
- Lookalike domain: paypa1[.]com, arnazon[.]com
- URL shortener: bit.ly, tinyurl (hide final destination)
- Excessive subdomains: login.account.secure.paypal.evil[.]com
- Non-HTTPS for login pages
- Newly registered domain (< 30 days old)
- Random character strings in path
```

---

## Attachment Analysis (Safe Methods)

```
1. NEVER open attachments on production systems.

2. Get file hash first (md5sum, sha256sum)
   md5sum suspicious.docx
   sha256sum suspicious.exe

3. Check hash on VirusTotal (File search)

4. Upload to sandbox for behavioral analysis:
   - Any.run (interactive)
   - Hybrid Analysis
   - Joe Sandbox
   - Cuckoo Sandbox (self-hosted)

5. Static analysis (without execution):
   - ExifTool   — metadata extraction
   - olevba     — macro analysis in Office files
   - pdfid      — PDF structure analysis
   - strings    — extract readable strings from binary
```

### Suspicious Attachment Types
| Type | Common Threat | Tool |
|---|---|---|
| .docm / .xlsm | Malicious macros | olevba, oledump |
| .pdf | Embedded JavaScript, links | pdfid, pdf-parser |
| .html | Credential harvesting page | Browser + urlscan |
| .exe / .dll | Malware dropper | Any.run, VT |
| .zip / .rar | Packed malware | Extract + analyze |
| .lnk | PowerShell stager | strings, exiftool |
| .iso | UAC bypass technique | Mount + analyze |

---

## IOC Extraction from Phishing Email

```
From email headers:
- Sender IP (from bottom Received header)
- Sending domain
- Reply-To domain
- Return-Path domain
- Message-ID domain

From email body:
- URLs (defanged)
- Redirector URLs
- Domains mentioned
- Phone numbers (vishing component)

From attachments:
- File hash (MD5, SHA256)
- Embedded URLs
- Macro execution strings
- Dropped file hashes
- C2 IP/domain contacted
```

---

## Containment & Remediation

```
Immediate Actions:
1. Block sender domain/IP at email gateway
2. Block malicious URLs at proxy/firewall
3. Search for other users who received same email
4. If user clicked: isolate endpoint, begin IR process
5. Reset credentials if user entered them

Threat Intelligence:
6. Report IOCs to threat intel platform
7. Submit to VirusTotal, abuse.ch, phishtank
8. Create SIEM detection rule for similar emails

User Notification:
9. Notify affected user(s)
10. Send awareness reminder to all users
11. Document timeline and actions taken
```

---

## Useful Tools Summary

| Tool | Purpose | URL |
|---|---|---|
| MXToolbox | Email header analyzer | mxtoolbox.com/EmailHeaders |
| URLScan.io | URL screenshot + analysis | urlscan.io |
| VirusTotal | Multi-AV file/URL/IP check | virustotal.com |
| Any.run | Interactive sandbox | any.run |
| PhishTool | Phishing email analysis | phishtool.com |
| AbuseIPDB | IP reputation check | abuseipdb.com |
| WHOIS | Domain registration info | whois.domaintools.com |
| olevba | Office macro analysis | pip install oletools |

---

## Notes

- Document every step with timestamps for the incident report.
- Always defang IOCs before sharing (replace . with [.]).
- Check if phishing is targeted (spear phishing) or mass campaign.
- Correlate with endpoint logs to check if malware was executed.
