# MITRE ATT&CK Mapping — SOC Lab Notes

> **Purpose:** Practical guide for mapping security alerts and incidents to MITRE ATT&CK framework.
> **Source:** Personal lab notes from TryHackMe, Blue Team exercises, and SOC simulations.

---

## MITRE ATT&CK Overview

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.

```
Matrix Structure:
Tactic (Why) → Technique (How) → Sub-Technique (Specific method)

Example:
TA0006: Credential Access (Tactic)
  └─ T1110: Brute Force (Technique)
       ├─ T1110.001: Password Guessing
       ├─ T1110.002: Password Cracking
       ├─ T1110.003: Password Spraying
       └─ T1110.004: Credential Stuffing
```

---

## The 14 MITRE ATT&CK Tactics (Enterprise)

| ID | Tactic | Description |
|---|---|---|
| TA0043 | Reconnaissance | Gathering info before attack |
| TA0042 | Resource Development | Building infrastructure |
| TA0001 | Initial Access | Getting into the environment |
| TA0002 | Execution | Running malicious code |
| TA0003 | Persistence | Maintaining foothold |
| TA0004 | Privilege Escalation | Gaining higher permissions |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Exploring the environment |
| TA0008 | Lateral Movement | Moving through the network |
| TA0009 | Collection | Gathering target data |
| TA0010 | Exfiltration | Stealing data out |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0040 | Impact | Disrupting / destroying systems |

---

## Common Techniques by SOC Alert Type

### Brute Force Alerts
```
Alert: Multiple failed logins (Event ID 4625)

MITRE Mapping:
  TA0006 — Credential Access
    T1110     — Brute Force
    T1110.001 — Password Guessing (trying common passwords)
    T1110.003 — Password Spraying (one password, many users)
    T1110.004 — Credential Stuffing (breached credentials)

If successful login follows:
  TA0001 — Initial Access
    T1078 — Valid Accounts
```

### Phishing Alerts
```
Alert: Suspicious email with malicious link / attachment

MITRE Mapping:
  TA0001 — Initial Access
    T1566     — Phishing
    T1566.001 — Spearphishing Attachment
    T1566.002 — Spearphishing Link
    T1566.003 — Spearphishing via Service

If user clicked and malware executed:
  TA0002 — Execution
    T1059.001 — PowerShell
    T1059.003 — Windows Command Shell
    T1204.002 — Malicious File (user opened attachment)
```

### C2 Beaconing Alerts
```
Alert: Periodic outbound connections to unknown IP

MITRE Mapping:
  TA0011 — Command and Control
    T1071     — Application Layer Protocol
    T1071.001 — Web Protocols (HTTP/HTTPS C2)
    T1071.004 — DNS (DNS tunneling)
    T1095     — Non-Application Layer Protocol (raw TCP/UDP)
    T1132     — Data Encoding (encoded C2 traffic)
    T1573     — Encrypted Channel
    T1573.001 — Symmetric Cryptography
    T1573.002 — Asymmetric Cryptography (TLS)
    T1008     — Fallback Channels
```

### Lateral Movement Alerts
```
Alert: RDP/SMB connection between internal hosts

MITRE Mapping:
  TA0008 — Lateral Movement
    T1021     — Remote Services
    T1021.001 — Remote Desktop Protocol (RDP)
    T1021.002 — SMB/Windows Admin Shares
    T1021.006 — Windows Remote Management (WinRM)
    T1550.002 — Pass the Hash
    T1550.003 — Pass the Ticket (Kerberos)
```

### Persistence Alerts
```
Alert: New scheduled task or service created

MITRE Mapping:
  TA0003 — Persistence
    T1053.005 — Scheduled Task/Job: Scheduled Task
    T1543.003 — Create or Modify System Process: Windows Service
    T1547.001 — Boot or Logon Autostart: Registry Run Keys
    T1136.001 — Create Account: Local Account
    T1078     — Valid Accounts (using existing account)
```

### Data Exfiltration Alerts
```
Alert: Large data transfer to external IP

MITRE Mapping:
  TA0010 — Exfiltration
    T1041   — Exfiltration Over C2 Channel
    T1048   — Exfiltration Over Alternative Protocol
    T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
    T1567   — Exfiltration Over Web Service (cloud storage)

Preceded by:
  TA0009 — Collection
    T1005 — Data from Local System
    T1039 — Data from Network Shared Drive
    T1074 — Data Staged
```

### Defense Evasion Alerts
```
Alert: Event log cleared, AV disabled, encoded PowerShell

MITRE Mapping:
  TA0005 — Defense Evasion
    T1070.001 — Clear Windows Event Logs (Event ID 1102)
    T1562.001 — Disable or Modify Tools (AV disabled)
    T1562.002 — Disable Windows Event Logging
    T1027     — Obfuscated Files or Information
    T1027.010 — Command Obfuscation (base64 PowerShell)
    T1055     — Process Injection
```

---

## Mapping Workflow for SOC Analysts

```
Step 1: Identify what happened (observable behavior)
  "Multiple failed SSH logins followed by success"

Step 2: Identify the Tactic (the WHY)
  Credential Access (TA0006) → Initial Access (TA0001)

Step 3: Identify the Technique (the HOW)
  T1110 Brute Force → T1078 Valid Accounts

Step 4: Document in the incident report
  Format: [Tactic] [Technique ID] - Technique Name
  Example: Credential Access T1110.001 - Password Guessing

Step 5: Check ATT&CK Navigator for related techniques
  URL: https://mitre-attack.github.io/attack-navigator/
```

---

## Incident Report Format for MITRE Mapping

```markdown
## MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID | Evidence |
|---|---|---|---|---|
| 1 | Credential Access | Brute Force: Password Guessing | T1110.001 | 847 failed logins (Event 4625) |
| 2 | Initial Access | Valid Accounts | T1078 | Successful login after brute force |
| 3 | Execution | Command and Scripting Interpreter | T1059.001 | PowerShell commands executed |
| 4 | Persistence | Scheduled Task | T1053.005 | New task created post-access |
| 5 | Command & Control | Application Layer Protocol | T1071.001 | HTTP beaconing to 45.33.32.156 |
```

---

## Quick Reference: Common Techniques by Tool/Action

| Tool / Action | MITRE Technique |
|---|---|
| Nmap scan | T1595.001 - Active Scanning |
| Password spraying | T1110.003 - Password Spraying |
| Mimikatz | T1003.001 - LSASS Memory |
| PsExec | T1569.002 - Service Execution |
| PowerShell download | T1105 - Ingress Tool Transfer |
| Encoded PowerShell | T1027.010 - Command Obfuscation |
| Reg persistence | T1547.001 - Registry Run Keys |
| RDP connection | T1021.001 - Remote Desktop Protocol |
| Pass the Hash | T1550.002 - Pass the Hash |
| DLL sideloading | T1574.002 - DLL Side-Loading |
| DNS tunneling | T1071.004 - DNS |
| Log clearing | T1070.001 - Clear Windows Event Logs |

---

## Resources

- **ATT&CK Navigator:** https://mitre-attack.github.io/attack-navigator/
- **ATT&CK Matrix (Enterprise):** https://attack.mitre.org/matrices/enterprise/
- **ATT&CK Search:** https://attack.mitre.org/
- **D3FEND (Defensive Countermeasures):** https://d3fend.mitre.org/

---

## Notes

- One incident can map to MULTIPLE tactics and techniques (attack chains).
- Use MITRE ATT&CK Navigator to visualize which techniques were used per incident.
- Always map to the most specific sub-technique when available.
- Include ATT&CK mappings in all incident reports for professional documentation.
