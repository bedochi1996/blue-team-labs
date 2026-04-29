# Windows Event Log Analysis — Lab Notes

> **Purpose:** Practical reference for SOC analysts during alert triage and incident investigation.
> **Source:** Personal lab notes from TryHackMe, LetsDefend, and simulated environments.

---

## Key Security Event IDs Reference

| Event ID | Channel | Description | SOC Use Case |
|---|---|---|---|
| 4624 | Security | Successful Logon | Baseline activity, detect anomalous logons |
| 4625 | Security | Failed Logon | Brute force detection |
| 4634 | Security | Account Logoff | Session tracking |
| 4648 | Security | Logon with Explicit Credentials | Pass-the-hash / lateral movement |
| 4656 | Security | Handle to Object Requested | File/registry access attempts |
| 4663 | Security | Access to Object Attempted | Data access monitoring |
| 4672 | Security | Special Privileges Assigned | Privileged account usage |
| 4688 | Security | New Process Created | Malware execution, suspicious process |
| 4698 | Security | Scheduled Task Created | Persistence mechanism |
| 4720 | Security | User Account Created | Unauthorized account detection |
| 4724 | Security | Password Reset Attempt | Credential manipulation |
| 4728 | Security | Member Added to Global Group | Privilege escalation |
| 4732 | Security | Member Added to Local Group | Local privilege escalation |
| 4768 | Security | Kerberos TGT Requested | Kerberoasting pre-detection |
| 4769 | Security | Kerberos TGS Requested | Kerberoasting / service ticket abuse |
| 4776 | Security | NTLM Authentication | Pass-the-hash detection |
| 7045 | System | New Service Installed | Persistence / malware installation |
| 1102 | Security | Audit Log Cleared | Anti-forensics indicator |
| 4104 | PowerShell | Script Block Logging | Malicious PowerShell detection |

---

## Logon Types Reference

| Logon Type | Description | Threat Relevance |
|---|---|---|
| 2 | Interactive (local keyboard) | Normal workstation access |
| 3 | Network | Lateral movement indicator |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service account activity |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Cleartext credentials — suspicious |
| 9 | NewCredentials | runas /netonly — common in PTH attacks |
| 10 | RemoteInteractive | RDP logon |
| 11 | CachedInteractive | Offline logon |

---

## Attack Patterns in Event Logs

### Brute Force (T1110)
```
Pattern: Many Event ID 4625 (failed) from same SourceIP → single 4624 (success)
Filter (Splunk): index=wineventlog EventCode=4625 | stats count by src_ip | where count > 50
Key fields: TargetUserName, IpAddress, LogonType, FailureReason
```

### Pass-the-Hash (T1550.002)
```
Pattern: Event 4624 LogonType=3 with AuthPackage=NTLM from unexpected host
Pattern: Event 4648 showing explicit credentials usage
Key fields: AuthenticationPackageName=NTLM, LogonType=3, WorkstationName
```

### Lateral Movement via RDP (T1021.001)
```
Pattern: Event 4624 LogonType=10 from unusual source
Correlate with: Security log on destination + Source's process creation logs
Key fields: IpAddress, TargetUserName, LogonType=10
```

### Persistence via Scheduled Task (T1053.005)
```
Pattern: Event 4698 (task created) shortly after initial access
Filter: index=wineventlog EventCode=4698
Key fields: TaskName, TaskContent (check for encoded commands)
```

### Audit Log Clearing (T1070.001)
```
Pattern: Event 1102 — immediate indicator of anti-forensics
Action: Escalate immediately, assume compromise
Key fields: SubjectUserName, TimeCreated
```

### PowerShell Abuse (T1059.001)
```
Pattern: Event 4104 with encoded commands (-EncodedCommand, -enc)
Suspicious strings: IEX, DownloadString, Invoke-Expression, bypass, hidden
Filter: index=wineventlog EventCode=4104 ScriptBlockText=*encodedcommand*
```

---

## Investigation Workflow

```
1. Receive alert from SIEM
2. Identify relevant Event IDs for the alert type
3. Collect context:
   - Source IP / Hostname
   - Username (local vs domain)
   - Timestamp and duration
   - LogonType
4. Correlate across log sources:
   - Security log (authentication)
   - System log (services, reboots)
   - Application log (application errors)
   - PowerShell log (script execution)
5. Check IOCs against threat intel
6. Determine: False Positive or True Positive
7. Escalate or close with documentation
```

---

## Useful Splunk SPL for Windows Logs

```spl
-- Failed logins by source IP (brute force detection)
index=wineventlog EventCode=4625
| stats count by IpAddress, TargetUserName
| where count > 20
| sort -count

-- Privileged logons outside business hours
index=wineventlog EventCode=4672
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, TargetUserName, IpAddress

-- New user accounts created
index=wineventlog EventCode=4720
| table _time, SubjectUserName, TargetUserName, TargetSid

-- Scheduled tasks created
index=wineventlog EventCode=4698
| table _time, SubjectUserName, TaskName, TaskContent
```

---

## Notes

- Enable **Process Creation** logging (Event 4688 with command line) via Group Policy for full visibility.
- **PowerShell ScriptBlock Logging** must be enabled explicitly — not on by default.
- **Sysmon** provides significantly better process and network telemetry than native Windows logging.
- Always correlate multiple Event IDs — no single event tells the full story.
