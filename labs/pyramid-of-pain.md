# Pyramid of Pain

## Overview
Completed an intensive practical lab on the **Pyramid of Pain** model by David Bianco on TryHackMe.

This model is more than just a diagram — it's a Blue Team philosophy that dictates how to make a cyberattack painful and expensive for the adversary.

## The Core Concept

> "Blocking an IP or a Hash isn't a defensive victory; it's a minor delay for a well-equipped adversary. Real defense? Disrupting their TTPs — that's where you hit them where it hurts."

The Pyramid of Pain is a framework that shows the increasing difficulty (pain) an attacker experiences when defenders detect and block different types of indicators.

## The Pyramid Levels (Bottom to Top)

### Level 1: Hash Values (Trivial)
**Pain Level for Attacker**: Trivial 🟢

- **What**: File hashes (MD5, SHA1, SHA256)
- **Detection**: Easy to identify malicious files
- **Attacker Response**: Extremely easy to bypass
  - Change one byte → New hash
  - Recompile malware → New hash
  - Use polymorphic malware
- **Defensive Value**: Minimal
- **Example**: Blocking a specific malware sample hash

**Reality Check**: Relying on hash blocking alone creates a false sense of security.

### Level 2: IP Addresses (Easy)
**Pain Level for Attacker**: Easy 🟢

- **What**: Source/destination IP addresses
- **Detection**: Identify command and control (C2) servers
- **Attacker Response**: Simple to change
  - Use VPN/Proxy
  - Compromised legitimate servers
  - Cloud infrastructure (AWS, Azure)
  - Fast-flux DNS
- **Defensive Value**: Low
- **Example**: Blocking a known C2 IP address

**Reality Check**: Attackers can spin up new infrastructure in minutes.

### Level 3: Domain Names (Simple)
**Pain Level for Attacker**: Simple 🟡

- **What**: Malicious domain names
- **Detection**: DNS monitoring, domain reputation
- **Attacker Response**: Requires more effort
  - Register new domains
  - Use domain generation algorithms (DGA)
  - Compromised legitimate domains
- **Defensive Value**: Moderate
- **Cost for Attacker**: Registration fees, time

**Better than IPs**, but still relatively easy to bypass.

### Level 4: Network/Host Artifacts (Annoying)
**Pain Level for Attacker**: Annoying 🟠

- **What**: Observable patterns in network traffic or host behavior
  - User-Agent strings
  - C2 callback patterns
  - Registry keys
  - File paths
  - Service names
- **Detection**: Behavioral analysis, anomaly detection
- **Attacker Response**: Requires retooling
  - Modify malware configuration
  - Change communication patterns
  - Adjust persistence mechanisms
- **Defensive Value**: Good

**This level starts causing real friction** for the attacker.

### Level 5: Tools (Challenging)
**Pain Level for Attacker**: Challenging 🟠

- **What**: Specific software/tools used by attackers
  - Mimikatz
  - Cobalt Strike
  - PowerShell Empire
  - Custom malware
- **Detection**: Tool signatures, behavior patterns
- **Attacker Response**: Significant effort required
  - Find alternative tools
  - Develop custom tools
  - Modify existing tools significantly
- **Defensive Value**: High
- **Cost for Attacker**: Time, money, development resources

**Detecting and blocking tools** forces attackers to invest significant resources.

### Level 6: TTPs (Tactics, Techniques, Procedures) - Tough!
**Pain Level for Attacker**: **EXCRUCIATING** 🔴

- **What**: The attacker's methods, behaviors, and operational patterns
  - **Tactics**: The "why" (objectives)
  - **Techniques**: The "how" (methods)
  - **Procedures**: The "detailed steps"
- **Detection**: MITRE ATT&CK mapping, behavioral analytics
- **Attacker Response**: **EXTREMELY DIFFICULT**
  - Must fundamentally change operational methods
  - Requires complete strategy overhaul
  - May need to rebuild entire attack infrastructure
  - Training, tools, and tradecraft must all change
- **Defensive Value**: **MAXIMUM**

**Examples of TTPs**:
- Credential dumping techniques
- Lateral movement patterns
- Persistence mechanisms
- Data exfiltration methods
- Command and control techniques

**This is the knockout blow**. When you detect and disrupt TTPs, the attacker must fundamentally change how they operate.

## Key Insights

### The Paradigm Shift

🚨 **Don't chase indicators — hunt behaviors**

Mastering this pyramid transitions you from a **"Reactive" defender** to a **"Proactive" Threat Hunter**.

### Why TTPs Matter Most

1. **Persistence**: TTPs change slowly (attackers are creatures of habit)
2. **Cost**: Changing TTPs requires major investment
3. **Detection**: Behavioral detection catches unknown threats
4. **Intelligence**: Understanding TTPs reveals adversary capabilities

### Real-World Application

**Scenario**: Ransomware attack detected

**Weak Response** (Bottom of Pyramid):
- Block the ransomware file hash
- Block the C2 IP address
- **Result**: Attacker returns tomorrow with new hash and IP

**Strong Response** (Top of Pyramid):
- Identify the TTP: "PowerShell used for credential dumping"
- Detect the pattern: "WMI used for lateral movement"
- Block the behavior: "Unusual network connections from workstations"
- **Result**: Attacker must completely change their methodology

## SOC Analyst Takeaways

1. **Don't celebrate blocking an IP or hash** — it's not a real win
2. **Focus detection on behaviors** (TTPs), not just indicators
3. **Map detections to MITRE ATT&CK** framework
4. **Build behavioral analytics** in your SIEM
5. **Threat intelligence should focus on TTPs**, not just IoCs

## Detection Strategy

### Pyramid-Aware Detection Architecture

```
Lower Pyramid (IoCs):
- Quick wins, automated blocking
- Threat intelligence feeds
- Limited long-term value

Upper Pyramid (TTPs):
- Behavioral detection rules
- Anomaly detection
- UEBA (User and Entity Behavior Analytics)
- High long-term value
```

### Building TTP-Based Detections

1. **Map your environment to MITRE ATT&CK**
2. **Identify critical techniques** for your threat landscape
3. **Build detections for behaviors**, not signatures
4. **Test with adversary emulation** (Atomic Red Team, Caldera)
5. **Continuously refine** based on false positives/negatives

## Discussion Question

**Question for the Blue Team community**:

Beyond IPs and Hashes, which **Tactic** or **Technique** have you found to be the most "painful" for adversaries to lose access to?

Share your experience:
- What TTP did you detect?
- How did it impact the attacker's operation?
- What was your detection method?

## Resources

- [TryHackMe: Pyramid of Pain](https://tryhackme.com)
- [David Bianco's Original Blog Post](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- Recommended Reading: "Intelligence-Driven Incident Response" by Scott Roberts & Rebekah Brown

## Final Thought

> "The attacker can change their tools in minutes. But they cannot change their pattern without leaving a trace in the logs. We hunt behavior, not tools."

---
**Tags:** #PyramidOfPain #ThreatHunting #BlueTeam #SOC #TTPs #MITREATTACK #IncidentResponse #CyberDefense #TryHackMe #CyberSecurity
