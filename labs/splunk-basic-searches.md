# Splunk SPL — SOC Analyst Reference

> **Purpose:** Essential SPL (Search Processing Language) commands for SOC alert triage and threat hunting.
> **Source:** Personal lab notes from Splunk training, TryHackMe, and simulated SOC exercises.

---

## SPL Fundamentals

### Basic Search Syntax
```spl
-- Basic keyword search
index=main "failed login"

-- Search with time range
index=main earliest=-24h latest=now

-- Search specific source type
index=main sourcetype=WinEventLog

-- Multiple conditions (AND is implicit)
index=main EventCode=4625 host=DC01

-- OR condition
index=main (EventCode=4624 OR EventCode=4625)

-- NOT condition
index=main NOT (user=service_account)

-- Wildcard
index=main user=admin*
```

### Field Searching
```spl
-- Search for specific field value
index=main src_ip="192.168.1.100"

-- Field exists
index=main | where isnotnull(src_ip)

-- Field comparison
index=main | where bytes_out > 1000000

-- Field contains string
index=main | where like(uri, "%/admin%")
```

---

## Essential SPL Commands

### stats — Aggregate Data
```spl
-- Count events by field
index=main | stats count by src_ip

-- Count, sum, avg grouped by field
index=main | stats count, sum(bytes) as total_bytes, avg(bytes) as avg_bytes by src_ip

-- Count distinct values
index=main | stats dc(user) as unique_users by src_ip

-- Multiple aggregations
index=main | stats count as login_attempts, max(_time) as last_attempt by src_ip, user
```

### table — Display Specific Fields
```spl
index=main | table _time, src_ip, user, EventCode, action
```

### sort — Order Results
```spl
-- Sort ascending
index=main | stats count by src_ip | sort count

-- Sort descending
index=main | stats count by src_ip | sort -count

-- Sort by multiple fields
index=main | sort -count, +src_ip
```

### where — Filter Results
```spl
-- Numeric comparison
index=main | stats count by src_ip | where count > 100

-- String match
index=main | where user="administrator"

-- Time-based filter
index=main | where _time > relative_time(now(), "-1h")
```

### eval — Create New Fields
```spl
-- Create calculated field
index=main | eval mb_transferred = bytes / 1048576

-- Conditional field
index=main | eval severity = if(count > 100, "High", "Low")

-- String manipulation
index=main | eval domain = lower(host)

-- Time formatting
index=main | eval readable_time = strftime(_time, "%Y-%m-%d %H:%M:%S")
```

### timechart — Time-Based Visualization
```spl
-- Events over time
index=main | timechart count

-- Events by field over time
index=main | timechart count by action

-- Span control
index=main | timechart span=1h count by src_ip
```

### rename — Rename Fields
```spl
index=main | stats count by src_ip | rename src_ip as "Source IP", count as "Event Count"
```

### dedup — Remove Duplicates
```spl
-- Remove duplicate src_ip entries
index=main | dedup src_ip

-- Keep most recent per field
index=main | dedup src_ip sortby -_time
```

### rex — Extract Fields with Regex
```spl
-- Extract username from log message
index=main | rex "User: (?P<username>[\\w]+)"

-- Extract IP from message
index=main | rex "from (?P<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"
```

---

## SOC Detection Searches

### Brute Force Detection
```spl
index=wineventlog EventCode=4625
| stats count as failed_attempts by src_ip, TargetUserName
| where failed_attempts > 20
| sort -failed_attempts
| table src_ip, TargetUserName, failed_attempts
```

### Successful Login After Many Failures
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes
        by src_ip, TargetUserName
| where failures > 10 AND successes >= 1
| table src_ip, TargetUserName, failures, successes
```

### After-Hours Privileged Logons
```spl
index=wineventlog EventCode=4672
| eval hour=strftime(_time, "%H")
| where hour < "07" OR hour > "19"
| table _time, TargetUserName, IpAddress, hour
| sort -_time
```

### New User Account Creation
```spl
index=wineventlog EventCode=4720
| table _time, SubjectUserName, TargetUserName, TargetSid
| sort -_time
```

### PowerShell Suspicious Activity
```spl
index=wineventlog EventCode=4104
| where like(lower(ScriptBlockText), "%encodedcommand%")
   OR like(lower(ScriptBlockText), "%downloadstring%")
   OR like(lower(ScriptBlockText), "%iex%")
   OR like(lower(ScriptBlockText), "%bypass%")
| table _time, ComputerName, ScriptBlockText
| sort -_time
```

### Network Beaconing Detection
```spl
index=network dest_ip="<suspect_ip>"
| bucket _time span=5m
| stats count by _time, dest_ip
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by dest_ip
| where abs(count - avg_count) < stdev_count
| table _time, dest_ip, count
```

### DNS Query Analysis
```spl
index=dns
| stats count by query
| sort -count
| head 50
| table query, count
```

### Large File Transfers (Exfiltration)
```spl
index=network
| stats sum(bytes_out) as total_bytes_out by src_ip, dest_ip
| eval mb_out = round(total_bytes_out / 1048576, 2)
| where mb_out > 100
| sort -mb_out
| table src_ip, dest_ip, mb_out
```

---

## Lookup and Enrichment

```spl
-- Lookup IP against known bad list
index=network
| lookup threat_intel_ips ip as dest_ip OUTPUT reputation
| where reputation="malicious"

-- Lookup user info
index=wineventlog
| lookup users_lookup username as TargetUserName OUTPUT department, manager
| table _time, TargetUserName, department, manager, EventCode
```

---

## Dashboard Panel Searches

```spl
-- Top 10 source IPs (last 24h)
index=network earliest=-24h
| stats count by src_ip
| sort -count
| head 10

-- Alert severity over time
index=alerts earliest=-7d
| timechart span=1h count by severity

-- Open incidents count
index=incidents status="open"
| stats count as open_incidents
```

---

## Notes

- Splunk time range: use `earliest` and `latest` or the time picker in the UI.
- `_time` is stored in Unix epoch format — use `strftime()` to convert to human-readable.
- Always use `| head N` to limit large result sets during investigation.
- Saved searches can be set as alerts with threshold conditions.
- Use `| outputlookup` to export search results to a CSV lookup table.
