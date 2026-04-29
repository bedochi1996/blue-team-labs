# PCAP Analysis — Lab Notes

> **Purpose:** Wireshark and network traffic analysis techniques for SOC investigation.
> **Source:** Personal lab notes from TryHackMe, LetsDefend, and simulated PCAP exercises.

---

## Essential Wireshark Display Filters

### Protocol Filters
```
http                          -- HTTP traffic only
https or tls                  -- Encrypted web traffic
dns                           -- DNS queries and responses
smb or smb2                   -- SMB file sharing
ftp                           -- FTP control channel
ftp-data                      -- FTP data transfer
ssh                           -- SSH connections
telnet                        -- Telnet (plaintext remote access)
icmp                          -- Ping / ICMP messages
arp                           -- ARP requests and replies
```

### IP and Port Filters
```
ip.addr == 192.168.1.100      -- Traffic to/from specific IP
ip.src == 10.0.0.5            -- Traffic FROM specific IP
ip.dst == 8.8.8.8             -- Traffic TO specific IP
tcp.port == 4444              -- Common C2 port
udp.port == 53                -- DNS
tcp.port == 80 or tcp.port == 443
```

### Suspicious Traffic Filters
```
-- Large data transfers (potential exfiltration)
frame.len > 1000

-- Non-standard DNS ports
dns and not (udp.port == 53 or tcp.port == 53)

-- HTTP POST requests (data submission)
http.request.method == "POST"

-- Executable file downloads
http contains ".exe" or http contains ".dll"

-- Beaconing pattern (periodic connections)
ip.dst == <C2_IP> and tcp.flags.syn == 1

-- Long connections (persistent C2)
tcp.time_delta > 60
```

---

## Attack Pattern Recognition

### C2 Beaconing
```
Indicators:
- Periodic SYN packets to same external IP at regular intervals
- Small, consistent packet sizes (heartbeat)
- Unusual ports (e.g., 4444, 8080, 1337)
- User-Agent strings not matching browser (curl, python-requests)
- JA3 hash mismatch with claimed application

Filter: ip.dst == <suspect_ip> and tcp.flags.syn == 1
Look for: Regular time intervals between packets (e.g., every 30 seconds)
```

### DNS Tunneling
```
Indicators:
- Unusually long subdomain queries (> 50 chars)
- High volume of DNS queries to single domain
- TXT record queries (used for data exfiltration)
- Non-existent domain responses with NXDOMAIN
- Encoded strings in DNS labels (base64, hex)

Filter: dns and frame.len > 200
Filter: dns.qry.name contains "=" (base64 padding)
```

### ARP Spoofing / MitM
```
Indicators:
- Multiple ARP replies for same IP from different MACs
- ARP reply without preceding request
- Gateway MAC address changing frequently

Filter: arp.opcode == 2 (ARP replies only)
Filter: arp.duplicate-address-detected
```

### Port Scanning (Nmap)
```
Indicators:
- SYN packets to many ports with RST responses
- Sequential port targeting from single source
- Short time window with many connections

Filter: tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### Data Exfiltration via HTTP
```
Indicators:
- Large HTTP POST to external IP (not known CDN/SaaS)
- Base64-encoded payloads in POST body
- Unusual User-Agent strings
- HTTP to non-standard ports

Filter: http.request.method == "POST" and http.content_length > 10000
```

---

## PCAP Investigation Workflow

```
Step 1: Get overview
  - Statistics > Protocol Hierarchy (see traffic composition)
  - Statistics > Conversations (top talkers by IP)
  - Statistics > Endpoints (unique hosts)

Step 2: Identify suspicious IPs
  - Look for unknown external IPs with high traffic
  - Check IPs against VirusTotal / AbuseIPDB
  - Look for GeoIP anomalies (unexpected countries)

Step 3: Investigate protocols
  - HTTP: Check request/response, URIs, User-Agents
  - DNS: Check queried domains, response sizes
  - SMTP: Check for phishing email traffic
  - FTP/Telnet: Extract credentials (plaintext!)

Step 4: Follow streams
  - Right-click packet > Follow > TCP/UDP/HTTP Stream
  - Read the full conversation in plaintext
  - Extract files: File > Export Objects > HTTP

Step 5: Timeline reconstruction
  - Sort by time, map sequence of events
  - Correlate with SIEM/endpoint logs
```

---

## tshark Command-Line Reference

```bash
# Read pcap and display as text
tshark -r capture.pcap

# Filter HTTP requests
tshark -r capture.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri

# Extract all DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Show top talkers
tshark -r capture.pcap -qz conv,ip

# Export HTTP objects
tshark -r capture.pcap --export-objects http,./exported_files/

# Show TCP connections with duration
tshark -r capture.pcap -qz conv,tcp

# Filter by IP and port
tshark -r capture.pcap -Y 'ip.addr==192.168.1.100 and tcp.port==80'
```

---

## IOC Extraction from PCAP

| IOC Type | How to Extract |
|---|---|
| IP Addresses | Statistics > Endpoints > IPv4 |
| Domains | DNS query names (dns.qry.name) |
| URLs | http.request.full_uri |
| User-Agents | http.user_agent |
| File hashes | Export HTTP objects, hash with md5sum |
| Email addresses | smtp/pop3/imap streams |
| JA3 hashes | ja3 or ja3s fields (TLS fingerprint) |

---

## Notes

- Always analyze PCAP in an isolated environment.
- Use **NetworkMiner** for automatic file extraction and host enumeration.
- Check JA3/JA3S hashes against [sslbl.abuse.ch](https://sslbl.abuse.ch) for known malware TLS fingerprints.
- **Zeek** (formerly Bro) converts PCAPs into structured logs easier to query than raw packets.
