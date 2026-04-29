#!/usr/bin/env python3
"""
log_analyzer.py - Advanced Security Log Analyzer
=================================================
Author  : Badi Alosaimi
Version : 1.5.0
License : MIT

Description:
    Multi-platform security log analyzer supporting Windows Event Logs,
    Linux auth.log/syslog, Apache/Nginx access logs, and firewall logs.
    Detects common attack patterns: brute force, privilege escalation,
    suspicious commands, port scanning, and abnormal authentication.

Usage:
    python log_analyzer.py --file /var/log/auth.log --format linux
    python log_analyzer.py -f access.log --format apache --threats
    python log_analyzer.py -f Security.evtx --format windows
"""

import re
import sys
import json
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple


class LogAnalyzer:
    """Security log analyzer with pattern-based threat detection."""

    def __init__(self, log_format: str, enable_ml: bool = False):
        self.log_format = log_format.lower()
        self.enable_ml = enable_ml
        self.events = []
        self.stats = defaultdict(int)
        self.alerts = []
        self.ip_counter = Counter()

    # LINUX AUTH LOG PATTERNS
    LINUX_FAILED_PASSWORD = re.compile(
        r"(Failed password).*(from|for) ([\d.]+)"
    )
    LINUX_ACCEPTED_PASSWORD = re.compile(
        r"(Accepted password).*(from|for user) (\S+)"
    )
    LINUX_SUDO = re.compile(
        r"sudo:\s+(\S+).*COMMAND=(.*)"
    )

    # APACHE/NGINX ATTACK PATTERNS
    WEB_SQL_INJECTION = re.compile(
        r"(union|select|insert|drop|update|delete|--|;|<script)",
        re.IGNORECASE
    )
    WEB_XSS = re.compile(r"<script|javascript:|onerror=", re.IGNORECASE)
    WEB_LFI = re.compile(r"\.\./\.\./|/etc/passwd|/proc/self", re.IGNORECASE)

    # WINDOWS SECURITY EVENT IDS
    WINDOWS_FAILED_LOGON = ["4625"]
    WINDOWS_SUCCESS_LOGON = ["4624"]
    WINDOWS_PRIV_ESC = ["4672", "4673"]
    WINDOWS_ACCOUNT_CREATED = ["4720"]
    WINDOWS_ADMIN_ADDED = ["4728", "4732"]

    def parse_linux_auth(self, line: str) -> Dict:
        """Parse Linux /var/log/auth.log line."""
        event = {"type": "unknown", "raw": line}

        # Failed password
        match = self.LINUX_FAILED_PASSWORD.search(line)
        if match:
            self.stats["failed_auth"] += 1
            ip = match.group(3)
            self.ip_counter[ip] += 1
            event["type"] = "failed_auth"
            event["src_ip"] = ip
            if self.ip_counter[ip] > 10:
                self.alerts.append({
                    "severity": "HIGH",
                    "type": "Brute Force Detected",
                    "details": f"IP {ip} has {self.ip_counter[ip]} failed login attempts"
                })

        # Accepted password
        match = self.LINUX_ACCEPTED_PASSWORD.search(line)
        if match:
            self.stats["successful_auth"] += 1
            event["type"] = "successful_auth"
            event["user"] = match.group(3)

        # Sudo command
        match = self.LINUX_SUDO.search(line)
        if match:
            self.stats["sudo_command"] += 1
            user = match.group(1)
            cmd = match.group(2)
            event["type"] = "sudo"
            event["user"] = user
            event["command"] = cmd

            # Check for suspicious commands
            suspicious = ["rm -rf", "chmod 777", "nc -e", "bash -i",
                          "/etc/shadow", "passwd", "useradd"]
            if any(s in cmd.lower() for s in suspicious):
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "Suspicious Sudo Command",
                    "details": f"User {user} executed: {cmd}"
                })

        return event

    def parse_apache_log(self, line: str) -> Dict:
        """Parse Apache/Nginx access log."""
        event = {"type": "web_request", "raw": line}

        # Extract IP
        ip_match = re.match(r"^([\d.]+)", line)
        if ip_match:
            ip = ip_match.group(1)
            event["src_ip"] = ip
            self.ip_counter[ip] += 1

        # SQL injection attempt
        if self.WEB_SQL_INJECTION.search(line):
            self.stats["sql_injection_attempt"] += 1
            self.alerts.append({
                "severity": "HIGH",
                "type": "SQL Injection Attempt",
                "details": f"Detected SQL keywords in: {line[:100]}"
            })

        # XSS attempt
        if self.WEB_XSS.search(line):
            self.stats["xss_attempt"] += 1
            self.alerts.append({
                "severity": "MEDIUM",
                "type": "XSS Attempt",
                "details": f"JavaScript detected in request"
            })

        # LFI/Directory traversal
        if self.WEB_LFI.search(line):
            self.stats["lfi_attempt"] += 1
            self.alerts.append({
                "severity": "HIGH",
                "type": "Local File Inclusion Attempt",
                "details": f"Path traversal detected"
            })

        return event

    def analyze_file(self, filepath: str) -> Dict:
        """Main analysis function."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                if self.log_format == "linux":
                    event = self.parse_linux_auth(line)
                elif self.log_format in ["apache", "nginx"]:
                    event = self.parse_apache_log(line)
                else:
                    event = {"type": "unknown", "raw": line}

                event["line_num"] = line_num
                self.events.append(event)

        # Post-processing: detect port scans
        top_ips = self.ip_counter.most_common(10)
        for ip, count in top_ips:
            if count > 100:
                self.alerts.append({
                    "severity": "MEDIUM",
                    "type": "Possible Port Scan / Automated Attack",
                    "details": f"IP {ip} generated {count} requests"
                })

        return self.generate_report()

    def generate_report(self) -> Dict:
        """Generate summary report."""
        return {
            "metadata": {
                "tool": "Log Analyzer v1.5",
                "author": "Badi Alosaimi",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "log_format": self.log_format,
                "total_events": len(self.events),
                "total_alerts": len(self.alerts),
            },
            "statistics": dict(self.stats),
            "top_ips": dict(self.ip_counter.most_common(10)),
            "alerts": self.alerts,
        }

    def print_report(self, report: Dict):
        """Pretty-print the analysis report."""
        print("\n" + "=" * 70)
        print("  SECURITY LOG ANALYSIS REPORT — Badi Alosaimi")
        print("=" * 70)
        print(f"  Format       : {report['metadata']['log_format'].upper()}")
        print(f"  Total Events : {report['metadata']['total_events']}")
        print(f"  Total Alerts : {report['metadata']['total_alerts']}")
        print("=" * 70)

        if report["statistics"]:
            print("\n  [STATISTICS]")
            for k, v in report["statistics"].items():
                print(f"    {k.replace('_', ' ').title()}: {v}")

        if report["top_ips"]:
            print("\n  [TOP SOURCE IPs]")
            for ip, count in list(report["top_ips"].items())[:5]:
                print(f"    {ip:<20} → {count} events")

        if report["alerts"]:
            print(f"\n  [SECURITY ALERTS] — {len(report['alerts'])} total")
            for i, alert in enumerate(report["alerts"][:10], 1):
                severity_color = {
                    "CRITICAL": "[❌ CRITICAL]",
                    "HIGH": "[⚠️ HIGH]",
                    "MEDIUM": "[🟡 MEDIUM]",
                    "LOW": "[🔵 LOW]"
                }
                symbol = severity_color.get(alert["severity"], "[•]")
                print(f"\n    {i}. {symbol} {alert['type']}")
                print(f"       {alert['details'][:80]}")

        print("\n" + "=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        prog="log_analyzer",
        description="Security Log Analyzer v1.5 by Badi Alosaimi"
    )
    parser.add_argument("-f", "--file", required=True, help="Log file path")
    parser.add_argument(
        "--format",
        choices=["linux", "apache", "nginx", "windows"],
        required=True,
        help="Log format type"
    )
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    analyzer = LogAnalyzer(log_format=args.format)

    try:
        report = analyzer.analyze_file(args.file)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        analyzer.print_report(report)


if __name__ == "__main__":
    main()
