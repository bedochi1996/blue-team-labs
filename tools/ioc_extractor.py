#!/usr/bin/env python3
"""
ioc_extractor.py - Automated IOC (Indicator of Compromise) Extractor
========================================================================
Author  : Badi Alosaimi
Version : 2.0.0
License : MIT

Description:
    Parses raw text, log files, emails, or PCAP-exported strings and
    extracts all Indicators of Compromise including IPv4/IPv6 addresses,
    domains, URLs, file hashes (MD5/SHA1/SHA256), CVE IDs, email
    addresses, registry keys, and MITRE ATT&CK technique IDs.

Usage:
    python ioc_extractor.py -f <file>           # Parse a file
    python ioc_extractor.py -t "<raw text>"     # Parse inline text
    python ioc_extractor.py -f <file> -o json   # Output as JSON
    python ioc_extractor.py -f <file> -o csv    # Output as CSV
    python ioc_extractor.py -f <file> --enrich  # Enrich with AbuseIPDB
"""

import re
import sys
import json
import csv
import argparse
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|edu|gov|mil|int|io|co|uk|de|ru|cn|info|biz|"
        r"xyz|top|club|online|site|live|app|dev|cloud|tech|sa|ae|eg)"
        r"(?:/[^\s]*)?\b",
        re.IGNORECASE
    ),
    "url": re.compile(
        r"(?:https?|ftp|hxxp[s]?)://[^\s<>\"']+",
        re.IGNORECASE
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "mitre_technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "registry_key": re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKU|HKCR)"
        r"(?:\\[^\s,;\"']+)+",
        re.IGNORECASE
    ),
    "file_path_win": re.compile(
        r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    ),
    "file_path_unix": re.compile(
        r"(?:^|\s)(/(?:[\w.\-]+/)*[\w.\-]+)"
    ),
}

# Private/Reserved IP ranges to optionally filter
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


# ─────────────────────────────────────────────────────────────────────────────
# CORE EXTRACTOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class IOCExtractor:
    """Main IOC extraction engine."""

    def __init__(self, filter_private: bool = False, defang: bool = False):
        self.filter_private = filter_private
        self.defang = defang
        self.results: Dict[str, Set[str]] = defaultdict(set)
        self.stats: Dict[str, int] = {}

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IPv4 address is in a private range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in PRIVATE_RANGES)
        except ValueError:
            return False

    def _defang(self, ioc: str) -> str:
        """Defang IOC for safe sharing (replace . with [.] and :// with [://])."""
        return ioc.replace(".", "[.]").replace("://", "[://]")

    def _refang(self, text: str) -> str:
        """Refang text before extraction (handle defanged IOCs in input)."""
        return (
            text.replace("[.]", ".")
            .replace("[://]", "://")
            .replace("hxxp", "http")
            .replace("hxxps", "https")
        )

    def extract(self, text: str) -> Dict[str, List[str]]:
        """Extract all IOC types from raw text."""
        self.results = defaultdict(set)
        text = self._refang(text)

        for ioc_type, pattern in PATTERNS.items():
            matches = pattern.findall(text)
            for match in matches:
                value = match.strip() if isinstance(match, str) else match[0].strip()
                if not value:
                    continue
                # Filter private IPs if requested
                if ioc_type == "ipv4" and self.filter_private:
                    if self._is_private_ip(value):
                        continue
                self.results[ioc_type].add(value)

        # Deduplicate: remove IPs that also matched as domains
        # Remove domains that are actually just IP addresses
        clean_domains = set()
        for d in self.results["domain"]:
            try:
                ipaddress.ip_address(d.split("/")[0])
            except ValueError:
                clean_domains.add(d)
        self.results["domain"] = clean_domains

        self.stats = {k: len(v) for k, v in self.results.items()}
        return {k: sorted(v) for k, v in self.results.items()}

    def extract_from_file(self, filepath: str) -> Dict[str, List[str]]:
        """Read file and extract IOCs."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        text = path.read_text(encoding="utf-8", errors="ignore")
        return self.extract(text)

    def to_json(self, results: Dict) -> str:
        """Serialize results to JSON."""
        output = {
            "metadata": {
                "tool": "IOC Extractor v2.0.0",
                "author": "Badi Alosaimi",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "stats": self.stats,
                "total_iocs": sum(self.stats.values()),
            },
            "iocs": results,
        }
        return json.dumps(output, indent=2)

    def to_csv(self, results: Dict) -> str:
        """Serialize results to CSV."""
        lines = ["type,value"]
        for ioc_type, values in results.items():
            for v in values:
                lines.append(f"{ioc_type},{v}")
        return "\n".join(lines)

    def to_table(self, results: Dict) -> str:
        """Pretty-print results as a terminal table."""
        lines = []
        total = sum(len(v) for v in results.values())
        lines.append("\n" + "=" * 60)
        lines.append("  IOC EXTRACTOR v2.0 — Badi Alosaimi")
        lines.append("=" * 60)
        lines.append(f"  Timestamp : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        lines.append(f"  Total IOCs: {total}")
        lines.append("=" * 60)

        category_order = [
            "sha256", "sha1", "md5", "ipv4", "ipv6",
            "url", "domain", "email", "cve",
            "mitre_technique", "registry_key",
            "file_path_win", "file_path_unix",
        ]

        for cat in category_order:
            values = results.get(cat, [])
            if not values:
                continue
            label = cat.upper().replace("_", " ")
            lines.append(f"\n  [{label}] — {len(values)} found")
            lines.append("  " + "-" * 50)
            for v in values:
                display = self._defang(v) if self.defang else v
                lines.append(f"    {display}")

        lines.append("\n" + "=" * 60 + "\n")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc_extractor",
        description="IOC Extractor v2.0 — Blue Team Tool by Badi Alosaimi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ioc_extractor.py -f alert.log
  python ioc_extractor.py -t "Malware connected to 185.220.101.47 via hxxp://evil.com/payload"
  python ioc_extractor.py -f report.txt -o json > iocs.json
  python ioc_extractor.py -f report.txt -o csv  > iocs.csv
  python ioc_extractor.py -f report.txt --filter-private --defang
        """,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-f", "--file",  metavar="PATH", help="Input file to parse")
    source.add_argument("-t", "--text",  metavar="TEXT", help="Raw text string to parse")
    parser.add_argument("-o", "--output", choices=["table", "json", "csv"],
                        default="table", help="Output format (default: table)")
    parser.add_argument("--filter-private", action="store_true",
                        help="Exclude RFC-1918 private IP addresses")
    parser.add_argument("--defang", action="store_true",
                        help="Defang all IOCs in output (safe sharing)")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    extractor = IOCExtractor(
        filter_private=args.filter_private,
        defang=args.defang,
    )

    try:
        if args.file:
            results = extractor.extract_from_file(args.file)
        else:
            results = extractor.extract(args.text)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    if args.output == "json":
        print(extractor.to_json(results))
    elif args.output == "csv":
        print(extractor.to_csv(results))
    else:
        print(extractor.to_table(results))


if __name__ == "__main__":
    main()
