#!/usr/bin/env python3
"""
Domain Expiry Reporter
Reads domains from a text file, performs WHOIS lookups, and generates
CSV reports that highlight expired or inactive domains.

Usage:
    python domain_expiry_report.py --input pch.txt
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


# Common phrases returned when a WHOIS record is not available.
NOT_FOUND_PATTERNS: Sequence[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bno match for\b",
        r"\bnot found\b",
        r"\bno entries found\b",
        r"\bno data found\b",
        r"\bstatus:\s*free\b",
        r"\bis available for registration\b",
        r"\bno such domain\b",
        r"\bdomain you requested is not found\b",
    ]
]

# Known WHOIS field labels that contain an expiry / expiration date.
EXPIRY_PATTERNS: Sequence[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"registry expiry date:\s*(.+)",
        r"registrar registration expiration date:\s*(.+)",
        r"expiry date:\s*(.+)",
        r"expiration date:\s*(.+)",
        r"paid-till:\s*(.+)",
        r"paid till:\s*(.+)",
        r"renewal date:\s*(.+)",
        r"expires on:\s*(.+)",
        r"expire date:\s*(.+)",
        r"expiration time:\s*(.+)",
    ]
]

# Status keywords that usually indicate the domain is inactive or in trouble.
INACTIVE_KEYWORDS: Sequence[str] = [
    "inactive",
    "redemption",
    "pending delete",
    "pendingdelete",
    "clienthold",
    "serverhold",
    "server-hold",
    "client-hold",
    "pendingrenewal",
    "pending renewal",
    "pending restore",
    "pendingrestore",
    "pendingtransfer",
    "pending transfer",
    "expired",
    "auto-renew grace",
    "pending delete scheduled for release",
    "pending delete restorable",
    "pendingdelete restorable",
]

# Multiple date formats appear across registries.
DATE_FORMATS: Sequence[str] = [
    "%Y-%m-%d",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%MZ",
    "%Y.%m.%d",
    "%Y.%m.%d %H:%M:%S",
    "%Y/%m/%d",
    "%Y/%m/%d %H:%M:%S",
    "%d-%b-%Y",
    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S %Z",
    "%d.%m.%Y",
    "%d.%m.%Y %H:%M:%S",
    "%d-%B-%Y",
    "%d-%B-%Y %H:%M:%S",
]

# Lines that commonly prefix WHOIS status information.
STATUS_PATTERNS: Sequence[re.Pattern[str]] = [
    re.compile(r"domain status:\s*(.+)", re.IGNORECASE),
    re.compile(r"status:\s*(.+)", re.IGNORECASE),
]


@dataclass
class WhoisData:
    domain: str
    not_found: bool
    error: Optional[str]
    expiry_date: Optional[datetime]
    expiry_source: Optional[str]
    statuses: List[str]
    inactive_hits: List[str]

    @property
    def is_expired(self) -> bool:
        if not self.expiry_date:
            return False
        return self.expiry_date < datetime.now(timezone.utc)

    @property
    def is_inactive(self) -> bool:
        return bool(self.inactive_hits)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a domain expiry report from WHOIS data.")
    parser.add_argument(
        "--input",
        default="pch.txt",
        help="Path to the input file containing domains (default: %(default)s)",
    )
    parser.add_argument(
        "--report",
        default="whois_expired_inactive_report.csv",
        help="CSV file to write domains flagged as expired or inactive (default: %(default)s)",
    )
    parser.add_argument(
        "--full-report",
        default="whois_full_report.csv",
        help="CSV file to write the full WHOIS summary for all domains (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="Timeout (seconds) for each WHOIS query (default: %(default)s)",
    )
    return parser.parse_args(argv)


def read_domains(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    domains: List[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            candidate = line.strip()
            if candidate and not candidate.startswith("#"):
                domains.append(candidate)
    return domains


def canonicalize_domain(domain: str) -> str:
    cleaned = domain.strip()
    cleaned = re.sub(r"^\*+\.", "", cleaned)  # remove wildcard prefix if present
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.strip(".")
    return cleaned.lower()


def run_whois_query(domain: str, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    try:
        completed = subprocess.run(
            ["whois", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None, "The `whois` command is not available on this system."
    except subprocess.TimeoutExpired:
        return None, f"WHOIS lookup timed out after {timeout} seconds."

    output = (completed.stdout or "") + (completed.stderr or "")
    if not output.strip():
        return "", None
    return output, None


def response_indicates_not_found(text: str) -> bool:
    for pattern in NOT_FOUND_PATTERNS:
        if pattern.search(text):
            return True
    return False


def extract_statuses(text: str) -> List[str]:
    statuses: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in STATUS_PATTERNS:
            match = pattern.match(stripped)
            if match:
                payload = match.group(1)
                payload = payload.split(" https://")[0].split(" http://")[0]
                fragments = [fragment.strip() for fragment in re.split(r"[,\t]+", payload) if fragment.strip()]
                if fragments:
                    statuses.extend(fragments)
    return statuses


def normalize_date_string(value: str) -> str:
    cleaned = value.strip()
    cleaned = re.sub(r"\s*\(.*\)$", "", cleaned)
    cleaned = cleaned.replace(" UTC", "Z")
    cleaned = cleaned.replace("GMT", "Z")
    cleaned = cleaned.replace("(UTC)", "")
    cleaned = re.sub(r"\s+UTC$", "", cleaned)
    return cleaned.strip()


def parse_expiry(text: str) -> Tuple[Optional[datetime], Optional[str]]:
    for line in text.splitlines():
        stripped = line.strip()
        for pattern in EXPIRY_PATTERNS:
            match = pattern.match(stripped)
            if not match:
                continue
            candidate = normalize_date_string(match.group(1))
            parsed = parse_datetime(candidate)
            if parsed:
                return parsed, candidate
            # Fallback to raw string if parsing failed.
            return None, candidate
    return None, None


def parse_datetime(value: str) -> Optional[datetime]:
    cleaned = value.strip()
    if not cleaned:
        return None

    # Replace trailing Z with explicit UTC offset for strptime compatibility.
    if cleaned.endswith("Z") and not cleaned.endswith("+00:00"):
        cleaned_for_parse = cleaned[:-1] + "+0000"
        formats = list(DATE_FORMATS) + ["%Y-%m-%dT%H:%M:%S.%f%z"]
    else:
        cleaned_for_parse = cleaned
        formats = DATE_FORMATS

    for fmt in formats:
        try:
            parsed = datetime.strptime(cleaned_for_parse, fmt)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue

    try:
        parsed_generic = parsedate_to_datetime(cleaned)
        if parsed_generic.tzinfo is None:
            return parsed_generic.replace(tzinfo=timezone.utc)
        return parsed_generic.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def detect_inactive(statuses: Sequence[str], raw: str) -> List[str]:
    hits: List[str] = []
    lowered_statuses = [status.lower().replace("_", "").replace("-", "").replace(" ", "") for status in statuses]
    lowered_raw = raw.lower()
    for keyword in INACTIVE_KEYWORDS:
        compressed = keyword.lower().replace("_", "").replace("-", "").replace(" ", "")
        if any(compressed in status for status in lowered_statuses):
            hits.append(keyword)
            continue
        if keyword.lower() in lowered_raw:
            hits.append(keyword)
    # Deduplicate while preserving order.
    seen = set()
    ordered_hits: List[str] = []
    for hit in hits:
        label = hit.lower()
        if label not in seen:
            ordered_hits.append(hit)
            seen.add(label)
    return ordered_hits


def build_whois_data(domain: str, timeout: int, cache: Dict[str, WhoisData]) -> WhoisData:
    host = canonicalize_domain(domain)
    if not host:
        return WhoisData(
            domain=host,
            not_found=True,
            error="Domain name is empty after normalisation.",
            expiry_date=None,
            expiry_source=None,
            statuses=[],
            inactive_hits=[],
        )

    if host in cache:
        return cache[host]

    output, error = run_whois_query(host, timeout)

    if error:
        data = WhoisData(
            domain=host,
            not_found=False,
            error=error,
            expiry_date=None,
            expiry_source=None,
            statuses=[],
            inactive_hits=[],
        )
    elif output is None:
        data = WhoisData(
            domain=host,
            not_found=False,
            error="No WHOIS output returned.",
            expiry_date=None,
            expiry_source=None,
            statuses=[],
            inactive_hits=[],
        )
    else:
        not_found = response_indicates_not_found(output)
        expiry_date, expiry_source = parse_expiry(output)
        statuses = extract_statuses(output)
        inactive_hits = detect_inactive(statuses, output)
        data = WhoisData(
            domain=host,
            not_found=not_found,
            error=None,
            expiry_date=expiry_date,
            expiry_source=expiry_source,
            statuses=statuses,
            inactive_hits=inactive_hits,
        )

    cache[host] = data
    return data


def analyse_domains(domains: Sequence[str], timeout: int) -> List[Dict[str, object]]:
    cache: Dict[str, WhoisData] = {}
    results: List[Dict[str, object]] = []

    for domain in domains:
        data = build_whois_data(domain, timeout, cache)
        results.append(
            {
                "input_domain": domain,
                "queried_domain": data.domain,
                "expiry_date_iso": data.expiry_date.isoformat() if data.expiry_date else "",
                "expiry_source": data.expiry_source or "",
                "is_expired": "yes" if data.is_expired else "no",
                "is_inactive": "yes" if data.is_inactive else "no",
                "inactive_indicators": "; ".join(data.inactive_hits),
                "statuses": "; ".join(data.statuses),
                "not_found": "yes" if data.not_found else "no",
                "error": data.error or "",
            }
        )

    return results


def write_report(path: Path, rows: Sequence[Dict[str, object]]) -> None:
    if not rows:
        # Still create the file with headers so the user knows the structure.
        headers = [
            "input_domain",
            "queried_domain",
            "expiry_date_iso",
            "expiry_source",
            "is_expired",
            "is_inactive",
            "inactive_indicators",
            "statuses",
            "not_found",
            "error",
        ]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
        return

    headers = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    input_path = Path(args.input).expanduser()
    report_path = Path(args.report).expanduser()
    full_report_path = Path(args.full_report).expanduser()

    try:
        domains = read_domains(input_path)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    if not domains:
        print(f"No domains found in {input_path}. Nothing to do.")
        return 0

    results = analyse_domains(domains, args.timeout)
    flagged = [
        row for row in results if row["is_expired"] == "yes" or row["is_inactive"] == "yes"
    ]

    write_report(full_report_path, results)
    write_report(report_path, flagged)

    print(f"Analysed {len(results)} domain(s).")
    print(f"Full WHOIS summary written to: {full_report_path}")
    print(f"Expired / inactive report written to: {report_path}")

    if any(row["error"] for row in results):
        print("Some domains returned errors. Review the 'error' column in the full report.")

    if not flagged:
        print("No domains were flagged as expired or inactive.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
