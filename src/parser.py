"""Defensive analysis of SSH authentication failures from Linux-style auth logs.

Designed for education and offline analysis of logs you own or are authorized
 to review. It does not connect to hosts or generate login attempts.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


# Typical Ubuntu/Debian syslog line. Usernames and IPs are checked separately.
FAILED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+Failed password for\s+"
    r"(?:invalid user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+\d+\s+ssh2\b"
)


@dataclass(frozen=True)
class FailedLogin:
    timestamp: datetime
    username: str
    source_ip: str
    line_number: int


@dataclass(frozen=True)
class Alert:
    source_ip: str
    severity: str
    attempt_count: int
    first_seen: str
    last_seen: str
    targeted_users: list[str]
    log_lines: list[int]


def parse_auth_log(log_path: Path, year: int) -> tuple[list[FailedLogin], int]:
    """Return recognized failed SSH logins and the number of lines examined.

    Syslog timestamps do not specify a year or timezone. The caller supplies the
    year; timestamps are interpreted as local wall time in that year.
    """
    if not log_path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    failures: list[FailedLogin] = []
    total_lines = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for total_lines, line in enumerate(log_file, start=1):
            match = FAILED_SSH_PATTERN.search(line)
            if match is None:
                continue

            try:
                address = str(ipaddress.ip_address(match.group("source_ip")))
                timestamp = datetime.strptime(
                    f"{year} {match.group('timestamp')}", "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                # Ignore malformed IPs or timestamps rather than misreport them.
                continue

            failures.append(
                FailedLogin(
                    timestamp=timestamp,
                    username=match.group("username"),
                    source_ip=address,
                    line_number=total_lines,
                )
            )
    return failures, total_lines


def detect_bruteforce(
    failures: Iterable[FailedLogin], threshold: int = 5, window_seconds: int = 60
) -> list[Alert]:
    """Find the largest burst of failures per IP inside a sliding time window."""
    if threshold < 1 or window_seconds < 1:
        raise ValueError("Threshold and window_seconds must be positive integers")

    per_ip: dict[str, list[FailedLogin]] = defaultdict(list)
    for failure in failures:
        per_ip[failure.source_ip].append(failure)

    alerts: list[Alert] = []
    for address, raw_events in per_ip.items():
        events = sorted(raw_events, key=lambda item: item.timestamp)
        left = 0
        best: list[FailedLogin] = []

        for right, event in enumerate(events):
            while (
                event.timestamp - events[left].timestamp
            ).total_seconds() > window_seconds:
                left += 1
            burst = events[left : right + 1]
            if len(burst) > len(best):
                best = burst

        if len(best) < threshold:
            continue

        alerts.append(
            Alert(
                source_ip=address,
                severity="HIGH" if len(best) >= 10 else "MEDIUM",
                attempt_count=len(best),
                first_seen=best[0].timestamp.isoformat(sep=" "),
                last_seen=best[-1].timestamp.isoformat(sep=" "),
                targeted_users=sorted({event.username for event in best}),
                log_lines=[event.line_number for event in best],
            )
        )

    return sorted(alerts, key=lambda item: (-item.attempt_count, item.source_ip))


def create_report(
    log_path: Path, *, year: int, threshold: int = 5, window_seconds: int = 60
) -> dict:
    if threshold < 1 or window_seconds < 1 or not 1 <= year <= 9999:
        raise ValueError("Year, threshold, and window must be positive and valid")
    failures, line_count = parse_auth_log(log_path, year)
    alerts = detect_bruteforce(failures, threshold, window_seconds)
    return {
        "tool": "SSH Auth Log Analyzer & Brute-Force Detector",
        "log_file": str(log_path),
        "timestamp_note": "Syslog timestamps have no year/timezone; year supplied by caller",
        "analysis_year": year,
        "total_lines": line_count,
        "failed_logins_parsed": len(failures),
        "threshold": threshold,
        "window_seconds": window_seconds,
        "alert_count": len(alerts),
        "alerts": [asdict(alert) for alert in alerts],
    }


def format_text(report: dict) -> str:
    lines = [
        "SSH AUTH LOG ANALYZER — DEFENSIVE REPORT",
        "=" * 49,
        f"Log file: {report['log_file']}",
        f"Analyzed: {report['total_lines']} lines; "
        f"{report['failed_logins_parsed']} failed SSH logins",
        f"Alert rule: {report['threshold']}+ failures from one IP "
        f"within {report['window_seconds']} seconds",
        f"Alerts found: {report['alert_count']}",
    ]
    if not report["alerts"]:
        lines.append("No IP addresses met the alert threshold.")
    for alert in report["alerts"]:
        lines.extend(
            [
                "-" * 49,
                f"[{alert['severity']}] {alert['source_ip']}",
                f"Failed attempts: {alert['attempt_count']}",
                f"Observed: {alert['first_seen']} -> {alert['last_seen']}",
                f"Targeted accounts: {', '.join(alert['targeted_users'])}",
                f"Log line numbers: {', '.join(map(str, alert['log_lines']))}",
            ]
        )
    lines.extend(["", "Educational use; review alerts before drawing conclusions."])
    return "\n".join(lines) + "\n"


def format_csv(report: dict) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "source_ip", "severity", "attempt_count", "first_seen", "last_seen",
            "targeted_users", "log_lines",
        ],
    )
    writer.writeheader()
    for alert in report["alerts"]:
        writer.writerow(
            {
                **alert,
                "targeted_users": ";".join(alert["targeted_users"]),
                "log_lines": ";".join(map(str, alert["log_lines"])),
            }
        )
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a local SSH auth.log for bursts of failed password attempts."
    )
    parser.add_argument(
        "--log", type=Path, default=Path("samples/sample_auth.log"),
        help="Path to an authorized local auth log (default: samples/sample_auth.log)",
    )
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument(
        "--year", type=int, default=datetime.now().year,
        help="Calendar year to assign to syslog entries without years",
    )
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--output", type=Path, help="Write a report to this local file")
    args = parser.parse_args(argv)

    try:
        report = create_report(
            args.log,
            year=args.year,
            threshold=args.threshold,
            window_seconds=args.window_seconds,
        )
    except (ValueError, OSError) as exc:
        parser.exit(2, f"Error: {exc}\n")

    if args.format == "json":
        rendered = json.dumps(report, indent=2) + "\n"
    elif args.format == "csv":
        rendered = format_csv(report)
    else:
        rendered = format_text(report)

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            parser.exit(2, f"Could not save report: {exc}\n")
        print(f"Saved {args.format.upper()} report: {args.output}")
        print(f"Detected {report['alert_count']} suspicious IP address(es).")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
