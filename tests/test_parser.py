"""Tests run with: python -m unittest discover -s tests -v"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from src.parser import (
    FailedLogin,
    create_report,
    detect_bruteforce,
    format_csv,
    main,
    parse_auth_log,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "sample_auth.log"


class ParserTests(unittest.TestCase):
    def test_sample_parsing_ignores_successes_and_cron(self):
        failures, total = parse_auth_log(SAMPLE, year=2026)
        self.assertEqual(total, 15)
        self.assertEqual(len(failures), 12)
        self.assertEqual(sum(f.source_ip == "10.0.0.15" for f in failures), 1)

    def test_sample_detects_two_independent_bursts(self):
        report = create_report(SAMPLE, year=2026)
        self.assertEqual(report["alert_count"], 2)
        self.assertEqual(
            [(item["source_ip"], item["attempt_count"]) for item in report["alerts"]],
            [("192.168.1.105", 6), ("203.0.113.42", 5)],
        )
        self.assertEqual(report["alerts"][1]["targeted_users"],
                         ["guest", "oracle", "postgres", "test", "ubuntu"])

    def test_higher_threshold_returns_no_alerts(self):
        self.assertEqual(create_report(SAMPLE, year=2026, threshold=7)["alert_count"], 0)

    def test_window_matters(self):
        self.assertEqual(create_report(SAMPLE, year=2026, window_seconds=1)["alert_count"], 0)

    def test_separated_failures_do_not_trigger(self):
        stamp = datetime(2026, 11, 16, 10, 0, 0)
        events = [
            FailedLogin(stamp + timedelta(minutes=i), "alice", "203.0.113.7", i)
            for i in range(5)
        ]
        self.assertEqual(detect_bruteforce(events, threshold=5, window_seconds=30), [])

    def test_high_severity_on_ten_failures(self):
        stamp = datetime(2026, 11, 16, 10, 0, 0)
        events = [
            FailedLogin(stamp + timedelta(seconds=i), "root", "203.0.113.7", i + 1)
            for i in range(10)
        ]
        alerts = detect_bruteforce(events)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertEqual(alerts[0].attempt_count, 10)

    def test_invalid_address_not_parsed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "auth.log"
            path.write_text(
                "Nov 16 10:00:00 vm sshd[12]: Failed password for root from "
                "999.999.1.1 port 22 ssh2\n",
                encoding="utf-8",
            )
            results, count = parse_auth_log(path, year=2026)
        self.assertEqual((results, count), ([], 1))

    def test_ipv6_address_is_supported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "auth.log"
            path.write_text(
                "Nov 16 10:00:00 vm sshd[12]: Failed password for root from "
                "2001:db8::12 port 22 ssh2\n",
                encoding="utf-8",
            )
            results, _ = parse_auth_log(path, year=2026)
        self.assertEqual(results[0].source_ip, "2001:db8::12")

    def test_csv_header_and_rows(self):
        report = create_report(SAMPLE, year=2026)
        csv_data = format_csv(report)
        self.assertIn("source_ip,severity,attempt_count", csv_data)
        self.assertIn("192.168.1.105,MEDIUM,6", csv_data)

    def test_cli_writes_json_report(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "report.json"
            with patch("builtins.print"):
                result = main([
                    "--log", str(SAMPLE), "--year", "2026", "--format", "json",
                    "--output", str(output),
                ])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.read_text())["alert_count"], 2)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_auth_log(Path("does-not-exist.log"), year=2026)

    def test_invalid_threshold_raises(self):
        with self.assertRaises(ValueError):
            create_report(SAMPLE, year=2026, threshold=0)


if __name__ == "__main__":
    unittest.main()
