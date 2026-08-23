"""
test_detector.py
-----------------
Basic unit tests for the detection rules in detector.py.

Run with:
    python -m unittest tests/test_detector.py -v

or, from the project root:
    python -m unittest discover tests
"""

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

# Allow importing parser.py and detector.py from the project root when
# running this test file directly (e.g. `python tests/test_detector.py`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parser import LogEntry, parse_line, parse_log_file
from detector import (
    detect_failed_logins,
    detect_success_after_failures,
    detect_suspicious_paths,
    detect_error_spikes,
    detect_request_flooding,
    detect_attack_patterns,
)


def make_entry(ip="192.168.1.10", minute_offset=0, method="GET",
                path="/index.html", status=200):
    """Helper to quickly build a LogEntry for tests without repeating
    boilerplate timestamp math."""
    base_time = datetime(2026, 8, 23, 9, 0, 0)
    timestamp = base_time + timedelta(seconds=minute_offset)
    return LogEntry(
        ip=ip, timestamp=timestamp, method=method, path=path,
        status=status, size="512", raw_line="",
    )


class TestParser(unittest.TestCase):
    def test_parses_valid_line(self):
        line = '192.168.1.10 - - [23/Aug/2026:09:10:01 +0800] "POST /login HTTP/1.1" 401 512'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.10")
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.path, "/login")
        self.assertEqual(entry.status, 401)

    def test_rejects_malformed_line(self):
        self.assertIsNone(parse_line("this is not a log line"))

    def test_rejects_bad_timestamp(self):
        line = '192.168.1.10 - - [BADTIMESTAMP] "GET / HTTP/1.1" 200 512'
        self.assertIsNone(parse_line(line))

    def test_rejects_empty_line(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("   "))

    def test_is_failed_login(self):
        entry = make_entry(method="POST", path="/login", status=401)
        self.assertTrue(entry.is_failed_login())
        self.assertFalse(entry.is_successful_login())

    def test_is_successful_login(self):
        entry = make_entry(method="POST", path="/login", status=200)
        self.assertTrue(entry.is_successful_login())
        self.assertFalse(entry.is_failed_login())


class TestFailedLoginDetection(unittest.TestCase):
    def test_flags_brute_force(self):
        entries = [
            make_entry(minute_offset=i * 4, method="POST", path="/login", status=401)
            for i in range(6)
        ]
        findings = detect_failed_logins(entries, threshold=5, window_seconds=300)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["ip"], "192.168.1.10")

    def test_does_not_flag_below_threshold(self):
        entries = [
            make_entry(minute_offset=i * 4, method="POST", path="/login", status=401)
            for i in range(3)
        ]
        findings = detect_failed_logins(entries, threshold=5, window_seconds=300)
        self.assertEqual(len(findings), 0)

    def test_does_not_flag_attempts_outside_window(self):
        # 5 failures, but spread far apart (outside the time window)
        entries = [
            make_entry(minute_offset=i * 1000, method="POST", path="/login", status=401)
            for i in range(5)
        ]
        findings = detect_failed_logins(entries, threshold=5, window_seconds=300)
        self.assertEqual(len(findings), 0)


class TestSuccessAfterFailures(unittest.TestCase):
    def test_flags_success_after_several_failures(self):
        entries = [
            make_entry(minute_offset=0, method="POST", path="/login", status=401),
            make_entry(minute_offset=5, method="POST", path="/login", status=401),
            make_entry(minute_offset=10, method="POST", path="/login", status=401),
            make_entry(minute_offset=15, method="POST", path="/login", status=401),
            make_entry(minute_offset=20, method="POST", path="/login", status=401),
            make_entry(minute_offset=25, method="POST", path="/login", status=200),
        ]
        findings = detect_success_after_failures(entries, threshold=5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_no_finding_for_immediate_success(self):
        entries = [make_entry(method="POST", path="/login", status=200)]
        findings = detect_success_after_failures(entries, threshold=5)
        self.assertEqual(len(findings), 0)


class TestSuspiciousPaths(unittest.TestCase):
    def test_flags_sensitive_path(self):
        entries = [make_entry(path="/etc/passwd")]
        findings = detect_suspicious_paths(entries, suspicious_paths=["/etc/passwd"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_ignores_normal_path(self):
        entries = [make_entry(path="/index.html")]
        findings = detect_suspicious_paths(entries, suspicious_paths=["/etc/passwd"])
        self.assertEqual(len(findings), 0)


class TestErrorSpike(unittest.TestCase):
    def test_flags_excessive_404s(self):
        entries = [make_entry(minute_offset=i, status=404) for i in range(35)]
        findings = detect_error_spikes(entries, threshold=30)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["details"]["count"], 35)

    def test_ignores_normal_error_rate(self):
        entries = [make_entry(minute_offset=i, status=404) for i in range(5)]
        findings = detect_error_spikes(entries, threshold=30)
        self.assertEqual(len(findings), 0)


class TestRequestFlooding(unittest.TestCase):
    def test_flags_high_volume(self):
        entries = [make_entry(minute_offset=i * 0.1) for i in range(150)]
        findings = detect_request_flooding(entries, threshold=100, window_seconds=60)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_ignores_normal_traffic(self):
        entries = [make_entry(minute_offset=i * 5) for i in range(10)]
        findings = detect_request_flooding(entries, threshold=100, window_seconds=60)
        self.assertEqual(len(findings), 0)


class TestAttackPatterns(unittest.TestCase):
    PATTERNS = [r"\.\./", r"union\s+select", r"<script"]

    def test_flags_directory_traversal(self):
        entries = [make_entry(path="/download?file=../../etc/passwd")]
        findings = detect_attack_patterns(entries, attack_patterns=self.PATTERNS)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_flags_url_encoded_payload(self):
        entries = [make_entry(path="/product?id=1%20union%20select%20*")]
        findings = detect_attack_patterns(entries, attack_patterns=self.PATTERNS)
        self.assertEqual(len(findings), 1)

    def test_ignores_normal_request(self):
        entries = [make_entry(path="/products?category=shoes")]
        findings = detect_attack_patterns(entries, attack_patterns=self.PATTERNS)
        self.assertEqual(len(findings), 0)


class TestSampleLogFile(unittest.TestCase):
    """Integration-style test using the bundled sample log file."""

    def test_sample_log_produces_findings(self):
        sample_path = Path(__file__).resolve().parent.parent / "logs" / "sample_access.log"
        entries, total_lines, skipped_lines = parse_log_file(str(sample_path))

        self.assertGreater(total_lines, 0)
        self.assertGreater(len(entries), 0)
        # The sample log intentionally contains a few malformed lines.
        self.assertGreater(skipped_lines, 0)


if __name__ == "__main__":
    unittest.main()
