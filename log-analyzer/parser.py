"""
parser.py
---------
Responsible for reading raw log files and turning each line into a
structured Python dictionary ("log entry") that the rest of the
program can work with.

Keeping parsing logic in its own module means we can add support for
new log formats later (e.g. syslog, auth.log) without touching the
detection logic in detector.py.
"""

import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Regular expression for a common Apache/Nginx "combined" style access log:
#
#   192.168.1.10 - - [23/Aug/2026:09:10:01 +0800] "POST /login HTTP/1.1" 401 512
#
# Groups:
#   1. IP address
#   2. Timestamp (inside the square brackets)
#   3. HTTP method (GET, POST, ...)
#   4. Requested path
#   5. HTTP status code
#   6. Response size in bytes
# ---------------------------------------------------------------------------
APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)

# Apache-style timestamp format, e.g. "23/Aug/2026:09:10:01 +0800"
APACHE_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class LogEntry:
    """
    A single parsed log line.

    Using a small class (instead of a raw dict) gives us autocomplete
    and makes the code that reads log entries easier to follow.
    """

    def __init__(self, ip: str, timestamp: datetime, method: str,
                 path: str, status: int, size: str, raw_line: str):
        self.ip = ip
        self.timestamp = timestamp
        self.method = method
        self.path = path
        self.status = status
        self.size = size
        self.raw_line = raw_line

    def is_login_request(self) -> bool:
        """A very simple heuristic: treat any POST to a path containing
        'login' as a login attempt. Real systems would use application
        knowledge to identify auth endpoints more precisely."""
        return self.method == "POST" and "login" in self.path.lower()

    def is_failed_login(self) -> bool:
        """Failed logins are approximated as login requests that returned
        401 (Unauthorized) or 403 (Forbidden)."""
        return self.is_login_request() and self.status in (401, 403)

    def is_successful_login(self) -> bool:
        """A successful login is approximated as a login request that
        returned a 2xx status code."""
        return self.is_login_request() and 200 <= self.status < 300

    def __repr__(self) -> str:
        return f"<LogEntry {self.ip} {self.method} {self.path} {self.status}>"


def parse_timestamp(raw_timestamp: str) -> Optional[datetime]:
    """
    Convert an Apache-style timestamp string into a datetime object.
    Returns None if the timestamp cannot be parsed (malformed line).
    """
    try:
        return datetime.strptime(raw_timestamp, APACHE_TIMESTAMP_FORMAT)
    except (ValueError, TypeError):
        return None


def parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single raw log line into a LogEntry.

    Returns None if the line does not match the expected format or
    contains a malformed field (e.g. bad timestamp, non-numeric status).
    This lets the caller simply skip lines that fail to parse instead
    of crashing the whole program.
    """
    line = line.strip()
    if not line:
        return None

    match = APACHE_COMBINED_PATTERN.match(line)
    if not match:
        return None

    fields = match.groupdict()

    timestamp = parse_timestamp(fields["timestamp"])
    if timestamp is None:
        return None

    try:
        status = int(fields["status"])
    except ValueError:
        return None

    return LogEntry(
        ip=fields["ip"],
        timestamp=timestamp,
        method=fields["method"],
        path=fields["path"],
        status=status,
        size=fields["size"],
        raw_line=line,
    )


def parse_log_file(file_path: str) -> Tuple[List[LogEntry], int, int]:
    """
    Read a log file and parse every line.

    Returns a tuple of:
        (list_of_valid_entries, total_lines, skipped_lines)

    Design note: we intentionally do NOT raise an exception for a bad
    individual line. A single malformed line should never crash log
    analysis on a 10,000-line file. File-level problems (missing file,
    permission errors) are still raised so the CLI can report them
    clearly to the user.
    """
    entries: List[LogEntry] = []
    total_lines = 0
    skipped_lines = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as log_file:
        for raw_line in log_file:
            if not raw_line.strip():
                continue  # blank lines don't count as "skipped/malformed"

            total_lines += 1
            entry = parse_line(raw_line)

            if entry is None:
                skipped_lines += 1
                continue

            entries.append(entry)

    return entries, total_lines, skipped_lines
