"""
detector.py
-----------
Contains all detection rules. Each rule is a separate function that
takes the list of parsed log entries (plus configuration thresholds)
and returns a list of "findings".

A finding is a dictionary describing one piece of suspicious activity,
e.g.:

    {
        "severity": "HIGH",
        "type": "brute_force",
        "ip": "192.168.1.10",
        "description": "Multiple failed login attempts detected",
        "details": {"failed_attempts": 7, "window_seconds": 300}
    }

IMPORTANT: These are rule-based heuristics, not proof of an attack.
See the README "Limitations" section for more context.
"""

import re
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any
from urllib.parse import unquote

from parser import LogEntry


# ---------------------------------------------------------------------------
# Rule A: Failed Login Attempts (possible brute force)
# ---------------------------------------------------------------------------
def detect_failed_logins(entries: List[LogEntry], threshold: int,
                          window_seconds: int) -> List[Dict[str, Any]]:
    """
    Flags an IP address once it accumulates `threshold` or more failed
    login attempts inside any `window_seconds`-long sliding window.

    Why HIGH severity: a burst of failed logins in a short window is a
    classic signature of automated brute-force password guessing.
    """
    findings = []
    window = timedelta(seconds=window_seconds)

    # Group failed login timestamps by IP first.
    failed_by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.is_failed_login():
            failed_by_ip[entry.ip].append(entry)

    for ip, attempts in failed_by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)

        # Sliding window: for each attempt, count how many other attempts
        # from the same IP fall within `window_seconds` after it.
        for i, start_entry in enumerate(attempts):
            window_end = start_entry.timestamp + window
            count_in_window = sum(
                1 for e in attempts[i:] if e.timestamp <= window_end
            )

            if count_in_window >= threshold:
                findings.append({
                    "severity": "HIGH",
                    "type": "brute_force",
                    "ip": ip,
                    "description": "Multiple failed login attempts detected",
                    "details": {
                        "failed_attempts": count_in_window,
                        "window_seconds": window_seconds,
                    },
                })
                break  # one finding per IP is enough; avoid duplicate spam

    return findings


# ---------------------------------------------------------------------------
# Rule B: Successful Login After Failures
# ---------------------------------------------------------------------------
def detect_success_after_failures(entries: List[LogEntry],
                                   threshold: int) -> List[Dict[str, Any]]:
    """
    Flags an IP that racked up `threshold` or more failed logins and
    THEN succeeded. This pattern can indicate a successful brute-force
    (the attacker eventually guessed correctly) or a legitimate user
    who mistyped their password several times.

    Why MEDIUM severity: it's suspicious, but too common among real
    users to justify HIGH on its own.
    """
    findings = []

    # Process entries per-IP, in chronological order.
    by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.is_login_request():
            by_ip[entry.ip].append(entry)

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)

        consecutive_failures = 0
        for entry in attempts:
            if entry.is_failed_login():
                consecutive_failures += 1
            elif entry.is_successful_login():
                if consecutive_failures >= threshold:
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "success_after_failure",
                        "ip": ip,
                        "description": "Successful login after repeated failures",
                        "details": {
                            "failed_attempts_before_success": consecutive_failures,
                        },
                    })
                consecutive_failures = 0  # reset after any successful login

    return findings


# ---------------------------------------------------------------------------
# Rule C: Suspicious Paths
# ---------------------------------------------------------------------------
def detect_suspicious_paths(entries: List[LogEntry],
                             suspicious_paths: List[str]) -> List[Dict[str, Any]]:
    """
    Flags requests to sensitive or commonly-attacked paths such as
    /admin, /wp-admin, /etc/passwd, /.env, etc.

    Why MEDIUM severity: visiting these paths isn't proof of compromise
    (scanners and curious users do this too), but it's worth a human
    review, especially if combined with other findings.
    """
    findings = []
    hits: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for entry in entries:
        for suspicious_path in suspicious_paths:
            if suspicious_path.lower() in entry.path.lower():
                hits[entry.ip][suspicious_path] += 1

    for ip, path_counts in hits.items():
        for path, count in path_counts.items():
            findings.append({
                "severity": "MEDIUM",
                "type": "suspicious_path",
                "ip": ip,
                "description": "Request to suspicious or sensitive path",
                "details": {"path": path, "requests": count},
            })

    return findings


# ---------------------------------------------------------------------------
# Rule D: HTTP Error Spike
# ---------------------------------------------------------------------------
def detect_error_spikes(entries: List[LogEntry],
                         threshold: int) -> List[Dict[str, Any]]:
    """
    Flags an IP that generates an unusually high number of 401/403/404
    responses. This can indicate scanning/enumeration behavior (e.g.
    someone probing many URLs to find something that exists).

    Why MEDIUM severity: automated scanners and broken bookmarks/links
    can both cause this, so it needs human context to confirm intent.
    """
    findings = []
    error_codes = {401, 403, 404}

    counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for entry in entries:
        if entry.status in error_codes:
            counts[entry.ip][entry.status] += 1

    for ip, status_counts in counts.items():
        for status, count in status_counts.items():
            if count >= threshold:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "error_spike",
                    "ip": ip,
                    "description": f"Excessive HTTP {status} responses",
                    "details": {"status_code": status, "count": count},
                })

    return findings


# ---------------------------------------------------------------------------
# Rule E: Request Flooding
# ---------------------------------------------------------------------------
def detect_request_flooding(entries: List[LogEntry], threshold: int,
                             window_seconds: int) -> List[Dict[str, Any]]:
    """
    Flags an IP making an unusually large number of requests within a
    short time window, regardless of what those requests are. This can
    indicate a denial-of-service attempt, aggressive scraping, or a
    misbehaving script/bot.

    Why HIGH severity: sustained high-volume traffic from a single
    source can degrade service availability for everyone else.
    """
    findings = []
    window = timedelta(seconds=window_seconds)

    by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for entry in entries:
        by_ip[entry.ip].append(entry)

    for ip, requests in by_ip.items():
        requests.sort(key=lambda e: e.timestamp)

        for i, start_entry in enumerate(requests):
            window_end = start_entry.timestamp + window
            count_in_window = sum(
                1 for e in requests[i:] if e.timestamp <= window_end
            )

            if count_in_window >= threshold:
                findings.append({
                    "severity": "HIGH",
                    "type": "request_flood",
                    "ip": ip,
                    "description": "Unusually high request volume",
                    "details": {
                        "requests": count_in_window,
                        "window_seconds": window_seconds,
                    },
                })
                break  # one finding per IP

    return findings


# ---------------------------------------------------------------------------
# Rule F: Suspicious Request Patterns (SQLi, path traversal, XSS, etc.)
# ---------------------------------------------------------------------------
def detect_attack_patterns(entries: List[LogEntry],
                            attack_patterns: List[str]) -> List[Dict[str, Any]]:
    """
    Flags requests whose path contains a string commonly associated
    with web attacks (SQL injection, directory traversal, XSS, etc.).

    Why CRITICAL severity: unlike the other heuristics, these strings
    have very few legitimate reasons to appear in a URL, so a match is
    a strong signal that someone is actively probing for a
    vulnerability -- even though it still isn't proof an attack
    succeeded.

    Note: paths are URL-decoded before matching (e.g. "%20" -> " ")
    since real attackers often percent-encode payloads to slip past
    naive filters.
    """
    findings = []
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in attack_patterns]

    for entry in entries:
        decoded_path = unquote(entry.path)
        for pattern, raw_pattern in zip(compiled_patterns, attack_patterns):
            if pattern.search(decoded_path):
                findings.append({
                    "severity": "CRITICAL",
                    "type": "attack_pattern",
                    "ip": entry.ip,
                    "description": "Request contains a known attack-like pattern",
                    "details": {
                        "pattern": raw_pattern,
                        "path": decoded_path,
                    },
                })
                break  # don't double-count one request against multiple patterns

    return findings


# ---------------------------------------------------------------------------
# Orchestration: run every rule and combine the results
# ---------------------------------------------------------------------------
def run_all_detections(entries: List[LogEntry],
                        config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Runs every detection rule using the supplied configuration and
    returns a single combined list of findings.
    """
    findings: List[Dict[str, Any]] = []

    findings += detect_failed_logins(
        entries,
        threshold=config["failed_login_threshold"],
        window_seconds=config["failed_login_window_seconds"],
    )

    findings += detect_success_after_failures(
        entries,
        threshold=config["failed_login_threshold"],
    )

    findings += detect_suspicious_paths(
        entries,
        suspicious_paths=config["suspicious_paths"],
    )

    findings += detect_error_spikes(
        entries,
        threshold=config["error_threshold"],
    )

    findings += detect_request_flooding(
        entries,
        threshold=config["request_threshold"],
        window_seconds=config["request_window_seconds"],
    )

    findings += detect_attack_patterns(
        entries,
        attack_patterns=config["attack_patterns"],
    )

    return findings
