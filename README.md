# Python Log Analyzer

A beginner-friendly, command-line **log analysis tool** that scans web server
access logs and flags rule-based indicators of suspicious activity — such as
possible brute-force login attempts, requests to sensitive paths, HTTP error
spikes, request flooding, and known attack-like URL patterns.

This project was built as a **student cybersecurity lab exercise** to
demonstrate practical Python skills combined with fundamental log-analysis
and threat-detection concepts.

> **This tool does not prove that an attack happened.** It highlights
> patterns that are *worth a human's attention*. See [Limitations](#limitations)
> below.

---

## Table of Contents



---

## Project Overview

Log Analyzer reads a web server access log (Apache/Nginx "combined" style),
parses each line into a structured record, and runs a set of configurable
detection rules against those records. Findings are printed to the terminal
with a severity rating and can optionally be exported as a JSON report.

The project is intentionally kept **small and readable** — no frameworks,
no database, no external APIs. Everything runs locally using only the
Python standard library.

## Why Log Analysis Matters in Cybersecurity

Every request to a web server leaves a trace in its logs. Attackers often
generate patterns that differ from normal user traffic: many failed logins
in a short time, requests to files that shouldn't be reachable
(`/etc/passwd`, `.env`), unusual spikes in errors as a scanner probes for
valid URLs, or literal attack payloads (like SQL injection strings) sitting
in a URL. Learning to recognize these patterns — and understanding their
limitations — is a foundational skill in security monitoring, incident
response, and SOC (Security Operations Center) work.

## Features

- Parses Apache/Nginx "combined" style access logs
- Six configurable detection rules (see below)
- Severity ratings: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Clear, readable terminal report
- Optional JSON report for further processing
- Configurable thresholds via `config.json` or CLI flags
- Skips malformed lines instead of crashing, and reports how many were skipped
- 100% local — no network calls, no telemetry, no data collection
- Small, well-commented codebase suitable for a student project presentation

## Installation

Requires **Python 3.8+**. No external dependencies.

```bash
git clone <this-repository>
cd log-analyzer
```

That's it — there's nothing to `pip install` (see `requirements.txt`).

## Usage

Basic usage:

```bash
python log_analyzer.py logs/sample_access.log
```

Override the brute-force detection threshold and time window:

```bash
python log_analyzer.py logs/sample_access.log --threshold 5 --window 300
```

Generate a JSON report in addition to the terminal output:

```bash
python log_analyzer.py logs/sample_access.log --json report.json
```

Show extra detail (including which configuration values are in use):

```bash
python log_analyzer.py logs/sample_access.log --verbose
```

Use a custom configuration file:

```bash
python log_analyzer.py logs/sample_access.log --config my_config.json
```

Full CLI help:

```bash
python log_analyzer.py --help
```

## Supported Log Format

Log Analyzer currently supports the Apache/Nginx **combined log format**:

```text
192.168.1.10 - - [23/Aug/2026:09:10:01 +0800] "POST /login HTTP/1.1" 401 512
```

Fields used: client IP address, timestamp, HTTP method, requested path,
HTTP status code.

The parsing logic lives entirely in `parser.py`. Additional log formats
(e.g. syslog or `auth.log`) can be added later by writing a new parsing
function there — the detection rules in `detector.py` work with the same
`LogEntry` structure regardless of which log format produced it, so they
would not need to change.

## Detection Rules

All thresholds below are configurable in `config.json` (or via CLI flags
for the login-related settings).

| Rule | What it looks for | Default threshold | Severity | Why this severity |
|---|---|---|---|---|
| **A. Brute-force logins** | N+ failed logins from one IP within a time window | 5 attempts / 5 min | **HIGH** | A burst of failed logins in a short window is a classic automated password-guessing signature |
| **B. Success after failures** | A successful login preceded by several failed attempts from the same IP | 5 prior failures | **MEDIUM** | Could mean a successful brute-force *or* a real user who mistyped their password — needs human review |
| **C. Suspicious paths** | Requests to sensitive paths like `/admin`, `/wp-admin`, `/.env`, `/etc/passwd` | configurable list | **MEDIUM** | Visiting these paths isn't proof of compromise (scanners & curious users do it too) but deserves review |
| **D. HTTP error spikes** | Unusually many `401`/`403`/`404` responses from one IP | 30 errors | **MEDIUM** | Can indicate scanning/enumeration, but broken links cause this too |
| **E. Request flooding** | Very high request volume from one IP in a short window | 100 requests / 60 sec | **HIGH** | Sustained high-volume traffic can be a DoS attempt or aggressive bot/scraper |
| **F. Attack-like patterns** | Strings associated with common web attacks (`../`, `union select`, `<script>`, `' or '1'='1`, etc.) in the request path (URL-decoded first) | configurable list | **CRITICAL** | These strings have very few legitimate reasons to appear in a URL |

Detection logic for each rule lives in its own function inside
`detector.py`, with a docstring explaining both *what* it detects and
*why* it was assigned that severity level.

## Example Output

```text
========================================
        PYTHON LOG ANALYZER
========================================

Log file: logs/sample_access.log
Lines analyzed: 186
Lines skipped (malformed): 2
Time range: 09:00:01 - 09:40:05

Suspicious Activity
----------------------------------------

[CRITICAL] Request contains a known attack-like pattern
IP: 203.0.113.50
Pattern: \.\./
Path: /search?q=../../../../etc/passwd

[HIGH] Multiple failed login attempts detected
IP: 192.168.1.10
Failed attempts: 6
Window seconds: 300

[HIGH] Unusually high request volume
IP: 172.16.0.99
Requests: 120
Window seconds: 60

[MEDIUM] Successful login after repeated failures
IP: 192.168.1.10
Failed attempts before success: 6

[MEDIUM] Excessive HTTP 404 responses
IP: 10.0.0.25
Status code: 404
Count: 34

----------------------------------------
Summary
----------------------------------------
Suspicious IPs: 4
Critical severity findings: 2
High severity findings: 2
Medium severity findings: 8
Low severity findings: 0
========================================

Note: These are rule-based indicators, not confirmed attacks.
Review findings manually before taking action.
```

(Run the tool yourself against `logs/sample_access.log` to see the complete
output — this excerpt is trimmed for the README.)

## Project Structure

```text
log-analyzer/
│
├── log_analyzer.py       # CLI entry point (argument parsing, orchestration)
├── parser.py             # Turns raw log lines into structured LogEntry objects
├── detector.py           # All detection rules (Rule A through Rule F)
├── reporter.py           # Terminal output + JSON report generation
├── config.json           # Default detection thresholds and lists
├── requirements.txt      # No external dependencies
├── README.md
│
├── logs/
│   └── sample_access.log # Sample log with intentional findings, for testing
│
└── tests/
    └── test_detector.py  # Unit tests for parser + detection functions
```

## Testing

Sample data with **intentional findings** is included at
`logs/sample_access.log`. It contains:

- Normal, unremarkable traffic
- 6+ failed logins from one IP within the brute-force window (Rule A)
- A successful login after those failures (Rule B)
- Requests to `/admin`, `/.env`, `/wp-admin`, `/phpmyadmin` (Rule C)
- 30+ `404` responses from one IP (Rule D)
- 120 requests from one IP within 60 seconds (Rule E)
- Directory traversal, SQL injection, and `<script>` payloads, including
  URL-encoded variants (Rule F)
- A few intentionally malformed lines to test error handling

Run it directly:

```bash
python log_analyzer.py logs/sample_access.log
```

Run the unit tests:

```bash
python -m unittest tests/test_detector.py -v
```

or, from the project root:

```bash
python -m unittest discover tests
```

## Limitations

> This tool is an educational log-analysis project. Its detections are
> rule-based indicators of suspicious activity and should not be treated
> as definitive proof of malicious behavior.

Specifically:

- **False positives are expected.** A user mistyping their password five
  times, a broken link generating repeated 404s, or a security researcher
  legitimately testing their own site can all trigger findings.
- **False negatives are also expected.** A patient, slow, low-and-slow
  attacker who stays under every threshold will not be flagged.
- Only one log format is currently supported (Apache/Nginx combined).
- Detection is purely rule-based — there is no machine learning, behavioral
  baselining, or correlation across multiple log sources.
- Real-world security monitoring is significantly more sophisticated than
  what a script like this can offer. Production environments typically use
  **SIEM platforms** (e.g. Splunk, Elastic Security, Microsoft Sentinel),
  **correlation rules** across many data sources, **threat intelligence
  feeds**, **behavioral/anomaly analysis**, and **human analyst
  investigation** — all working together with far more context than a
  single log file can provide.

## Future Improvements

- Support additional log formats (syslog, `auth.log`, JSON-formatted logs)
- Allowlist/denylist for known-good IPs (e.g. internal monitoring tools)
- Geolocation-based anomaly hints (e.g. logins from unexpected countries)
- A rolling "risk score" per IP that combines multiple findings
- HTML report output in addition to JSON
- Basic rate-limiting recommendations based on findings

---

**Disclaimer:** This tool works entirely locally. It does not upload logs,
call external APIs, collect telemetry, store credentials, attempt to log
into any system, or perform any active scanning/attacks. It only reads and
analyzes log files you provide.
