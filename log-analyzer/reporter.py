"""
reporter.py
-----------
Turns a list of findings into human-readable terminal output and/or
a JSON report file. Keeping presentation logic separate from
detection logic (detector.py) means we can change how results are
displayed without touching any detection rules.
"""

import json
from datetime import datetime
from typing import List, Dict, Any


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort findings so the most severe issues appear first."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))


def count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity = finding.get("severity", "LOW")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def unique_ips(findings: List[Dict[str, Any]]) -> int:
    return len({f["ip"] for f in findings if "ip" in f})


def _format_finding_lines(finding: Dict[str, Any]) -> str:
    """Format one finding as a multi-line, human-readable block."""
    lines = [f"[{finding['severity']}] {finding['description']}"]

    if "ip" in finding:
        lines.append(f"IP: {finding['ip']}")

    for key, value in finding.get("details", {}).items():
        # Turn "failed_attempts" -> "Failed attempts" for nicer display
        label = key.replace("_", " ").capitalize()
        lines.append(f"{label}: {value}")

    return "\n".join(lines)


def print_terminal_report(log_file: str, entries, total_lines: int,
                           skipped_lines: int,
                           findings: List[Dict[str, Any]]) -> None:
    """Print the full analysis report to the terminal."""
    width = 40
    sorted_findings = sort_findings(findings)
    severity_counts = count_by_severity(findings)

    print("=" * width)
    print("        PYTHON LOG ANALYZER")
    print("=" * width)
    print()
    print(f"Log file: {log_file}")
    print(f"Lines analyzed: {total_lines:,}")
    print(f"Lines skipped (malformed): {skipped_lines:,}")

    if entries:
        start_time = min(e.timestamp for e in entries)
        end_time = max(e.timestamp for e in entries)
        print(f"Time range: {start_time.strftime('%H:%M:%S')} - {end_time.strftime('%H:%M:%S')}")

    print()
    print("Suspicious Activity")
    print("-" * width)
    print()

    if not sorted_findings:
        print("No suspicious activity detected.")
        print()
    else:
        for finding in sorted_findings:
            print(_format_finding_lines(finding))
            print()

    print("-" * width)
    print("Summary")
    print("-" * width)
    print(f"Suspicious IPs: {unique_ips(findings)}")
    print(f"Critical severity findings: {severity_counts['CRITICAL']}")
    print(f"High severity findings: {severity_counts['HIGH']}")
    print(f"Medium severity findings: {severity_counts['MEDIUM']}")
    print(f"Low severity findings: {severity_counts['LOW']}")
    print("=" * width)
    print()
    print("Note: These are rule-based indicators, not confirmed attacks.")
    print("Review findings manually before taking action.")


def write_json_report(output_path: str, log_file: str, total_lines: int,
                       skipped_lines: int,
                       findings: List[Dict[str, Any]]) -> None:
    """Write findings and summary statistics to a JSON file."""
    severity_counts = count_by_severity(findings)

    report = {
        "generated_at": datetime.now().isoformat(),
        "log_file": log_file,
        "summary": {
            "lines_analyzed": total_lines,
            "lines_skipped": skipped_lines,
            "suspicious_ips": unique_ips(findings),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
        },
        "findings": sort_findings(findings),
    }

    with open(output_path, "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=2)
