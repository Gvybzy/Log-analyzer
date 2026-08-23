#!/usr/bin/env python3
"""
log_analyzer.py
----------------
Command-line entry point for the Log Analyzer tool.

This is an educational cybersecurity project that scans web-server
style access logs for rule-based indicators of suspicious activity
(e.g. possible brute-force login attempts, requests to sensitive
paths, error spikes, request flooding, and known attack-like
patterns).

IMPORTANT: This tool does NOT prove that an attack occurred. It flags
patterns worth a human's attention. See README.md for details and
limitations.

Usage:
    python log_analyzer.py access.log
    python log_analyzer.py access.log --threshold 5 --window 300
    python log_analyzer.py access.log --json report.json
    python log_analyzer.py access.log --verbose
"""

import argparse
import json
import sys
from pathlib import Path

from parser import parse_log_file
from detector import run_all_detections
from reporter import print_terminal_report, write_json_report


DEFAULT_CONFIG_PATH = "config.json"

# Fallback values used if config.json is missing or a key is absent.
# Keeping these here means the program still runs even without a
# configuration file, just with sensible defaults.
DEFAULT_CONFIG = {
    "failed_login_threshold": 5,
    "failed_login_window_seconds": 300,
    "request_threshold": 100,
    "request_window_seconds": 60,
    "error_threshold": 30,
    "suspicious_paths": [
        "/admin", "/login", "/wp-admin", "/phpmyadmin",
        "/etc/passwd", "/.env", "/config",
    ],
    "attack_patterns": [
        r"\.\./", r"/etc/passwd", r"union\s+select",
        r"'\s*or\s*'1'\s*=\s*'1", r"<script",
    ],
}


def build_arg_parser() -> argparse.ArgumentParser:
    """Define and return the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description=(
            "Log Analyzer: an educational tool that scans web-server "
            "access logs for rule-based indicators of suspicious "
            "activity, such as possible brute-force logins, requests "
            "to sensitive paths, HTTP error spikes, request flooding, "
            "and known attack-like patterns."
        ),
        epilog=(
            "Note: findings are heuristic indicators, not confirmed "
            "attacks. Always review results manually."
        ),
    )

    parser.add_argument(
        "log_file",
        help="Path to the log file to analyze (Apache/Nginx combined format).",
    )

    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to a JSON configuration file (default: {DEFAULT_CONFIG_PATH}).",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Override the failed-login threshold (number of attempts).",
    )

    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help="Override the failed-login time window, in seconds.",
    )

    parser.add_argument(
        "--json",
        metavar="OUTPUT_PATH",
        default=None,
        help="Write a JSON report to the given path in addition to the terminal report.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional detail, including config values in use.",
    )

    return parser


def load_config(config_path: str, verbose: bool = False) -> dict:
    """
    Load configuration from a JSON file, falling back to built-in
    defaults for any missing keys (or if the file doesn't exist).
    """
    config = dict(DEFAULT_CONFIG)  # start from defaults, then overlay file values

    path = Path(config_path)
    if not path.exists():
        if verbose:
            print(f"[info] Config file '{config_path}' not found; using built-in defaults.")
        return config

    try:
        with open(path, "r", encoding="utf-8") as config_file:
            file_config = json.load(config_file)
        # Ignore the "_comment" key if present; it's just documentation.
        file_config.pop("_comment", None)
        config.update(file_config)
    except (json.JSONDecodeError, OSError) as error:
        print(f"[warning] Could not read config file '{config_path}': {error}")
        print("[warning] Falling back to built-in default configuration.")

    return config


def main() -> int:
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args()

    # --- Load configuration --------------------------------------------
    config = load_config(args.config, verbose=args.verbose)

    # Command-line flags override config-file values when provided.
    if args.threshold is not None:
        config["failed_login_threshold"] = args.threshold
    if args.window is not None:
        config["failed_login_window_seconds"] = args.window

    if args.verbose:
        print("[info] Using configuration:")
        for key, value in config.items():
            print(f"        {key}: {value}")
        print()

    # --- Validate the log file ------------------------------------------
    log_path = Path(args.log_file)

    if not log_path.exists():
        print(f"Error: log file '{args.log_file}' does not exist.")
        return 1

    if not log_path.is_file():
        print(f"Error: '{args.log_file}' is not a regular file.")
        return 1

    try:
        # A quick readability check gives a clearer error message than
        # letting a PermissionError bubble up from deep inside parsing.
        with open(log_path, "r", encoding="utf-8", errors="replace"):
            pass
    except PermissionError:
        print(f"Error: permission denied when trying to read '{args.log_file}'.")
        return 1
    except OSError as error:
        print(f"Error: could not open '{args.log_file}': {error}")
        return 1

    # --- Parse the log file ----------------------------------------------
    try:
        entries, total_lines, skipped_lines = parse_log_file(str(log_path))
    except OSError as error:
        print(f"Error: could not read '{args.log_file}': {error}")
        return 1

    if total_lines == 0:
        print(f"Log file '{args.log_file}' is empty. Nothing to analyze.")
        return 0

    if not entries:
        print(
            f"Warning: none of the {total_lines} lines in '{args.log_file}' "
            "matched the supported log format. No analysis was performed."
        )
        print("Supported format: Apache/Nginx 'combined' access log.")
        return 0

    # --- Run detection rules ----------------------------------------------
    findings = run_all_detections(entries, config)

    # --- Report results -----------------------------------------------------
    print_terminal_report(
        log_file=args.log_file,
        entries=entries,
        total_lines=total_lines,
        skipped_lines=skipped_lines,
        findings=findings,
    )

    if args.json:
        write_json_report(
            output_path=args.json,
            log_file=args.log_file,
            total_lines=total_lines,
            skipped_lines=skipped_lines,
            findings=findings,
        )
        print(f"\nJSON report written to: {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
