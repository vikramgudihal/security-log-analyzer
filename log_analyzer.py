#!/usr/bin/env python3
"""
TASK 4: Security Log Analyzer (Incident Response & Anomaly Detection)
---------------------------------------------------------------------
Analyzes authentication (Linux auth.log) and web server (Nginx/Apache) logs.
Identifies repeated failed logins, rapid bursts, off-hours activity,
and known cyber attack signatures, generating structured Tabulate & Markdown reports.
"""

import argparse
import os
import sys
from datetime import datetime
from src.parsers import LogParser
from src.analyzer import SecurityLogAnalyzer
from src.reporter import SecurityReportGenerator


def print_banner():
    banner = r"""
  ___                      _ _           _                     ___               _                     
 / __| ___ __ _  _ _ _  _(_) |_ _  _   | |   ___  __ _       /   \ _ _  __ _  | |_  _ _____ _ _ 
 \__ \/ -_) _| || | '_| | |  _| || |  | |__/ _ \/ _` |     / /_\ \ ' \/ _` | | | || |_ / -_) '_|
 |___/\___\__|\_,_|_|   |_|\__|\_, |  |____\___/\__, |    / /___\ \_||_\__,_| |_|\_, /___\___|_|   
                               |__/             |___/    /_/     \_\             |__/              
   [ Incident Response & Threat Detection Engine - Python | Regex | Datetime | Tabulate ]
    """
    print(banner)


def run_analysis(
    log_file: str,
    output_dir: str = "reports",
    output_format: str = "both",
    failed_threshold: int = 5,
    burst_threshold: int = 4,
    burst_window: int = 60,
    quiet: bool = False,
):
    if not os.path.exists(log_file):
        print(f"[!] Error: Log file '{log_file}' not found.")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(log_file))[0]

    if not quiet:
        print(f"[*] Loading and parsing log dataset: '{log_file}'...")

    parser = LogParser()
    entries = parser.parse_file(log_file)

    if not quiet:
        print(f"[+] Successfully parsed {len(entries)} events.")
        print(f"[*] Running multi-vector anomaly detection...")

    analyzer = SecurityLogAnalyzer(
        failed_login_threshold=failed_threshold,
        burst_threshold=burst_threshold,
        burst_window_seconds=burst_window,
    )
    result = analyzer.analyze(entries)

    reporter = SecurityReportGenerator(result, log_filename=log_file)
    text_report = reporter.generate_text()
    md_report = reporter.generate_markdown()

    # Console display
    if not quiet:
        print(text_report)

    # Save outputs
    created_files = []
    if output_format in ("text", "both"):
        txt_path = os.path.join(output_dir, f"security_incident_report_{base_name}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(text_report)
        created_files.append(txt_path)

    if output_format in ("markdown", "both"):
        md_path = os.path.join(output_dir, f"security_incident_report_{base_name}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_report)
        created_files.append(md_path)

    print("\n[✔] Analysis Completed Successfully!")
    for f in created_files:
        print(f"    - Generated Report: {f}")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Incident Response & Anomaly Detection"
    )
    parser.add_argument(
        "--log",
        "-l",
        type=str,
        default="logs/auth.log",
        help="Path to the log file to analyze (default: logs/auth.log)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="reports",
        help="Directory to save generated reports (default: reports)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "text", "both"],
        default="both",
        help="Report format to generate (default: both)",
    )
    parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        default=5,
        help="Failed login threshold per IP to flag (default: 5)",
    )
    parser.add_argument(
        "--burst-count",
        type=int,
        default=4,
        help="Consecutive failed logins to trigger a rapid burst alert (default: 4)",
    )
    parser.add_argument(
        "--burst-window",
        type=int,
        default=60,
        help="Time window in seconds for rapid sequential bursts (default: 60)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress banner and console table output",
    )

    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    run_analysis(
        log_file=args.log,
        output_dir=args.output_dir,
        output_format=args.format,
        failed_threshold=args.threshold,
        burst_threshold=args.burst_count,
        burst_window=args.burst_window,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    main()

