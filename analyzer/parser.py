"""
Master Log Parser Dispatcher.
Auto-detects log format, dispatches to AuthParser or WebParser, and aggregates parsing statistics.
"""

from typing import List, Tuple
from analyzer.auth_parser import AuthParser
from analyzer.web_parser import WebParser
from analyzer.normalizer import LogEvent, ParseStats
from config import Config


class MasterParser:
    """Master parser orchestrator with format auto-detection and error tracking."""

    def __init__(self, default_year: int = Config.DEFAULT_YEAR, timezone: str = Config.TIMEZONE):
        self.auth_parser = AuthParser(default_year=default_year, timezone=timezone)
        self.web_parser = WebParser(timezone=timezone)

    def detect_format(self, lines: List[str]) -> str:
        """Inspects initial sample lines to detect format."""
        auth_matches = 0
        web_matches = 0

        for line in lines[:20]:
            line_str = line.strip()
            if not line_str:
                continue
            if "sshd[" in line_str or "pam_unix" in line_str:
                auth_matches += 1
            if 'HTTP/' in line_str or '"] ' in line_str:
                web_matches += 1

        if auth_matches > 0 and web_matches == 0:
            return "Linux Auth Log (auth.log/secure)"
        if web_matches > 0 and auth_matches == 0:
            return "Web Server Log (Nginx/Apache)"
        if auth_matches > 0 and web_matches > 0:
            return "Mixed Heterogeneous Log"
        return "Generic Server Log"

    def parse_content(self, content: str) -> Tuple[List[LogEvent], ParseStats]:
        """
        Parses text content of an uploaded or sample log file.
        Returns a tuple of (parsed_events, parse_stats).
        """
        lines = content.splitlines()
        stats = ParseStats(total_lines=len(lines))

        if not lines:
            stats.format_detected = "Empty File"
            return [], stats

        stats.format_detected = self.detect_format(lines)
        events: List[LogEvent] = []

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            event: LogEvent = None

            # Attempt web parser first if line looks like HTTP request
            if 'HTTP/' in line_str or '" ' in line_str:
                event = self.web_parser.parse_line(line_str, line_id=idx)

            # If not web or failed, try auth parser
            if not event:
                event = self.auth_parser.parse_line(line_str, line_id=idx)

            # If still not parsed, try web parser as fallback
            if not event:
                event = self.web_parser.parse_line(line_str, line_id=idx)

            if event:
                events.append(event)
                stats.parsed_events += 1
            else:
                stats.failed_lines += 1
                if len(stats.parse_errors) < 10:
                    stats.parse_errors.append(f"Line {idx}: Unrecognized format -> {line_str[:70]}...")

        return events, stats

    def parse_file(self, filepath: str) -> Tuple[List[LogEvent], ParseStats]:
        """Reads a file path and parses it."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return self.parse_content(content)
        except Exception as e:
            stats = ParseStats(total_lines=0, failed_lines=0, format_detected="Read Error")
            stats.parse_errors.append(str(e))
            return [], stats
