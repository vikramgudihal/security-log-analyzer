"""
Linux Authentication Log Parser (auth.log and secure).
Uses regular expressions to extract authentication events, source IPs, usernames, and timestamps.
"""

import re
from datetime import datetime
from typing import Optional
from analyzer.normalizer import LogEvent
from config import Config


class AuthParser:
    """Parser for Linux sshd, pam, and system authentication logs."""

    # Timestamp patterns
    SYSLOG_TIME_REGEX = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    )
    ISO_TIME_REGEX = re.compile(
        r"^(?P<iso>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    )

    # SSH Authentication Patterns
    SSH_FAILED_INVALID = re.compile(
        r"sshd\[\d+\]:\s+Failed password for invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )
    SSH_FAILED_USER = re.compile(
        r"sshd\[\d+\]:\s+Failed password for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )
    SSH_ACCEPTED = re.compile(
        r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey|keyboard-interactive)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )
    SSH_INVALID_USER = re.compile(
        r"sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )
    PAM_AUTH_FAILURE = re.compile(
        r"pam_unix\(sshd:auth\):\s+authentication failure;\s+.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+user=(?P<user>\S+))?",
        re.IGNORECASE,
    )
    SESSION_OPENED = re.compile(
        r"sshd\[\d+\]:\s+session opened for user\s+(?P<user>\S+)\s+by\s+\(uid=\d+\)",
        re.IGNORECASE,
    )

    # General IP fallback if no specific SSH pattern matches
    IP_REGEX = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")

    def __init__(self, default_year: int = Config.DEFAULT_YEAR, timezone: str = Config.TIMEZONE):
        self.default_year = default_year
        self.timezone = timezone

    def parse_timestamp(self, line: str) -> tuple[datetime, str]:
        """
        Extracts and parses timestamp with explicit year inference and timezone.
        Returns (parsed_datetime, raw_timestamp_string).
        """
        # Try ISO 8601 first
        iso_match = self.ISO_TIME_REGEX.match(line)
        if iso_match:
            raw_ts = iso_match.group("iso")
            clean_ts = raw_ts.replace("T", " ")[:19]
            dt = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S")
            return dt, raw_ts

        # Try standard Syslog: "Oct 21 08:30:15"
        sys_match = self.SYSLOG_TIME_REGEX.match(line)
        if sys_match:
            month = sys_match.group("month")
            day = int(sys_match.group("day"))
            time_part = sys_match.group("time")
            raw_ts = f"{month} {day:02d} {time_part}"
            normalized_str = f"{self.default_year} {month} {day:02d} {time_part}"
            dt = datetime.strptime(normalized_str, "%Y %b %d %H:%M:%S")
            return dt, raw_ts

        # Fallback to current time if no timestamp match
        now = datetime.now()
        return now, now.strftime("%Y-%m-%d %H:%M:%S")

    def parse_line(self, line: str, line_id: int) -> Optional[LogEvent]:
        """Parses a single line from an authentication log file."""
        line = line.strip()
        if not line:
            return None

        dt, raw_ts = self.parse_timestamp(line)

        # 1. Failed login with invalid user
        m = self.SSH_FAILED_INVALID.search(line)
        if m:
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=m.group("ip"),
                log_type="AUTH",
                event_type="LOGIN_FAILED",
                auth_status="FAILURE",
                username=m.group("user"),
                is_invalid_user=True,
                port=int(m.group("port")),
                message=line,
                timezone=self.timezone,
            )

        # 2. Failed login with existing user
        m = self.SSH_FAILED_USER.search(line)
        if m:
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=m.group("ip"),
                log_type="AUTH",
                event_type="LOGIN_FAILED",
                auth_status="FAILURE",
                username=m.group("user"),
                is_invalid_user=False,
                port=int(m.group("port")),
                message=line,
                timezone=self.timezone,
            )

        # 3. Accepted login
        m = self.SSH_ACCEPTED.search(line)
        if m:
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=m.group("ip"),
                log_type="AUTH",
                event_type="LOGIN_SUCCESS",
                auth_status="SUCCESS",
                username=m.group("user"),
                is_invalid_user=False,
                port=int(m.group("port")),
                message=line,
                timezone=self.timezone,
            )

        # 4. Invalid user probe notice
        m = self.SSH_INVALID_USER.search(line)
        if m:
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=m.group("ip"),
                log_type="AUTH",
                event_type="LOGIN_FAILED",
                auth_status="FAILURE",
                username=m.group("user"),
                is_invalid_user=True,
                message=line,
                timezone=self.timezone,
            )

        # 5. PAM failure
        m = self.PAM_AUTH_FAILURE.search(line)
        if m:
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=m.group("ip"),
                log_type="AUTH",
                event_type="LOGIN_FAILED",
                auth_status="FAILURE",
                username=m.group("user") if m.group("user") else "unknown",
                message=line,
                timezone=self.timezone,
            )

        # 6. Session opened
        m = self.SESSION_OPENED.search(line)
        if m:
            # Check if there is an IP in the line
            ip_m = self.IP_REGEX.search(line)
            source_ip = ip_m.group("ip") if ip_m else "127.0.0.1"
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=source_ip,
                log_type="AUTH",
                event_type="SESSION_OPEN",
                auth_status="SUCCESS",
                username=m.group("user"),
                message=line,
                timezone=self.timezone,
            )

        # If it's a general auth line with an IP, capture it as general event
        ip_m = self.IP_REGEX.search(line)
        if ip_m and ("sshd" in line or "login" in line):
            is_failure = "fail" in line.lower() or "error" in line.lower()
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=ip_m.group("ip"),
                log_type="AUTH",
                event_type="LOGIN_FAILED" if is_failure else "UNKNOWN",
                auth_status="FAILURE" if is_failure else "N/A",
                message=line,
                timezone=self.timezone,
            )

        return None

