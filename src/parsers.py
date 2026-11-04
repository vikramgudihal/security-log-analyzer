"""
Log parsing engine using Python Regex and Datetime.
Supports Linux auth.log, SSH logs, and Apache/Nginx web server access logs.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Generator
import urllib.parse


@dataclass
class LogEntry:
    line_number: int
    raw_line: str
    log_type: str  # 'AUTH' or 'WEB'
    timestamp: datetime
    ip: str
    event_type: str  # 'LOGIN_FAILED', 'LOGIN_SUCCESS', 'WEB_REQUEST', 'UNKNOWN'
    user: Optional[str] = None
    is_invalid_user: bool = False
    port: Optional[int] = None
    method: Optional[str] = None
    url: Optional[str] = None
    url_decoded: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None


class LogParser:
    """Regex-based parser for authentication and web server logs."""

    # Regex for standard syslog / auth.log timestamp: "Oct 24 14:02:01" or ISO "2026-10-24T14:02:01"
    SYSLOG_TIME_REGEX = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    )
    ISO_TIME_REGEX = re.compile(
        r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})"
    )

    # Auth log patterns:
    # Failed password for invalid user <user> from <ip> port <port> ssh2
    AUTH_FAILED_INVALID_USER = re.compile(
        r"sshd\[\d+\]:\s+Failed password for invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )
    # Failed password for <user> from <ip> port <port> ssh2
    AUTH_FAILED_USER = re.compile(
        r"sshd\[\d+\]:\s+Failed password for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )
    # Invalid user <user> from <ip>
    AUTH_INVALID_USER_NOTICE = re.compile(
        r"sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )
    # Accepted password/publickey for <user> from <ip>
    AUTH_ACCEPTED_USER = re.compile(
        r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )

    # Web log pattern (Nginx / Apache Combined):
    # 192.168.1.10 - - [24/Oct/2026:08:30:20 +0000] "GET /index.html HTTP/1.1" 200 4520 "..." "..."
    WEB_LOG_REGEX = re.compile(
        r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    def __init__(self, default_year: int = 2026):
        self.default_year = default_year

    def parse_syslog_timestamp(self, ts_str: str) -> datetime:
        """Parse syslog timestamps e.g. 'Oct 24 14:02:01' or ISO format."""
        try:
            # Check ISO format first
            if "-" in ts_str:
                iso_clean = ts_str.replace("T", " ")[:19]
                return datetime.strptime(iso_clean, "%Y-%m-%d %H:%M:%S")

            # Standard syslog format: '%b %d %H:%M:%S'
            # Normalize multiple spaces like "Oct  4" -> "Oct 4"
            parts = ts_str.split()
            normalized = f"{parts[0]} {int(parts[1]):02d} {parts[2]}"
            dt = datetime.strptime(normalized, "%b %d %H:%M:%S")
            return dt.replace(year=self.default_year)
        except Exception:
            return datetime.now()

    def parse_web_timestamp(self, ts_str: str) -> datetime:
        """Parse web log timestamps e.g. '24/Oct/2026:08:30:20 +0000'."""
        try:
            clean_ts = ts_str.split()[0]  # Take datetime part without offset
            return datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
        except Exception:
            return datetime.now()

    def parse_line(self, line: str, line_number: int = 1) -> Optional[LogEntry]:
        """Parses a single log line into a standardized LogEntry."""
        line = line.strip()
        if not line:
            return None

        # 1. Try Web Log format
        web_match = self.WEB_LOG_REGEX.match(line)
        if web_match:
            ip = web_match.group("ip")
            ts = self.parse_web_timestamp(web_match.group("timestamp"))
            method = web_match.group("method")
            raw_url = web_match.group("url")
            status = int(web_match.group("status"))
            user_agent = web_match.group("user_agent") or ""
            decoded_url = urllib.parse.unquote(raw_url)

            # Detect web authentication failures (HTTP 401 or login page failed POSTs)
            event_type = "WEB_REQUEST"
            if status in (401, 403) or ("/login" in raw_url.lower() and status >= 400):
                event_type = "LOGIN_FAILED"

            return LogEntry(
                line_number=line_number,
                raw_line=line,
                log_type="WEB",
                timestamp=ts,
                ip=ip,
                event_type=event_type,
                user=None,
                method=method,
                url=raw_url,
                url_decoded=decoded_url,
                status_code=status,
                user_agent=user_agent,
            )

        # 2. Try Linux Auth / Syslog format
        # Check timestamp
        sys_match = self.SYSLOG_TIME_REGEX.match(line)
        iso_match = self.ISO_TIME_REGEX.match(line)

        ts = datetime.now()
        if sys_match:
            ts = self.parse_syslog_timestamp(sys_match.group(1))
        elif iso_match:
            ts = self.parse_syslog_timestamp(iso_match.group(1))

        # Check Failed Password for Invalid User
        m = self.AUTH_FAILED_INVALID_USER.search(line)
        if m:
            return LogEntry(
                line_number=line_number,
                raw_line=line,
                log_type="AUTH",
                timestamp=ts,
                ip=m.group("ip"),
                event_type="LOGIN_FAILED",
                user=m.group("user"),
                is_invalid_user=True,
                port=int(m.group("port")),
            )

        # Check Failed Password for existing user
        m = self.AUTH_FAILED_USER.search(line)
        if m:
            return LogEntry(
                line_number=line_number,
                raw_line=line,
                log_type="AUTH",
                timestamp=ts,
                ip=m.group("ip"),
                event_type="LOGIN_FAILED",
                user=m.group("user"),
                is_invalid_user=False,
                port=int(m.group("port")),
            )

        # Check Accepted login
        m = self.AUTH_ACCEPTED_USER.search(line)
        if m:
            return LogEntry(
                line_number=line_number,
                raw_line=line,
                log_type="AUTH",
                timestamp=ts,
                ip=m.group("ip"),
                event_type="LOGIN_SUCCESS",
                user=m.group("user"),
                is_invalid_user=False,
                port=int(m.group("port")),
            )

        # Other auth lines (e.g. session opened or invalid user notice)
        m = self.AUTH_INVALID_USER_NOTICE.search(line)
        if m:
            return LogEntry(
                line_number=line_number,
                raw_line=line,
                log_type="AUTH",
                timestamp=ts,
                ip=m.group("ip"),
                event_type="LOGIN_FAILED",
                user=m.group("user"),
                is_invalid_user=True,
            )

        return None

    def parse_file(self, filepath: str) -> List[LogEntry]:
        """Reads and parses an entire log file."""
        entries = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
                entry = self.parse_line(line, line_number=idx)
                if entry:
                    entries.append(entry)
        return entries

