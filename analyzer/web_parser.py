"""
Apache and Nginx Web Server Access Log Parser.
Extracts HTTP requests, methods, URIs, status codes, user agents, and IP addresses.
"""

import re
import urllib.parse
from datetime import datetime
from typing import Optional
from analyzer.normalizer import LogEvent
from config import Config


class WebParser:
    """Parser for Apache and Nginx access logs (Common and Combined formats)."""

    # Combined Log Format:
    # 192.168.1.10 - - [21/Oct/2026:08:30:20 +0000] "GET /index.html HTTP/1.1" 200 4520 "referrer" "user-agent"
    WEB_LOG_REGEX = re.compile(
        r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(?P<ident>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    # Simpler request line fallback (e.g. malformed or HTTP 0.9 / 400 bad request)
    SIMPLE_WEB_REGEX = re.compile(
        r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})'
    )

    def __init__(self, timezone: str = Config.TIMEZONE):
        self.timezone = timezone

    def parse_web_timestamp(self, ts_str: str) -> tuple[datetime, str]:
        """Parses web server datetime strings like '21/Oct/2026:08:30:20 +0000'."""
        try:
            time_part = ts_str.split()[0]
            dt = datetime.strptime(time_part, "%d/%b/%Y:%H:%M:%S")
            return dt, ts_str
        except Exception:
            now = datetime.now()
            return now, ts_str

    def parse_line(self, line: str, line_id: int) -> Optional[LogEvent]:
        """Parses a single line from an Apache or Nginx access log."""
        line = line.strip()
        if not line:
            return None

        # 1. Standard Combined / Common format match
        m = self.WEB_LOG_REGEX.match(line)
        if m:
            ip = m.group("ip")
            dt, raw_ts = self.parse_web_timestamp(m.group("timestamp"))
            method = m.group("method")
            raw_url = m.group("url")
            status = int(m.group("status"))
            user_agent = m.group("user_agent") or ""
            ident_user = m.group("ident")
            username = ident_user if (ident_user and ident_user != "-") else None

            try:
                decoded_url = urllib.parse.unquote(raw_url)
            except Exception:
                decoded_url = raw_url

            # Determine authentication and event type
            is_auth_failure = (status in (401, 403)) or ("/login" in raw_url.lower() and status >= 400)
            if is_auth_failure:
                event_type = "LOGIN_FAILED"
                auth_status = "FAILURE"
            else:
                event_type = "WEB_REQUEST"
                auth_status = "SUCCESS" if status < 400 else "N/A"

            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=ip,
                log_type="WEB",
                event_type=event_type,
                auth_status=auth_status,
                username=username,
                http_method=method,
                http_status=status,
                url=decoded_url,
                user_agent=user_agent,
                message=line,
                timezone=self.timezone,
            )

        # 2. Fallback simpler match
        m_simple = self.SIMPLE_WEB_REGEX.match(line)
        if m_simple:
            ip = m_simple.group("ip")
            dt, raw_ts = self.parse_web_timestamp(m_simple.group("timestamp"))
            req_parts = m_simple.group("request").split()
            method = req_parts[0] if len(req_parts) > 0 else "GET"
            raw_url = req_parts[1] if len(req_parts) > 1 else "/"
            status = int(m_simple.group("status"))

            try:
                decoded_url = urllib.parse.unquote(raw_url)
            except Exception:
                decoded_url = raw_url

            is_auth_failure = (status in (401, 403))
            return LogEvent(
                id=line_id,
                timestamp=dt,
                raw_timestamp=raw_ts,
                source_ip=ip,
                log_type="WEB",
                event_type="LOGIN_FAILED" if is_auth_failure else "WEB_REQUEST",
                auth_status="FAILURE" if is_auth_failure else "N/A",
                http_method=method,
                http_status=status,
                url=decoded_url,
                message=line,
                timezone=self.timezone,
            )

        return None

