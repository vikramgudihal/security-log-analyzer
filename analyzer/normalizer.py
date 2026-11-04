"""
Standardized Log Event and Anomaly Data Models.
Normalizes heterogeneous logs (Auth, Apache, Nginx) into a consistent schema.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
import html


@dataclass
class LogEvent:
    """Standardized representation of a single security log event."""
    id: int
    timestamp: datetime
    raw_timestamp: str
    source_ip: str
    log_type: str                  # 'AUTH' or 'WEB'
    event_type: str                # 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'WEB_REQUEST', 'SESSION_OPEN', 'UNKNOWN'
    auth_status: str               # 'SUCCESS', 'FAILURE', 'N/A'
    username: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    url: Optional[str] = None
    user_agent: Optional[str] = None
    message: str = ""
    is_invalid_user: bool = False
    port: Optional[int] = None
    timezone: str = "UTC"

    def to_dict(self) -> Dict[str, Any]:
        """Converts to a dictionary suitable for JSON serialization and Jinja templates."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "raw_timestamp": self.raw_timestamp,
            "source_ip": self.source_ip,
            "log_type": self.log_type,
            "event_type": self.event_type,
            "auth_status": self.auth_status,
            "username": self.username or "N/A",
            "http_method": self.http_method or "-",
            "http_status": self.http_status or "-",
            "url": self.url or "-",
            "user_agent": self.user_agent or "-",
            "message": html.escape(self.message),
            "is_invalid_user": self.is_invalid_user,
            "port": self.port or "-",
            "timezone": self.timezone,
        }


@dataclass
class Incident:
    """Represents a flagged security incident / anomaly."""
    id: str
    rule_name: str
    description: str
    source_ip: str
    timestamp: datetime
    severity: str                  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    reason: str
    recommended_steps: List[str]
    related_events: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "description": self.description,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": self.severity,
            "reason": self.reason,
            "recommended_steps": self.recommended_steps,
            "related_events": self.related_events,
            "metadata": self.metadata,
        }


@dataclass
class ParseStats:
    """Metrics tracking parser success and failure counts."""
    total_lines: int = 0
    parsed_events: int = 0
    failed_lines: int = 0
    format_detected: str = "Unknown"
    parse_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "failed_lines": self.failed_lines,
            "format_detected": self.format_detected,
            "parse_errors": self.parse_errors[:10],
        }
