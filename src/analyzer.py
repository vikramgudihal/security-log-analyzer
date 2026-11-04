"""
Security Log Analyzer Engine.
Detects repeated failed logins, rapid bursts, off-hours activity,
and known attack signatures, clearly distinguishing routine errors from malicious attacks.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, time
from typing import Dict, List, Optional, Tuple
from src.parsers import LogEntry
from src.signatures import WEB_ATTACK_SIGNATURES, HIGH_VALUE_TARGET_USERS


@dataclass
class Anomaly:
    anomaly_type: str  # 'BRUTE_FORCE_BURST', 'HIGH_FAILED_LOGINS', 'OFF_HOURS_ACCESS', 'ATTACK_SIGNATURE', 'UNAUTHORIZED_ROOT_LOGIN'
    severity: str      # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    ip: str
    timestamp: datetime
    description: str
    details: Dict[str, any] = field(default_factory=dict)


@dataclass
class IPActivitySummary:
    ip: str
    total_events: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    targeted_users: List[str] = field(default_factory=list)
    invalid_user_attempts: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    attack_signatures_detected: List[str] = field(default_factory=list)
    is_burst_detected: bool = False
    is_off_hours_active: bool = False
    off_hours_count: int = 0
    classification: str = "BENIGN"  # 'ROUTINE_ERROR', 'SUSPICIOUS', 'BRUTE_FORCE_ATTACK', 'EXPLOIT_SCANNER'
    threat_severity: str = "LOW"    # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'


@dataclass
class AnalysisResult:
    total_logs_analyzed: int
    auth_logs_count: int
    web_logs_count: int
    ip_summaries: Dict[str, IPActivitySummary]
    anomalies: List[Anomaly]
    routine_errors: List[Dict[str, any]]
    malicious_attacks: List[Dict[str, any]]
    severity_counts: Dict[str, int]
    top_offending_ips: List[Tuple[str, int]]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class SecurityLogAnalyzer:
    """Core detection engine for authentication and web server security anomalies."""

    def __init__(
        self,
        failed_login_threshold: int = 5,
        burst_threshold: int = 4,
        burst_window_seconds: int = 60,
        business_start_hour: int = 8,
        business_end_hour: int = 18,
    ):
        self.failed_login_threshold = failed_login_threshold
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        self.business_start = time(business_start_hour, 0, 0)
        self.business_end = time(business_end_hour, 0, 0)

    def is_off_hours(self, dt: datetime) -> bool:
        """Determines if a timestamp falls outside regular business hours (Mon-Fri 08:00-18:00)."""
        # Weekend check (5 = Saturday, 6 = Sunday)
        if dt.weekday() >= 5:
            return True
        # Time of day check
        event_time = dt.time()
        return not (self.business_start <= event_time <= self.business_end)

    def analyze(self, entries: List[LogEntry]) -> AnalysisResult:
        """Performs multi-vector anomaly detection on parsed log entries."""
        if not entries:
            return AnalysisResult(
                total_logs_analyzed=0,
                auth_logs_count=0,
                web_logs_count=0,
                ip_summaries={},
                anomalies=[],
                routine_errors=[],
                malicious_attacks=[],
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                top_offending_ips=[],
            )

        entries_by_ip = defaultdict(list)
        auth_count = 0
        web_count = 0
        min_ts = entries[0].timestamp
        max_ts = entries[0].timestamp

        for entry in entries:
            if entry.log_type == "AUTH":
                auth_count += 1
            elif entry.log_type == "WEB":
                web_count += 1

            if entry.timestamp < min_ts:
                min_ts = entry.timestamp
            if entry.timestamp > max_ts:
                max_ts = entry.timestamp

            entries_by_ip[entry.ip].append(entry)

        anomalies: List[Anomaly] = []
        ip_summaries: Dict[str, IPActivitySummary] = {}
        routine_errors: List[Dict[str, any]] = []
        malicious_attacks: List[Dict[str, any]] = []

        # Analyze each IP
        for ip, ip_entries in entries_by_ip.items():
            # Sort entries chronologically
            ip_entries.sort(key=lambda x: x.timestamp)

            summary = IPActivitySummary(ip=ip)
            summary.total_events = len(ip_entries)
            summary.first_seen = ip_entries[0].timestamp
            summary.last_seen = ip_entries[-1].timestamp

            targeted_users = set()
            failed_attempts: List[LogEntry] = []
            successful_logins: List[LogEntry] = []
            off_hours_failed: List[LogEntry] = []

            for e in ip_entries:
                if e.user:
                    targeted_users.add(e.user)

                is_off = self.is_off_hours(e.timestamp)
                if is_off:
                    summary.is_off_hours_active = True
                    summary.off_hours_count += 1

                if e.event_type == "LOGIN_FAILED":
                    summary.failed_logins += 1
                    failed_attempts.append(e)
                    if e.is_invalid_user:
                        summary.invalid_user_attempts += 1
                    if is_off:
                        off_hours_failed.append(e)

                elif e.event_type == "LOGIN_SUCCESS":
                    summary.successful_logins += 1
                    successful_logins.append(e)
                    # Alert on privileged root login during off hours
                    if is_off and e.user in ("root", "admin", "administrator"):
                        anomalies.append(
                            Anomaly(
                                anomaly_type="UNAUTHORIZED_ROOT_LOGIN",
                                severity="CRITICAL",
                                ip=ip,
                                timestamp=e.timestamp,
                                description=f"Privileged '{e.user}' login confirmed during off-hours ({e.timestamp.strftime('%H:%M:%S')})",
                                details={"user": e.user, "time": str(e.timestamp)},
                            )
                        )

                # Check Web Attack Signatures
                if e.log_type == "WEB" and e.url_decoded:
                    target_payload = f"{e.url_decoded} {e.user_agent or ''}"
                    for sig_key, sig_data in WEB_ATTACK_SIGNATURES.items():
                        if sig_data["pattern"].search(target_payload):
                            if sig_key not in summary.attack_signatures_detected:
                                summary.attack_signatures_detected.append(sig_key)

                            anomalies.append(
                                Anomaly(
                                    anomaly_type="ATTACK_SIGNATURE",
                                    severity=sig_data["severity"],
                                    ip=ip,
                                    timestamp=e.timestamp,
                                    description=f"{sig_data['description']} in request '{e.method} {e.url}'",
                                    details={
                                        "signature": sig_key,
                                        "method": e.method,
                                        "url": e.url_decoded,
                                        "status": e.status_code,
                                        "user_agent": e.user_agent,
                                    },
                                )
                            )

            summary.targeted_users = sorted(list(targeted_users))

            # Flag Off-Hours Failed Attempts (aggregated per IP to avoid alert fatigue)
            if off_hours_failed:
                anomalies.append(
                    Anomaly(
                        anomaly_type="OFF_HOURS_ACCESS",
                        severity="HIGH" if len(off_hours_failed) >= 3 else "MEDIUM",
                        ip=ip,
                        timestamp=off_hours_failed[0].timestamp,
                        description=(
                            f"{len(off_hours_failed)} failed login attempts during off-hours "
                            f"(First seen at {off_hours_failed[0].timestamp.strftime('%H:%M:%S')})"
                        ),
                        details={"off_hours_failed_count": len(off_hours_failed)},
                    )
                )

            # Detect Rapid Sequential Burst Attacks (Brute-Force Bursts)
            # Sliding window over failed attempts
            if len(failed_attempts) >= self.burst_threshold:
                for i in range(len(failed_attempts) - self.burst_threshold + 1):
                    window_start = failed_attempts[i].timestamp
                    window_end = failed_attempts[i + self.burst_threshold - 1].timestamp
                    duration = (window_end - window_start).total_seconds()

                    if duration <= self.burst_window_seconds:
                        summary.is_burst_detected = True
                        anomalies.append(
                            Anomaly(
                                anomaly_type="BRUTE_FORCE_BURST",
                                severity="CRITICAL" if summary.failed_logins >= 10 else "HIGH",
                                ip=ip,
                                timestamp=window_start,
                                description=(
                                    f"Rapid brute-force burst: {self.burst_threshold} failed attempts in {int(duration)}s "
                                    f"targeting {', '.join(list(targeted_users)[:4])}"
                                ),
                                details={
                                    "burst_size": self.burst_threshold,
                                    "duration_seconds": duration,
                                    "targeted_users": list(targeted_users),
                                },
                            )
                        )
                        break  # Flag burst once per IP to avoid duplicates

            # Threshold Violation Check
            if summary.failed_logins >= self.failed_login_threshold:
                sev = "CRITICAL" if summary.failed_logins >= 15 else "HIGH"
                anomalies.append(
                    Anomaly(
                        anomaly_type="HIGH_FAILED_LOGINS",
                        severity=sev,
                        ip=ip,
                        timestamp=summary.last_seen,
                        description=(
                            f"Exceeded failed login threshold: {summary.failed_logins} failed attempts "
                            f"(Threshold = {self.failed_login_threshold})"
                        ),
                        details={
                            "failed_count": summary.failed_logins,
                            "invalid_users": summary.invalid_user_attempts,
                        },
                    )
                )

            # Classify IP: ROUTINE ERROR vs MALICIOUS ATTACK
            has_signatures = len(summary.attack_signatures_detected) > 0
            has_burst = summary.is_burst_detected
            targets_system_accounts = bool(set(summary.targeted_users).intersection(HIGH_VALUE_TARGET_USERS))
            is_high_volume = summary.failed_logins >= self.failed_login_threshold

            if has_signatures:
                summary.classification = "EXPLOIT_SCANNER"
                summary.threat_severity = "CRITICAL"
                malicious_attacks.append({
                    "ip": ip,
                    "type": "Exploit & Vulnerability Probing",
                    "reason": f"Active attack signatures: {', '.join(summary.attack_signatures_detected)}",
                    "severity": summary.threat_severity,
                    "events": summary.total_events,
                })
            elif has_burst or (is_high_volume and (summary.invalid_user_attempts > 0 or targets_system_accounts)):
                summary.classification = "BRUTE_FORCE_ATTACK"
                summary.threat_severity = "CRITICAL" if summary.failed_logins >= 10 else "HIGH"
                malicious_attacks.append({
                    "ip": ip,
                    "type": "Automated Brute-Force / Credential Stuffing",
                    "reason": f"{summary.failed_logins} failed logins, {summary.invalid_user_attempts} invalid users, burst={has_burst}",
                    "severity": summary.threat_severity,
                    "events": summary.total_events,
                })
            elif summary.failed_logins > 0 and summary.failed_logins < self.failed_login_threshold:
                # Differentiate routine login errors:
                if summary.successful_logins > 0 and not summary.is_off_hours_active:
                    summary.classification = "ROUTINE_ERROR"
                    summary.threat_severity = "LOW"
                    routine_errors.append({
                        "ip": ip,
                        "user": summary.targeted_users[0] if summary.targeted_users else "user",
                        "failed_count": summary.failed_logins,
                        "resolved": True,
                        "context": "Routine mistyped password followed by successful login during business hours",
                    })
                elif not summary.is_off_hours_active:
                    summary.classification = "ROUTINE_ERROR"
                    summary.threat_severity = "LOW"
                    routine_errors.append({
                        "ip": ip,
                        "user": ", ".join(summary.targeted_users),
                        "failed_count": summary.failed_logins,
                        "resolved": False,
                        "context": "Isolated failed login during business hours (below threshold)",
                    })
                else:
                    summary.classification = "SUSPICIOUS"
                    summary.threat_severity = "MEDIUM"
            else:
                summary.classification = "BENIGN"
                summary.threat_severity = "LOW"

            ip_summaries[ip] = summary

        # Aggregate counts
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in anomalies:
            severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

        # Calculate top offending IPs by failed logins or anomalies
        top_offending = sorted(
            [(ip, s.failed_logins) for ip, s in ip_summaries.items() if s.failed_logins > 0],
            key=lambda x: x[1],
            reverse=True,
        )

        return AnalysisResult(
            total_logs_analyzed=len(entries),
            auth_logs_count=auth_count,
            web_logs_count=web_count,
            ip_summaries=ip_summaries,
            anomalies=anomalies,
            routine_errors=routine_errors,
            malicious_attacks=malicious_attacks,
            severity_counts=severity_counts,
            top_offending_ips=top_offending,
            start_time=min_ts,
            end_time=max_ts,
        )
