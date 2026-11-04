"""
Security Anomaly & Intrusion Detection Engine.
Implements the 7 required SOC detection rules, false-positive differentiation,
MITRE ATT&CK correlation, and detailed incident generation.
"""

from collections import defaultdict
from datetime import datetime, time
import re
from typing import Dict, List, Any, Optional
from analyzer.normalizer import LogEvent, Incident
from analyzer.severity import SeverityEngine
from config import Config


class DetectionEngine:
    """Core detection engine implementing multi-vector log anomaly detection with MITRE ATT&CK alignment."""

    # Attack signatures regexes for Rule 7
    URL_ATTACK_PATTERNS = {
        "SQL_INJECTION": {
            "severity": "CRITICAL",
            "pattern": re.compile(
                r"(?i)(union\s+select|select\s+.+\s+from|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|/\*|information_schema|drop\s+table)",
            ),
            "description": "SQL Injection payload detected in request URI or query parameters",
            "recommendation": "Review database query parameterization; check WAF logs; block attacker IP at firewall.",
            "mitre_id": "T1190",
            "mitre_name": "Exploit Public-Facing Application: SQL Injection",
            "mitre_tactic": "Initial Access",
            "kill_chain": "Exploitation"
        },
        "PATH_TRAVERSAL": {
            "severity": "HIGH",
            "pattern": re.compile(
                r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)",
                re.IGNORECASE,
            ),
            "description": "Path / Directory Traversal attempt attempting arbitrary server file retrieval",
            "recommendation": "Verify web server root directory access restrictions; sanitize user-supplied file path parameters.",
            "mitre_id": "T1083",
            "mitre_name": "File and Directory Discovery: Path Traversal",
            "mitre_tactic": "Discovery",
            "kill_chain": "Reconnaissance"
        },
        "COMMAND_INJECTION": {
            "severity": "CRITICAL",
            "pattern": re.compile(
                r"(;|\||`|\$\(|\bexec\b|\bsystem\b).*(cat\s+/etc/passwd|whoami|id|bash|powershell|cmd\.exe|wget\s+|curl\s+)",
                re.IGNORECASE,
            ),
            "description": "Remote Code Execution (RCE) / OS Command Injection payload detected",
            "recommendation": "Isolate affected web application container; check system process tree for unauthorized forks.",
            "mitre_id": "T1059",
            "mitre_name": "Command and Scripting Interpreter",
            "mitre_tactic": "Execution",
            "kill_chain": "Exploitation"
        },
        "XSS_ATTACK": {
            "severity": "MEDIUM",
            "pattern": re.compile(
                r"(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|alert\(|<img\s+src=)",
                re.IGNORECASE,
            ),
            "description": "Cross-Site Scripting (XSS) probe detected in request parameter",
            "recommendation": "Ensure HTML output encoding is enabled across all reflected input parameters.",
            "mitre_id": "T1189",
            "mitre_name": "Drive-by Compromise: Stored / Reflected XSS",
            "mitre_tactic": "Initial Access",
            "kill_chain": "Delivery"
        },
        "SENSITIVE_FILE_PROBING": {
            "severity": "HIGH",
            "pattern": re.compile(
                r"(\.env|\.git|\.aws|\.ssh|wp-config|\.bak|\.old|phpinfo\.php|actuator/)",
                re.IGNORECASE,
            ),
            "description": "Probing for sensitive configuration, credentials, or backup artifacts",
            "recommendation": "Ensure configuration files and version control directories are blocked by web server rewrite rules.",
            "mitre_id": "T1552",
            "mitre_name": "Unsecured Credentials: File Probing",
            "mitre_tactic": "Credential Access",
            "kill_chain": "Reconnaissance"
        },
        "MALICIOUS_SCANNER": {
            "severity": "HIGH",
            "pattern": re.compile(
                r"(sqlmap|nikto|masscan|nmap|acunetix|dirbuster|gobuster|wpscan|hydra)",
                re.IGNORECASE,
            ),
            "description": "Automated security scanner or vulnerability pentest tool user-agent detected",
            "recommendation": "Block scanner IP address; review application endpoints probed during the scan.",
            "mitre_id": "T1595.002",
            "mitre_name": "Active Scanning: Vulnerability Scanning",
            "mitre_tactic": "Reconnaissance",
            "kill_chain": "Reconnaissance"
        }
    }

    def __init__(
        self,
        failed_low_min: int = Config.FAILED_LOGIN_LOW_MIN,
        failed_med_min: int = Config.FAILED_LOGIN_MED_MIN,
        failed_high_min: int = Config.FAILED_LOGIN_HIGH_MIN,
        burst_count: int = Config.BURST_COUNT_THRESHOLD,
        burst_window_seconds: int = Config.BURST_WINDOW_SECONDS,
        multiple_users_threshold: int = Config.MULTIPLE_USERNAMES_THRESHOLD,
        http_burst_threshold: int = Config.HTTP_ERROR_BURST_THRESHOLD,
        business_start: int = Config.BUSINESS_HOURS_START,
        business_end: int = Config.BUSINESS_HOURS_END,
    ):
        self.failed_low_min = failed_low_min
        self.failed_med_min = failed_med_min
        self.failed_high_min = failed_high_min
        self.burst_count = burst_count
        self.burst_window_seconds = burst_window_seconds
        self.multiple_users_threshold = multiple_users_threshold
        self.http_burst_threshold = http_burst_threshold
        self.biz_start = time(business_start, 0, 0)
        self.biz_end = time(business_end, 0, 0)

    def is_off_hours(self, dt: datetime) -> bool:
        """Determines if a timestamp falls outside regular business hours (Mon-Fri 08:00-18:00)."""
        if dt.weekday() >= 5:  # Saturday or Sunday
            return True
        return not (self.biz_start <= dt.time() <= self.biz_end)

    def analyze(self, events: List[LogEvent]) -> Dict[str, Any]:
        """
        Analyzes normalized log events against all detection rules.
        Returns a dictionary of analysis metrics, grouped statistics, and incidents.
        """
        if not events:
            return {
                "total_events": 0,
                "successful_logins": 0,
                "failed_logins": 0,
                "suspicious_ip_count": 0,
                "detected_anomalies_count": 0,
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "incidents": [],
                "ip_groups": {},
                "top_suspicious_ips": [],
                "routine_errors": [],
                "hourly_activity": {},
                "mitre_matrix": {},
            }

        events_by_ip = defaultdict(list)
        successful_logins = 0
        failed_logins = 0
        hourly_activity = defaultdict(lambda: {"total": 0, "failed": 0, "success": 0})

        for event in events:
            hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
            hourly_activity[hour_key]["total"] += 1

            if event.event_type == "LOGIN_SUCCESS":
                successful_logins += 1
                hourly_activity[hour_key]["success"] += 1
            elif event.event_type == "LOGIN_FAILED":
                failed_logins += 1
                hourly_activity[hour_key]["failed"] += 1

            events_by_ip[event.source_ip].append(event)

        incidents: List[Incident] = []
        ip_groups: Dict[str, Dict[str, Any]] = {}
        routine_errors: List[Dict[str, Any]] = []

        incident_counter = 1

        for ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda x: x.timestamp)

            ip_failed_events = [e for e in ip_events if e.event_type == "LOGIN_FAILED"]
            ip_success_events = [e for e in ip_events if e.event_type == "LOGIN_SUCCESS"]
            unique_users = sorted(list({e.username for e in ip_events if e.username}))

            first_seen = ip_events[0].timestamp
            last_seen = ip_events[-1].timestamp

            # Tally metrics for this IP
            ip_summary = {
                "ip": ip,
                "total_events": len(ip_events),
                "failed_logins": len(ip_failed_events),
                "successful_logins": len(ip_success_events),
                "unique_users": unique_users,
                "unique_user_count": len(unique_users),
                "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "is_suspicious": False,
                "highest_severity": "LOW",
                "rules_triggered": [],
                "classification": "BENIGN",
            }

            # -------------------------------------------------------------
            # Rule 1: Repeated Failed Authentication Attempts
            # -------------------------------------------------------------
            fail_count = len(ip_failed_events)
            if fail_count >= self.failed_low_min:
                severity, reason = SeverityEngine.evaluate_failed_logins(fail_count)
                
                # Check if it's a routine typo vs attack:
                is_routine = (
                    fail_count < self.failed_med_min
                    and len(ip_success_events) > 0
                    and not any(self.is_off_hours(e.timestamp) for e in ip_failed_events)
                    and not any(e.is_invalid_user for e in ip_failed_events)
                )

                if is_routine:
                    ip_summary["classification"] = "ROUTINE_ERROR"
                    routine_errors.append({
                        "ip": ip,
                        "user": unique_users[0] if unique_users else "unknown",
                        "failed_count": fail_count,
                        "reason": "Occasional password typo during business hours, resolved with successful login."
                    })
                else:
                    ip_summary["is_suspicious"] = True
                    ip_summary["classification"] = "SUSPICIOUS_BRUTE_FORCE"
                    ip_summary["rules_triggered"].append("Repeated Failed Authentication")
                    incidents.append(
                        Incident(
                            id=f"INC-{incident_counter:04d}",
                            rule_name="Repeated Failed Authentication",
                            description=f"Source IP generated {fail_count} failed login attempts targeting: {', '.join(unique_users[:3]) or 'unknown'}",
                            source_ip=ip,
                            timestamp=ip_failed_events[-1].timestamp,
                            severity=severity,
                            reason=reason,
                            recommended_steps=[
                                "Investigate if targeted account is an active enterprise user.",
                                "Verify whether host belongs to corporate IP space or external ISP.",
                                "If failures continue, apply perimeter firewall block."
                            ],
                            mitre_id="T1110.001",
                            mitre_name="Brute Force: Password Guessing",
                            mitre_tactic="Credential Access",
                            kill_chain_phase="Exploitation",
                            related_events=[e.id for e in ip_failed_events],
                            metadata={"failed_count": fail_count, "users": unique_users}
                        )
                    )
                    incident_counter += 1

            # -------------------------------------------------------------
            # Rule 2: Rapid Sequential Login Attempts (Burst Attacks)
            # -------------------------------------------------------------
            if len(ip_failed_events) >= self.burst_count:
                for i in range(len(ip_failed_events) - self.burst_count + 1):
                    t_start = ip_failed_events[i].timestamp
                    t_end = ip_failed_events[i + self.burst_count - 1].timestamp
                    delta_sec = (t_end - t_start).total_seconds()

                    if delta_sec <= self.burst_window_seconds:
                        burst_sev, burst_reason = SeverityEngine.evaluate_burst(self.burst_count, int(delta_sec))
                        ip_summary["is_suspicious"] = True
                        ip_summary["classification"] = "BURST_ATTACKER"
                        ip_summary["rules_triggered"].append("Rapid Sequential Login Attempts")
                        incidents.append(
                            Incident(
                                id=f"INC-{incident_counter:04d}",
                                rule_name="Rapid Sequential Login Attempts",
                                description=(
                                    f"Detected high-velocity brute-force burst: {self.burst_count} failed attempts "
                                    f"in {int(delta_sec)} seconds from {ip}."
                                ),
                                source_ip=ip,
                                timestamp=t_start,
                                severity=burst_sev,
                                reason=burst_reason,
                                recommended_steps=[
                                    "Inspect authentication service rate limiting configuration.",
                                    "Trigger temporary rate-limiting / CAPTCHA on login endpoint.",
                                    "Check for automated botnet tool signatures in traffic."
                                ],
                                mitre_id="T1110.003",
                                mitre_name="Brute Force: Password Spraying",
                                mitre_tactic="Credential Access",
                                kill_chain_phase="Exploitation",
                                related_events=[e.id for e in ip_failed_events[i:i + self.burst_count]],
                                metadata={"duration_seconds": delta_sec, "attempts": self.burst_count}
                            )
                        )
                        incident_counter += 1
                        break  # Report once per IP

            # -------------------------------------------------------------
            # Rule 3: Multiple Usernames Targeted from Same IP (Credential Stuffing)
            # -------------------------------------------------------------
            if len(unique_users) >= self.multiple_users_threshold and fail_count >= 3:
                ip_summary["is_suspicious"] = True
                ip_summary["classification"] = "CREDENTIAL_STUFFER"
                ip_summary["rules_triggered"].append("Multiple Usernames Targeted")
                incidents.append(
                    Incident(
                        id=f"INC-{incident_counter:04d}",
                        rule_name="Multiple Usernames Targeted",
                        description=f"Single source IP attempted authentication against {len(unique_users)} distinct usernames: {', '.join(unique_users[:5])}",
                        source_ip=ip,
                        timestamp=ip_failed_events[-1].timestamp if ip_failed_events else ip_events[-1].timestamp,
                        severity="HIGH",
                        reason=f"Credential stuffing / user enumeration pattern: {len(unique_users)} targeted accounts exceeding threshold ({self.multiple_users_threshold}).",
                        recommended_steps=[
                            "Check if targeted usernames match known public leak databases.",
                            "Notify targeted account owners to verify credential hygiene.",
                            "Enforce multi-factor authentication (MFA) across all targeted accounts."
                        ],
                        mitre_id="T1110.004",
                        mitre_name="Brute Force: Credential Stuffing",
                        mitre_tactic="Credential Access",
                        kill_chain_phase="Exploitation",
                        related_events=[e.id for e in ip_failed_events],
                        metadata={"unique_user_count": len(unique_users), "usernames": unique_users}
                    )
                )
                incident_counter += 1

            # -------------------------------------------------------------
            # Rule 4: Successful Login Following Repeated Failed Attempts
            # -------------------------------------------------------------
            if ip_success_events and fail_count >= 3:
                first_success = ip_success_events[0]
                prior_failures = [e for e in ip_failed_events if e.timestamp < first_success.timestamp]
                if len(prior_failures) >= 3:
                    sev, reason = SeverityEngine.evaluate_successful_login_after_failures(
                        len(prior_failures), first_success.username or "unknown"
                    )
                    ip_summary["is_suspicious"] = True
                    ip_summary["classification"] = "ACCOUNT_TAKEOVER_ALERT"
                    ip_summary["rules_triggered"].append("Successful Login Following Repeated Failures")
                    incidents.append(
                        Incident(
                            id=f"INC-{incident_counter:04d}",
                            rule_name="Successful Login Following Repeated Failures",
                            description=(
                                f"CRITICAL: User '{first_success.username}' logged in successfully AFTER "
                                f"{len(prior_failures)} consecutive failed attempts from IP {ip}."
                            ),
                            source_ip=ip,
                            timestamp=first_success.timestamp,
                            severity=sev,
                            reason=reason,
                            recommended_steps=[
                                "IMMEDIATE: Contact user out-of-band to verify if login was legitimate.",
                                "Terminate active SSH/web session for user if unconfirmed.",
                                "Rotate user credentials and inspect audit logs for lateral movement."
                            ],
                            mitre_id="T1078",
                            mitre_name="Valid Accounts: Account Takeover",
                            mitre_tactic="Defense Evasion",
                            kill_chain_phase="Actions on Objectives",
                            related_events=[e.id for e in prior_failures] + [first_success.id],
                            metadata={"prior_failures": len(prior_failures), "user": first_success.username}
                        )
                    )
                    incident_counter += 1

            # -------------------------------------------------------------
            # Rule 5: Off-Hours Login Activity
            # -------------------------------------------------------------
            off_hours_events = [e for e in ip_events if self.is_off_hours(e.timestamp) and e.event_type in ("LOGIN_SUCCESS", "LOGIN_FAILED")]
            if off_hours_events:
                off_users = list({e.username for e in off_hours_events if e.username})
                off_user_str = ", ".join(off_users) if off_users else "unknown"
                sev, reason = SeverityEngine.evaluate_off_hours(len(off_hours_events), off_user_str)
                
                # Per Section 3.F: Do NOT classify an event as CRITICAL solely because of off-hours login
                if sev == "CRITICAL":
                    sev = "HIGH"

                has_admin = any(u in ("root", "admin", "administrator") for u in off_users)
                if len(off_hours_events) >= 2 or has_admin:
                    ip_summary["is_suspicious"] = True
                    ip_summary["rules_triggered"].append("Off-Hours Login Activity")
                    incidents.append(
                        Incident(
                            id=f"INC-{incident_counter:04d}",
                            rule_name="Off-Hours Login Activity",
                            description=f"Authentication activity detected outside standard business hours ({off_hours_events[0].timestamp.strftime('%H:%M:%S')}) for user(s): {off_user_str}.",
                            source_ip=ip,
                            timestamp=off_hours_events[0].timestamp,
                            severity=sev,
                            reason=reason,
                            recommended_steps=[
                                "Cross-reference with employee shift schedules and maintenance windows.",
                                "Verify source IP against known corporate VPN egress ranges."
                            ],
                            mitre_id="T1078.003",
                            mitre_name="Valid Accounts: Local Accounts (Abnormal Time)",
                            mitre_tactic="Initial Access",
                            kill_chain_phase="Initial Access",
                            related_events=[e.id for e in off_hours_events],
                            metadata={"off_hours_count": len(off_hours_events), "users": off_users}
                        )
                    )
                    incident_counter += 1

            # -------------------------------------------------------------
            # Rule 6: HTTP 401 and 403 Bursts
            # -------------------------------------------------------------
            http_errors = [e for e in ip_events if e.http_status in (401, 403)]
            if len(http_errors) >= self.http_burst_threshold:
                ip_summary["is_suspicious"] = True
                ip_summary["classification"] = "WEB_PROBER"
                ip_summary["rules_triggered"].append("HTTP 401/403 Error Burst")
                incidents.append(
                    Incident(
                        id=f"INC-{incident_counter:04d}",
                        rule_name="HTTP 401/403 Error Burst",
                        description=f"High frequency of HTTP 401/403 responses ({len(http_errors)} errors) detected from IP {ip}.",
                        source_ip=ip,
                        timestamp=http_errors[-1].timestamp,
                        severity="MEDIUM",
                        reason=f"Exceeded threshold of unauthorized/forbidden responses ({len(http_errors)} >= {self.http_burst_threshold}) indicating automated scanning.",
                        recommended_steps=[
                            "Review target URI paths in web server access log.",
                            "Check for unauthorized web directory brute force or API abuse."
                        ],
                        mitre_id="T1595.002",
                        mitre_name="Active Scanning: Vulnerability Scanning",
                        mitre_tactic="Reconnaissance",
                        kill_chain_phase="Reconnaissance",
                        related_events=[e.id for e in http_errors],
                        metadata={"http_error_count": len(http_errors)}
                    )
                )
                incident_counter += 1

            # -------------------------------------------------------------
            # Rule 7: Suspicious URL Patterns & Known Attack Signatures
            # -------------------------------------------------------------
            for e in ip_events:
                if e.log_type == "WEB":
                    target_payload = f"{e.url or ''} {e.user_agent or ''} {e.message}"
                    for sig_key, sig_data in self.URL_ATTACK_PATTERNS.items():
                        if sig_data["pattern"].search(target_payload):
                            ip_summary["is_suspicious"] = True
                            ip_summary["classification"] = "ACTIVE_EXPLOITER"
                            rule_tag = f"Attack Signature: {sig_key}"
                            if rule_tag not in ip_summary["rules_triggered"]:
                                ip_summary["rules_triggered"].append(rule_tag)

                            incidents.append(
                                Incident(
                                    id=f"INC-{incident_counter:04d}",
                                    rule_name=f"Suspicious URL Pattern ({sig_key})",
                                    description=f"{sig_data['description']} in request: '{e.http_method or 'GET'} {e.url or '/'}'",
                                    source_ip=ip,
                                    timestamp=e.timestamp,
                                    severity=sig_data["severity"],
                                    reason=f"Signature match for pattern {sig_key}. Payload attempted: {e.url or e.user_agent}",
                                    recommended_steps=[
                                        sig_data["recommendation"],
                                        f"Check HTTP response status ({e.http_status}) to ensure payload was blocked."
                                    ],
                                    mitre_id=sig_data["mitre_id"],
                                    mitre_name=sig_data["mitre_name"],
                                    mitre_tactic=sig_data["mitre_tactic"],
                                    kill_chain_phase=sig_data["kill_chain"],
                                    related_events=[e.id],
                                    metadata={"signature": sig_key, "url": e.url, "method": e.http_method, "status": e.http_status}
                                )
                            )
                            incident_counter += 1

            # Determine highest severity for this IP
            triggered_severities = [
                inc.severity for inc in incidents if inc.source_ip == ip
            ]
            for s_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if s_level in triggered_severities:
                    ip_summary["highest_severity"] = s_level
                    break

            ip_groups[ip] = ip_summary

        # Aggregate incident severity breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        mitre_matrix = defaultdict(int)

        for inc in incidents:
            severity_counts[inc.severity] = severity_counts.get(inc.severity, 0) + 1
            mitre_key = f"{inc.mitre_id} ({inc.mitre_name})"
            mitre_matrix[mitre_key] += 1

        suspicious_ips = [ip for ip, data in ip_groups.items() if data["is_suspicious"]]

        # Top suspicious IPs ranked by severity then failed count
        top_suspicious = sorted(
            [data for data in ip_groups.values() if data["is_suspicious"]],
            key=lambda x: (
                {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["highest_severity"], 0),
                x["failed_logins"]
            ),
            reverse=True
        )

        return {
            "total_events": len(events),
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "suspicious_ip_count": len(suspicious_ips),
            "detected_anomalies_count": len(incidents),
            "severity_counts": severity_counts,
            "incidents": incidents,
            "ip_groups": ip_groups,
            "top_suspicious_ips": top_suspicious,
            "routine_errors": routine_errors,
            "hourly_activity": dict(hourly_activity),
            "mitre_matrix": dict(mitre_matrix),
        }
