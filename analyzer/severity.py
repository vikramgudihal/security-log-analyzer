"""
Incident Severity Classification Engine.
Assigns LOW, MEDIUM, HIGH, or CRITICAL severity with transparent technical justifications.
Ensures correlated events are not double-counted and adheres to SOC standards.
"""

from typing import Tuple


class SeverityEngine:
    """Evaluates threat vectors and assigns appropriate SOC severity levels."""

    SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # Severity color codes and badges for UI rendering
    SEVERITY_CONFIG = {
        "LOW": {
            "badge_class": "badge-low",
            "color": "#16a34a",
            "description": "Routine or informational activity with low risk of compromise."
        },
        "MEDIUM": {
            "badge_class": "badge-medium",
            "color": "#ea580c",
            "description": "Suspicious behavior requiring investigation but no immediate compromise indicated."
        },
        "HIGH": {
            "badge_class": "badge-high",
            "color": "#dc2626",
            "description": "Active attack pattern or threshold breach exhibiting malicious intent."
        },
        "CRITICAL": {
            "badge_class": "badge-critical",
            "color": "#7f1d1d",
            "description": "High-confidence intrusion, exploit payload, or successful authentication following brute-force."
        }
    }

    @classmethod
    def evaluate_failed_logins(cls, count: int) -> Tuple[str, str]:
        """
        Classifies failed login counts per IP:
        1-3: LOW
        4-5: MEDIUM
        6+: HIGH
        15+: CRITICAL
        """
        if count >= 15:
            return "CRITICAL", f"Severe brute-force volume ({count} failed attempts) indicating automated credential stuffing."
        elif count >= 6:
            return "HIGH", f"High failed login volume ({count} attempts) breaching security threshold (>= 6)."
        elif count >= 4:
            return "MEDIUM", f"Repeated failed logins ({count} attempts) exceeding normal typo threshold (>= 4)."
        elif count >= 1:
            return "LOW", f"Isolated failed login attempts ({count} attempt) consistent with routine user typos."
        return "LOW", "No failures observed."

    @classmethod
    def evaluate_burst(cls, count: int, window_sec: int) -> Tuple[str, str]:
        """Rapid sequential attempts within time window."""
        if count >= 8:
            return "CRITICAL", f"High-velocity brute-force burst ({count} attempts within {window_sec}s)."
        return "HIGH", f"Rapid sequential login burst detected ({count} attempts in <= {window_sec}s)."

    @classmethod
    def evaluate_successful_login_after_failures(cls, fail_count: int, user: str) -> Tuple[str, str]:
        """Critical alert: Successful login following brute-force attempts from same IP."""
        return "CRITICAL", (
            f"POTENTIAL COMPROMISE: Successful authentication for '{user}' immediately following "
            f"{fail_count} failed login attempts from the same IP address."
        )

    @classmethod
    def evaluate_off_hours(cls, count: int, user: str) -> Tuple[str, str]:
        """
        Off-hours activity evaluation.
        Per Section 3.F: Do NOT classify an event as CRITICAL solely because of off-hours login.
        """
        if count >= 4:
            return "HIGH", f"Elevated off-hours authentication activity ({count} events for user '{user}')."
        return "MEDIUM", f"Off-hours authentication event detected for user '{user}' outside configured business hours."

    @classmethod
    def evaluate_attack_signature(cls, sig_type: str, details: str) -> Tuple[str, str]:
        """Evaluates web attack payloads (SQLi, Traversal, XSS, Scanners)."""
        if sig_type in ("SQL_INJECTION", "COMMAND_INJECTION"):
            return "CRITICAL", f"Exploitation attempt: {sig_type} pattern detected ({details})."
        elif sig_type in ("PATH_TRAVERSAL", "MALICIOUS_SCANNER"):
            return "HIGH", f"Reconnaissance / LFI attempt: {sig_type} detected ({details})."
        elif sig_type == "XSS_ATTACK":
            return "MEDIUM", f"Cross-site scripting payload probe detected ({details})."
        return "MEDIUM", f"Suspicious signature matched: {sig_type} ({details})."
