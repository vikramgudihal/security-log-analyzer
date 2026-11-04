"""
Tests for SeverityEngine.
Validates 4-tier SOC classification, threshold scaling, and rule compliance.
"""

from analyzer.severity import SeverityEngine


def test_failed_login_severity_scaling():
    # 1 failure -> LOW
    sev_low, reason_low = SeverityEngine.evaluate_failed_logins(1)
    assert sev_low == "LOW"

    # 4 failures -> MEDIUM
    sev_med, reason_med = SeverityEngine.evaluate_failed_logins(4)
    assert sev_med == "MEDIUM"

    # 7 failures -> HIGH
    sev_high, reason_high = SeverityEngine.evaluate_failed_logins(7)
    assert sev_high == "HIGH"

    # 20 failures -> CRITICAL
    sev_crit, reason_crit = SeverityEngine.evaluate_failed_logins(20)
    assert sev_crit == "CRITICAL"


def test_off_hours_never_critical_alone():
    # Per section 3.F: Do not classify an event as CRITICAL solely because of an off-hours login
    sev_single, _ = SeverityEngine.evaluate_off_hours(1, "alice")
    assert sev_single == "MEDIUM"

    sev_multiple, _ = SeverityEngine.evaluate_off_hours(10, "bob")
    assert sev_multiple in ("HIGH", "MEDIUM")
    assert sev_multiple != "CRITICAL"


def test_attack_signature_severity():
    sev_sqli, _ = SeverityEngine.evaluate_attack_signature("SQL_INJECTION", "UNION SELECT")
    assert sev_sqli == "CRITICAL"

    sev_rce, _ = SeverityEngine.evaluate_attack_signature("COMMAND_INJECTION", "; whoami")
    assert sev_rce == "CRITICAL"

    sev_lfi, _ = SeverityEngine.evaluate_attack_signature("PATH_TRAVERSAL", "../etc/passwd")
    assert sev_lfi == "HIGH"
