"""
Tests for DetectionEngine.
Verifies the 7 required SOC intrusion detection rules against synthetic log datasets.
"""

import pytest
from analyzer.parser import MasterParser
from analyzer.detection import DetectionEngine


@pytest.fixture
def sample_events():
    master = MasterParser(default_year=2026)
    events, _ = master.parse_file("samples/mixed_sample.log")
    return events


def test_failed_login_grouping_and_threshold(sample_events):
    detector = DetectionEngine(failed_low_min=1, failed_med_min=4, failed_high_min=6)
    analysis = detector.analyze(sample_events)

    # 198.51.100.77 has 4 failed logins in mixed_sample.log
    ip_data = analysis["ip_groups"].get("198.51.100.77")
    assert ip_data is not None
    assert ip_data["failed_logins"] >= 4
    assert ip_data["is_suspicious"] is True


def test_successful_login_after_failures(sample_events):
    detector = DetectionEngine()
    analysis = detector.analyze(sample_events)

    # Rule 4: In mixed_sample.log, 198.51.100.77 failed 4 times then logged in successfully as admin!
    incidents = analysis["incidents"]
    breach_incidents = [
        inc for inc in incidents
        if inc.rule_name == "Successful Login Following Repeated Failures"
    ]

    assert len(breach_incidents) >= 1
    inc = breach_incidents[0]
    assert inc.source_ip == "198.51.100.77"
    assert inc.severity == "CRITICAL"
    assert "admin" in inc.description


def test_rapid_burst_detection():
    master = MasterParser(default_year=2026)
    events, _ = master.parse_file("samples/brute_force_sample.log")

    detector = DetectionEngine(burst_count=4, burst_window_seconds=60)
    analysis = detector.analyze(events)

    burst_incidents = [
        inc for inc in analysis["incidents"]
        if inc.rule_name == "Rapid Sequential Login Attempts"
    ]
    assert len(burst_incidents) >= 1
    assert any(inc.source_ip == "203.0.113.88" for inc in burst_incidents)


def test_multiple_usernames_targeted():
    master = MasterParser(default_year=2026)
    events, _ = master.parse_file("samples/brute_force_sample.log")

    detector = DetectionEngine(multiple_users_threshold=3)
    analysis = detector.analyze(events)

    user_enum_incidents = [
        inc for inc in analysis["incidents"]
        if inc.rule_name == "Multiple Usernames Targeted"
    ]
    assert len(user_enum_incidents) >= 1
    assert any(inc.source_ip == "203.0.113.88" for inc in user_enum_incidents)


def test_off_hours_detection():
    master = MasterParser(default_year=2026)
    events, _ = master.parse_file("samples/off_hours_sample.log")

    detector = DetectionEngine(business_start=8, business_end=18)
    analysis = detector.analyze(events)

    off_hours_incidents = [
        inc for inc in analysis["incidents"]
        if inc.rule_name == "Off-Hours Login Activity"
    ]
    assert len(off_hours_incidents) >= 1
    # Check that severity is not CRITICAL solely because of off-hours
    for inc in off_hours_incidents:
        assert inc.severity != "CRITICAL"


def test_web_signatures_and_error_burst():
    master = MasterParser(default_year=2026)
    events, _ = master.parse_file("samples/web_access_sample.log")

    detector = DetectionEngine(http_burst_threshold=5)
    analysis = detector.analyze(events)

    sqli = [inc for inc in analysis["incidents"] if "SQL_INJECTION" in inc.rule_name]
    lfi = [inc for inc in analysis["incidents"] if "PATH_TRAVERSAL" in inc.rule_name]
    http_burst = [inc for inc in analysis["incidents"] if inc.rule_name == "HTTP 401/403 Error Burst"]

    assert len(sqli) >= 1
    assert len(lfi) >= 1
    assert len(http_burst) >= 1
