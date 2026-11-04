"""
Unit & Integration Test Suite for Security Log Analyzer.
Verifies parsing accuracy, anomaly detection, threshold violations, and report generation.
"""

import unittest
from datetime import datetime
from src.parsers import LogParser, LogEntry
from src.analyzer import SecurityLogAnalyzer
from src.reporter import SecurityReportGenerator


class TestSecurityLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.parser = LogParser(default_year=2026)
        self.analyzer = SecurityLogAnalyzer(
            failed_login_threshold=5,
            burst_threshold=4,
            burst_window_seconds=60,
            business_start_hour=8,
            business_end_hour=18,
        )

    def test_auth_log_parsing(self):
        entries = self.parser.parse_file("logs/auth.log")
        self.assertGreater(len(entries), 30)
        failed_count = sum(1 for e in entries if e.event_type == "LOGIN_FAILED")
        success_count = sum(1 for e in entries if e.event_type == "LOGIN_SUCCESS")
        self.assertGreater(failed_count, 20)
        self.assertGreater(success_count, 3)

    def test_web_log_parsing(self):
        entries = self.parser.parse_file("logs/nginx_access.log")
        self.assertGreater(len(entries), 25)
        methods = {e.method for e in entries}
        self.assertTrue("GET" in methods)
        self.assertTrue("POST" in methods)

    def test_failed_login_threshold(self):
        entries = self.parser.parse_file("logs/auth.log")
        result = self.analyzer.analyze(entries)
        # Attacker 203.0.113.88 has 15 failed logins (threshold=5)
        attacker = result.ip_summaries.get("203.0.113.88")
        self.assertIsNotNone(attacker)
        self.assertGreaterEqual(attacker.failed_logins, 5)
        self.assertEqual(attacker.threat_severity, "CRITICAL")
        self.assertIn(attacker.classification, ["BRUTE_FORCE_ATTACK", "EXPLOIT_SCANNER"])

    def test_rapid_burst_detection(self):
        entries = self.parser.parse_file("logs/auth.log")
        result = self.analyzer.analyze(entries)
        burst_anomalies = [a for a in result.anomalies if a.anomaly_type == "BRUTE_FORCE_BURST"]
        self.assertGreaterEqual(len(burst_anomalies), 1)
        self.assertTrue(any(a.ip == "203.0.113.88" for a in burst_anomalies))

    def test_routine_error_vs_malicious_differentiation(self):
        entries = self.parser.parse_file("logs/auth.log")
        result = self.analyzer.analyze(entries)
        # Routine error: 192.168.1.45 (bob - 1 failed attempt during work hours followed by success)
        routine_ips = [r["ip"] for r in result.routine_errors]
        self.assertIn("192.168.1.45", routine_ips)

        # Malicious: 203.0.113.88 and 185.220.101.5
        malicious_ips = [m["ip"] for m in result.malicious_attacks]
        self.assertIn("203.0.113.88", malicious_ips)
        self.assertIn("185.220.101.5", malicious_ips)

    def test_web_attack_signatures(self):
        entries = self.parser.parse_file("logs/nginx_access.log")
        result = self.analyzer.analyze(entries)
        sqli_anomalies = [a for a in result.anomalies if "SQL Injection" in a.description]
        lfi_anomalies = [a for a in result.anomalies if "Path/Directory Traversal" in a.description]
        self.assertGreaterEqual(len(sqli_anomalies), 1)
        self.assertGreaterEqual(len(lfi_anomalies), 1)

    def test_report_generation(self):
        entries = self.parser.parse_file("logs/auth.log")
        result = self.analyzer.analyze(entries)
        reporter = SecurityReportGenerator(result, log_filename="logs/auth.log")
        md = reporter.generate_markdown()
        txt = reporter.generate_text()

        self.assertIn("# 🛡️ SECURITY INCIDENT & ANOMALY DETECTION REPORT", md)
        self.assertIn("BRUTE_FORCE_ATTACK", md)
        self.assertIn("iptables -A INPUT", md)
        self.assertIn("CYBER SECURITY INCIDENT & ANOMALY REPORT", txt)


if __name__ == "__main__":
    unittest.main()

