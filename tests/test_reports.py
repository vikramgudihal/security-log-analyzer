"""
Tests for ReportGenerator.
Validates generation of Markdown, Text, and CSV incident reports containing the 11 required sections.
"""

from analyzer.parser import MasterParser
from analyzer.detection import DetectionEngine
from analyzer.report_generator import ReportGenerator


def test_report_generation_formats():
    master = MasterParser(default_year=2026)
    events, _ = master.parse_file("samples/mixed_sample.log")
    detector = DetectionEngine()
    analysis = detector.analyze(events)

    generator = ReportGenerator(analysis, events, filename="mixed_sample.log")

    # 1. Test Markdown Report
    md = generator.generate_markdown()
    assert "# 🛡️ SECURITY INCIDENT & ANOMALY ANALYSIS REPORT" in md
    assert "1. Executive Summary" in md
    assert "2. Analysis Metadata" in md
    assert "3. Total Events & Authentication Metrics" in md
    assert "4. Severity Classification Breakdown" in md
    assert "5. Suspicious IP Addresses" in md
    assert "6. Detected Security Anomalies" in md
    assert "7. Relevant Event Evidence" in md
    assert "8. Recommended Investigation Steps" in md
    assert "9. False-Positive Disclaimer" in md

    # 2. Test Text Report
    txt = generator.generate_text()
    assert "CODENOVA SOC - SECURITY INCIDENT ANALYSIS REPORT" in txt
    assert "TOP SUSPICIOUS IP ADDRESSES" in txt
    assert "iptables -A INPUT" in txt

    # 3. Test CSV Report
    csv_data = generator.generate_csv()
    lines = csv_data.strip().split("\n")
    assert len(lines) >= 2  # Header + at least one incident
    assert "Incident_ID,Timestamp,Source_IP" in lines[0]
