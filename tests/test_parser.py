"""
Tests for MasterParser, AuthParser, and WebParser.
Verifies parsing of Linux auth.log, Apache/Nginx web access logs, and malformed inputs.
"""

import pytest
from analyzer.parser import MasterParser
from analyzer.auth_parser import AuthParser
from analyzer.web_parser import WebParser


def test_auth_parser_valid_failed_login():
    parser = AuthParser(default_year=2026, timezone="UTC")
    line = "Oct 21 14:02:01 server sshd[2201]: Failed password for root from 203.0.113.88 port 39101 ssh2"
    event = parser.parse_line(line, line_id=1)

    assert event is not None
    assert event.source_ip == "203.0.113.88"
    assert event.username == "root"
    assert event.event_type == "LOGIN_FAILED"
    assert event.auth_status == "FAILURE"
    assert event.is_invalid_user is False
    assert event.port == 39101


def test_auth_parser_invalid_user():
    parser = AuthParser(default_year=2026, timezone="UTC")
    line = "Oct 21 14:02:07 server sshd[2204]: Failed password for invalid user oracle from 203.0.113.88 port 39104 ssh2"
    event = parser.parse_line(line, line_id=2)

    assert event is not None
    assert event.username == "oracle"
    assert event.is_invalid_user is True
    assert event.source_ip == "203.0.113.88"


def test_auth_parser_accepted_login():
    parser = AuthParser(default_year=2026, timezone="UTC")
    line = "Oct 21 08:30:15 server sshd[1023]: Accepted publickey for alice from 192.168.1.10 port 54322 ssh2: RSA SHA256:abc123legit"
    event = parser.parse_line(line, line_id=3)

    assert event is not None
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.10"
    assert event.event_type == "LOGIN_SUCCESS"
    assert event.auth_status == "SUCCESS"


def test_web_parser_combined_format():
    parser = WebParser(timezone="UTC")
    line = '198.51.100.44 - - [21/Oct/2026:11:40:12 +0000] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 5600 "-" "sqlmap/1.6#stable"'
    event = parser.parse_line(line, line_id=4)

    assert event is not None
    assert event.source_ip == "198.51.100.44"
    assert event.http_method == "GET"
    assert event.http_status == 200
    assert "UNION SELECT" in event.url
    assert event.user_agent == "sqlmap/1.6#stable"


def test_master_parser_with_malformed_lines():
    master = MasterParser(default_year=2026)
    content = """
    Oct 21 09:15:02 server sshd[1050]: Failed password for bob from 192.168.1.45 port 51230 ssh2
    RANDOM_GARBAGE_LINE_THAT_CANNOT_BE_PARSED_AT_ALL_$$$
    192.168.1.10 - - [21/Oct/2026:08:30:20 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "-"
    """
    events, stats = master.parse_content(content)

    assert len(events) == 2
    assert stats.parsed_events == 2
    assert stats.failed_lines >= 1
    assert len(stats.parse_errors) >= 1
