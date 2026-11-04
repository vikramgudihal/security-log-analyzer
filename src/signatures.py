"""
Attack signatures and regex definitions for cybersecurity log analysis.
Identifies SQLi, Path Traversal, XSS, RCE, sensitive file access, and credential stuffing.
"""

import re
from typing import Dict, List, Pattern

# Web attack signatures for query strings, URLs, and payloads
WEB_ATTACK_SIGNATURES: Dict[str, Dict[str, any]] = {
    "SQL_INJECTION": {
        "severity": "CRITICAL",
        "description": "SQL Injection attempt detected (UNION SELECT, tautology, comment injection)",
        "pattern": re.compile(
            r"(?i)(union\s+select|select\s+.+\s+from|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|/\*|information_schema|drop\s+table|insert\s+into|benchmark\s*\(|sleep\s*\()",
        ),
    },
    "PATH_TRAVERSAL": {
        "severity": "HIGH",
        "description": "Path/Directory Traversal attempt attempting arbitrary file retrieval",
        "pattern": re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)",
            re.IGNORECASE,
        ),
    },
    "COMMAND_INJECTION": {
        "severity": "CRITICAL",
        "description": "OS Command Injection / Remote Code Execution attempt",
        "pattern": re.compile(
            r"(;|\||`|\$\(|\bexec\b|\bsystem\b|\bpassthru\b).*(cat\s+/etc/passwd|whoami|id|bash|powershell|cmd\.exe|wget\s+|curl\s+)",
            re.IGNORECASE,
        ),
    },
    "XSS_ATTACK": {
        "severity": "MEDIUM",
        "description": "Cross-Site Scripting (XSS) probe detected in request parameter",
        "pattern": re.compile(
            r"(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|alert\(|<img\s+src=)",
            re.IGNORECASE,
        ),
    },
    "SENSITIVE_FILE_PROBING": {
        "severity": "HIGH",
        "description": "Probing for sensitive configuration files, VCS directories, or backups",
        "pattern": re.compile(
            r"(\.env|\.git|\.aws|\.ssh|wp-config|\.bak|\.old|phpinfo\.php|actuator/|web\.config)",
            re.IGNORECASE,
        ),
    },
    "MALICIOUS_SCANNER": {
        "severity": "HIGH",
        "description": "Automated vulnerability scanner or pentest tool user agent",
        "pattern": re.compile(
            r"(sqlmap|nikto|nmap|masscan|zgrab|acunetix|dirbuster|gobuster|wpscan|hydra)",
            re.IGNORECASE,
        ),
    },
}

# Targeted high-value accounts in authentication logs
HIGH_VALUE_TARGET_USERS = {
    "root", "admin", "administrator", "postgres", "mysql", "oracle",
    "backup", "deploy", "guest", "test", "service_account", "ftpuser"
}

