"""
Security Incident Report Generator using Tabulate and Markdown.
Outputs structured, executive-ready incident reports in both Markdown (.md) and ASCII Grid (.txt).
"""

from datetime import datetime
from tabulate import tabulate
from src.analyzer import AnalysisResult


class SecurityReportGenerator:
    """Generates structured Security Incident Reports in Markdown and ASCII Grid text formats."""

    def __init__(self, result: AnalysisResult, log_filename: str = "server.log"):
        self.result = result
        self.log_filename = log_filename

    def _determine_overall_risk(self) -> str:
        if self.result.severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL (Immediate Action Required)"
        if self.result.severity_counts.get("HIGH", 0) > 0:
            return "HIGH (Elevated Threat Detected)"
        if self.result.severity_counts.get("MEDIUM", 0) > 0:
            return "MEDIUM (Suspicious Behavior Observed)"
        return "LOW (Nominal Operations)"

    def generate_markdown(self) -> str:
        """Generates a complete, publication-ready GitHub-flavored Markdown Security Incident Report."""
        res = self.result
        overall_risk = self._determine_overall_risk()

        # 1. IP Summary Table
        ip_rows = []
        for ip, s in sorted(res.ip_summaries.items(), key=lambda x: x[1].failed_logins, reverse=True):
            users_str = ", ".join(s.targeted_users[:3]) + ("..." if len(s.targeted_users) > 3 else "")
            violated = "YES 🚨" if s.failed_logins >= 5 else "NO"
            ip_rows.append([
                ip,
                s.total_events,
                s.failed_logins,
                s.successful_logins,
                users_str or "N/A",
                s.classification,
                s.threat_severity,
                violated
            ])

        ip_headers = ["Source IP", "Total Events", "Failed Logins", "Successes", "Targeted Users", "Classification", "Severity", "Threshold Breached"]
        ip_table_md = tabulate(ip_rows, headers=ip_headers, tablefmt="github") if ip_rows else "_No IP activity recorded._"

        # 2. Anomalies Table
        anomaly_rows = []
        for a in res.anomalies[:25]:  # Top 25 for report readability
            sev_badge = f"**{a.severity}**"
            ts_str = a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            anomaly_rows.append([
                ts_str,
                a.ip,
                a.anomaly_type,
                sev_badge,
                a.description
            ])

        anomaly_headers = ["Timestamp", "Source IP", "Anomaly Vector", "Severity", "Technical Description"]
        anomalies_table_md = tabulate(anomaly_rows, headers=anomaly_headers, tablefmt="github") if anomaly_rows else "_No anomalies detected._"

        # 3. Routine Errors vs Malicious Comparison Table
        routine_rows = []
        for r in res.routine_errors:
            routine_rows.append([
                r["ip"],
                r["user"],
                r["failed_count"],
                "Yes (Logged in afterwards)" if r["resolved"] else "No (Isolated typo)",
                r["context"]
            ])
        routine_headers = ["IP Address", "User", "Failed Count", "Resolved", "Context / Root Cause"]
        routine_table_md = tabulate(routine_rows, headers=routine_headers, tablefmt="github") if routine_rows else "_No routine login errors detected._"

        malicious_rows = []
        for m in res.malicious_attacks:
            malicious_rows.append([
                m["ip"],
                m["type"],
                m["events"],
                f"**{m['severity']}**",
                m["reason"]
            ])
        malicious_headers = ["Offending IP", "Attack Category", "Total Requests", "Severity", "Indicators of Compromise (IoC)"]
        malicious_table_md = tabulate(malicious_rows, headers=malicious_headers, tablefmt="github") if malicious_rows else "_No malicious attacks detected._"

        # 4. Generate Firewall Rules recommendations
        firewall_commands = []
        for ip, s in res.ip_summaries.items():
            if s.threat_severity in ("HIGH", "CRITICAL"):
                firewall_commands.append(f"# Block {ip} ({s.classification} - {s.threat_severity})\niptables -A INPUT -s {ip} -j DROP\nufw deny from {ip}")
        firewall_block = "\n".join(firewall_commands) if firewall_commands else "# No critical IP addresses required blocking."

        time_range = f"{res.start_time.strftime('%Y-%m-%d %H:%M:%S')} to {res.end_time.strftime('%Y-%m-%d %H:%M:%S')}" if res.start_time and res.end_time else "N/A"

        report = f"""# 🛡️ SECURITY INCIDENT & ANOMALY DETECTION REPORT

**Target Log File:** `{self.log_filename}`  
**Analysis Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}`  
**Log Duration Covered:** `{time_range}`  
**Overall Threat Posture:** **{overall_risk}**  

---

## 1. Executive Summary

An automated security log analysis was executed against the provided log dataset. The analysis engine parsed **{res.total_logs_analyzed} total log entries** ({res.auth_logs_count} authentication events, {res.web_logs_count} web server events) using custom regex patterns and temporal analysis.

### Key Metrics Scorecard
| Metric | Value | Status |
| :--- | :--- | :--- |
| **Total Log Events Analyzed** | `{res.total_logs_analyzed}` | Complete |
| **Total Security Anomalies Flagged** | `{len(res.anomalies)}` | Action Required |
| **Critical Severity Anomalies** | `{res.severity_counts.get('CRITICAL', 0)}` | 🚨 Urgent |
| **High Severity Anomalies** | `{res.severity_counts.get('HIGH', 0)}` | ⚠️ Elevate |
| **Medium Severity Anomalies** | `{res.severity_counts.get('MEDIUM', 0)}` | Monitor |
| **Low / Routine Severity Events** | `{res.severity_counts.get('LOW', 0)}` | Nominal |
| **High-Volume Malicious Attack Vectors** | `{len(res.malicious_attacks)}` | Confirmed |
| **Routine User Login Mistakes** | `{len(res.routine_errors)}` | Benign |

---

## 2. Differentiated Threat Classification

A core acceptance criterion of this analysis is the ability to strictly differentiate between **routine legitimate user mistakes** (e.g., mistyped passwords during work hours) and **malicious high-volume brute-force attacks or exploit scanners**.

### A. Benign / Routine Login Mistakes
Routine errors exhibit low failure counts ($< 5$), occur during standard business hours (08:00–18:00), target valid corporate users, and are commonly followed by a successful authentication session.

{routine_table_md}

### B. High-Volume Malicious Attacks & Exploit Scanners
Malicious attacks demonstrate automated high-frequency attempts ($> 5$ failures or $< 60$s bursts), off-hours probing, dictionary username enumeration (`root`, `oracle`, `admin`), or injection payloads.

{malicious_table_md}

---

## 3. Source IP Security Summary

The table below groups all network activity by source IP address, detailing total requests, failed authentications, credential stuffing targets, and threshold breach indicators.

{ip_table_md}

---

## 4. Detailed Security Anomalies & Incident Timeline

The analysis engine flagged the following specific security anomalies across authentication and web services:

{anomalies_table_md}

---

## 5. Recommended Incident Response & Mitigation Playbook

Based on the anomalies identified, the following mitigation steps are recommended immediately:

### A. Immediate Perimeter Blocking (Firewall Rules)
Execute the following commands on the affected gateway/server to drop all inbound traffic from high-severity offending IPs:

```bash
{firewall_block}
```

### B. SSH & Host Hardening Actions
1. **Disable SSH Password Authentication:** Enforce ED25519 or RSA public key authentication only (`PasswordAuthentication no` in `/etc/ssh/sshd_config`).
2. **Disable Direct Root Login:** Configure `PermitRootLogin no` to neutralize automated root brute-force attacks.
3. **Deploy Fail2ban:** Enable the `[sshd]` jail with `maxretry = 4` and `findtime = 600` to automatically ban repeat offenders.
4. **Change Default Ports:** Relocate SSH from port 22 to a non-standard port to avoid mass automated internet scans.

### C. Web Application & API Protection
1. **WAF Deployment:** Implement Cloud Armor, AWS WAF, or ModSecurity rules to intercept SQL injection (`UNION SELECT`) and Directory Traversal (`../etc/passwd`) before reaching backend apps.
2. **Parameter Sanitization:** Enforce strict prepared statements / parameterized queries to completely eliminate SQL injection vulnerabilities.
3. **Restrict Admin Endpoints:** Restrict access to `/admin`, `/phpmyadmin`, and configuration files (`.env`, `.git`) via IP allowlisting or VPN.

---
*Generated automatically by Antigravity Cyber Security Log Analyzer (Task 4).*
"""
        return report

    def generate_text(self) -> str:
        """Generates an ASCII Grid formatted plain text report for CLI and text outputs."""
        res = self.result
        overall_risk = self._determine_overall_risk()

        ip_rows = []
        for ip, s in sorted(res.ip_summaries.items(), key=lambda x: x[1].failed_logins, reverse=True):
            users_str = ", ".join(s.targeted_users[:2]) + ("..." if len(s.targeted_users) > 2 else "")
            ip_rows.append([
                ip,
                s.total_events,
                s.failed_logins,
                s.successful_logins,
                users_str or "N/A",
                s.classification,
                s.threat_severity,
                "YES [ALERT]" if s.failed_logins >= 5 else "NO"
            ])

        ip_headers = ["Source IP", "Total", "Failed", "Success", "Targeted Users", "Class", "Severity", "Threshold"]
        ip_grid = tabulate(ip_rows, headers=ip_headers, tablefmt="grid")

        anomaly_rows = []
        for a in res.anomalies[:20]:
            ts_str = a.timestamp.strftime("%m-%d %H:%M:%S")
            anomaly_rows.append([
                ts_str,
                a.ip,
                a.anomaly_type,
                a.severity,
                (a.description[:45] + "...") if len(a.description) > 45 else a.description
            ])
        anomaly_headers = ["Timestamp", "Source IP", "Vector", "Severity", "Description"]
        anomalies_grid = tabulate(anomaly_rows, headers=anomaly_headers, tablefmt="grid")

        text = f"""
================================================================================
                    CYBER SECURITY INCIDENT & ANOMALY REPORT
================================================================================
Target Log:       {self.log_filename}
Analysis Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Posture:     {overall_risk}
Total Events:     {res.total_logs_analyzed} (Auth: {res.auth_logs_count}, Web: {res.web_logs_count})
Critical / High:  {res.severity_counts.get('CRITICAL', 0)} Critical, {res.severity_counts.get('HIGH', 0)} High
--------------------------------------------------------------------------------

[1] IP SOURCE ACTIVITY SUMMARY:
{ip_grid}

[2] KEY SECURITY ANOMALIES DETECTED:
{anomalies_grid}

[3] ROUTINE USER ERRORS VS. MALICIOUS ATTACKS:
- Routine User Typos Detected:     {len(res.routine_errors)} instances
- Confirmed Malicious Attackers:    {len(res.malicious_attacks)} host(s)

[4] RECOMMENDED FIREWALL ACTIONS:
"""
        for ip, s in res.ip_summaries.items():
            if s.threat_severity in ("HIGH", "CRITICAL"):
                text += f"  * iptables -A INPUT -s {ip} -j DROP  # {s.classification} ({s.threat_severity})\n"

        text += "\n================================================================================\n"
        return text

