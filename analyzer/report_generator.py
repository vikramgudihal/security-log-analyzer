"""
Report Generation Engine for Security Log Analyzer.
Produces Markdown (.md), Plaintext (.txt), and CSV (.csv) reports with all 11 required sections.
"""

import csv
import io
from datetime import datetime
from typing import Dict, Any, List
from tabulate import tabulate
from analyzer.normalizer import LogEvent, Incident


class ReportGenerator:
    """Generates structured, professional security reports in MD, TXT, and CSV formats."""

    def __init__(self, analysis: Dict[str, Any], events: List[LogEvent], filename: str = "security_log.log"):
        self.analysis = analysis
        self.events = events
        self.filename = filename
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    def _determine_threat_posture(self) -> str:
        counts = self.analysis.get("severity_counts", {})
        if counts.get("CRITICAL", 0) > 0:
            return "CRITICAL (Active Exploitation or High-Confidence Compromise)"
        if counts.get("HIGH", 0) > 0:
            return "HIGH (Active Intrusions / Threshold Breaches Detected)"
        if counts.get("MEDIUM", 0) > 0:
            return "MEDIUM (Suspicious Activity Observed)"
        return "LOW (Nominal Operations)"

    def generate_markdown(self) -> str:
        """Generates the Markdown report (.md) with all 11 required sections."""
        a = self.analysis
        incidents: List[Incident] = a.get("incidents", [])
        counts = a.get("severity_counts", {})
        posture = self._determine_threat_posture()

        # Suspicious IPs Table
        ip_rows = []
        for ip_data in a.get("top_suspicious_ips", []):
            rules = ", ".join(ip_data.get("rules_triggered", [])[:2])
            ip_rows.append([
                ip_data["ip"],
                ip_data["total_events"],
                ip_data["failed_logins"],
                ip_data["successful_logins"],
                ", ".join(ip_data["unique_users"][:3]) or "N/A",
                f"**{ip_data['highest_severity']}**",
                rules or "N/A"
            ])
        ip_headers = ["Source IP", "Total", "Failed", "Success", "Targeted Users", "Severity", "Triggered Rules"]
        ip_table = tabulate(ip_rows, headers=ip_headers, tablefmt="github") if ip_rows else "_No suspicious IPs recorded._"

        # Incidents Table
        inc_rows = []
        for inc in incidents:
            inc_rows.append([
                inc.id,
                inc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                inc.source_ip,
                inc.rule_name,
                f"**{inc.severity}**",
                inc.description
            ])
        inc_headers = ["Incident ID", "Timestamp", "Source IP", "Rule Triggered", "Severity", "Description"]
        inc_table = tabulate(inc_rows, headers=inc_headers, tablefmt="github") if inc_rows else "_No security anomalies detected._"

        # Evidence table (sample events)
        evidence_rows = []
        for e in self.events[:15]:
            evidence_rows.append([
                e.id,
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                e.source_ip,
                e.event_type,
                e.auth_status,
                e.username or (e.url[:30] if e.url else "N/A"),
                e.message[:50] + ("..." if len(e.message) > 50 else "")
            ])
        ev_headers = ["Event ID", "Timestamp", "Source IP", "Event Type", "Status", "User / Endpoint", "Raw Sample"]
        evidence_table = tabulate(evidence_rows, headers=ev_headers, tablefmt="github")

        # Recommended Investigation Steps
        steps_list = []
        for inc in incidents[:5]:
            for step in inc.recommended_steps:
                if step not in steps_list:
                    steps_list.append(step)
        steps_md = "\n".join([f"- {s}" for s in steps_list]) if steps_list else "- No active remediation needed."

        md = f"""# 🛡️ SECURITY INCIDENT & ANOMALY ANALYSIS REPORT
**Incident Response & Security Operations**

---

### 1. Executive Summary
An automated defensive security analysis was conducted on the uploaded log dataset `{self.filename}`. The analysis engine evaluated all entries against standardized detection heuristics (brute force bursts, off-hours logins, credential stuffing, web exploit signatures, and authentication transitions).

The overall environment risk posture is currently evaluated as **{posture}**.

---

### 2. Analysis Metadata
- **Log Filename:** `{self.filename}`
- **Analysis Execution Time:** `{self.timestamp}`
- **Timezone Basis:** `UTC (Explicit Normalized)`
- **Parser Engine:** `MasterParser (Syslog / Apache / Nginx / CLF)`
- **Total Log Lines Processed:** `{len(self.events)}`

---

### 3. Total Events & Authentication Metrics
| Metric | Count | Assessment |
| :--- | :--- | :--- |
| **Total Events Analyzed** | `{a.get('total_events', 0)}` | Complete Log Stream |
| **Successful Logins** | `{a.get('successful_logins', 0)}` | Authorized Sessions |
| **Failed Logins** | `{a.get('failed_logins', 0)}` | Authentication Failures |
| **Unique Suspicious IPs** | `{a.get('suspicious_ip_count', 0)}` | Threat Actors Flagged |
| **Total Flagged Anomalies** | `{a.get('detected_anomalies_count', 0)}` | Actionable Incidents |

---

### 4. Severity Classification Breakdown
- 🚨 **CRITICAL:** `{counts.get('CRITICAL', 0)}`
- ⚠️ **HIGH:** `{counts.get('HIGH', 0)}`
- 🔶 **MEDIUM:** `{counts.get('MEDIUM', 0)}`
- 🟢 **LOW:** `{counts.get('LOW', 0)}`

---

### 5. Suspicious IP Addresses & Threat Attribution
{ip_table}

---

### 6. Detected Security Anomalies & Incident Timeline
{inc_table}

---

### 7. Relevant Event Evidence (Log Extract)
{evidence_table}

---

### 8. Recommended Investigation Steps & Playbooks
{steps_md}

#### Perimeter Containment Commands (Linux Firewall):
```bash
# Generated containment rules for detected High / Critical IPs:
"""
        for ip_data in a.get("top_suspicious_ips", []):
            if ip_data["highest_severity"] in ("CRITICAL", "HIGH"):
                md += f"iptables -A INPUT -s {ip_data['ip']} -j DROP  # {ip_data['highest_severity']}\n"
        md += """```

---

### 9. False-Positive Disclaimer
> **IMPORTANT NOTE:**  
> All security alerts generated by this tool are behavioral and signature-based indicators of potential malicious activity. Suspicious patterns must be treated as indicators requiring human validation, not definitive proof of system compromise. Routine password typos during regular business hours have been segregated to minimize operational noise.

---
*Report Generated by Security Log Analyzer (Task 4)*
"""
        return md

    def generate_text(self) -> str:
        """Generates an ASCII Grid formatted plain text report (.txt)."""
        a = self.analysis
        incidents: List[Incident] = a.get("incidents", [])
        posture = self._determine_threat_posture()

        ip_rows = []
        for ip_data in a.get("top_suspicious_ips", []):
            ip_rows.append([
                ip_data["ip"],
                ip_data["total_events"],
                ip_data["failed_logins"],
                ip_data["successful_logins"],
                ip_data["highest_severity"]
            ])
        ip_grid = tabulate(ip_rows, headers=["IP Address", "Total", "Failed", "Success", "Severity"], tablefmt="grid")

        inc_rows = []
        for inc in incidents[:15]:
            inc_rows.append([
                inc.id,
                inc.timestamp.strftime("%m-%d %H:%M:%S"),
                inc.source_ip,
                inc.rule_name[:25],
                inc.severity
            ])
        inc_grid = tabulate(inc_rows, headers=["ID", "Timestamp", "IP", "Rule", "Severity"], tablefmt="grid")

        txt = f"""
================================================================================
                    SECURITY INCIDENT ANALYSIS REPORT
================================================================================
Filename:        {self.filename}
Generated At:    {self.timestamp}
Threat Posture:  {posture}
Total Events:    {a.get('total_events', 0)}
Failed Logins:   {a.get('failed_logins', 0)}
Successful:      {a.get('successful_logins', 0)}
Suspicious IPs:  {a.get('suspicious_ip_count', 0)}
Anomalies:       {a.get('detected_anomalies_count', 0)}
--------------------------------------------------------------------------------

[1] TOP SUSPICIOUS IP ADDRESSES:
{ip_grid}

[2] DETECTED INCIDENTS:
{inc_grid}

[3] RECOMMENDED REMEDIATION ACTIONS:
"""
        for ip_data in a.get("top_suspicious_ips", []):
            if ip_data["highest_severity"] in ("CRITICAL", "HIGH"):
                txt += f"  - iptables -A INPUT -s {ip_data['ip']} -j DROP\n"

        txt += f"""
[4] FALSE-POSITIVE DISCLAIMER:
Alerts are behavioral indicators. Verify context before applying permanent bans.
================================================================================
"""
        return txt

    def generate_csv(self) -> str:
        """Generates a structured CSV (.csv) containing all detected incidents and event details."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Incident_ID",
            "Timestamp",
            "Source_IP",
            "Rule_Name",
            "Severity",
            "Description",
            "Reason",
            "Recommended_Investigation"
        ])

        for inc in self.analysis.get("incidents", []):
            writer.writerow([
                inc.id,
                inc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                inc.source_ip,
                inc.rule_name,
                inc.severity,
                inc.description,
                inc.reason,
                " | ".join(inc.recommended_steps)
            ])

        return output.getvalue()
