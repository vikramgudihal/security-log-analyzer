# 🛡️ Security Log Analyzer & Incident Response Engine (Task 4)

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red.svg)](https://streamlit.io/)
[![Tabulate](https://img.shields.io/badge/Report-Tabulate%20%7C%20Markdown-orange.svg)](https://pypi.org/project/tabulate/)
[![Cybersecurity](https://img.shields.io/badge/Domain-SOC%20%7C%20Incident%20Response-purple.svg)]()

> **Task 4: Incident Response & Anomaly Detection**  
> An automated, production-ready security log analysis tool designed to inspect authentication (`auth.log`) and web server (`access.log`) logs, detect brute-force attacks and known cyber attack signatures, differentiate routine errors from malicious campaigns, and generate executive-grade incident reports.

---

## 📌 Table of Contents
- [Project Overview](#-project-overview)
- [Key Features](#-key-features)
- [Technical Architecture](#-technical-architecture)
- [Detection Rules & Threat Engine](#-detection-rules--threat-engine)
- [Installation & Setup](#-installation--setup)
- [Command-Line Interface (CLI)](#-command-line-interface-cli)
- [Interactive Web Dashboard (Streamlit)](#-interactive-web-dashboard-streamlit)
- [Sample Incident Report Output](#-sample-incident-report-output)
- [Automated Testing Suite](#-automated-testing-suite)
- [Directory Structure](#-directory-structure)
- [Git & GitHub Submission Guide](#-git--github-submission-guide)
- [Author & Acknowledgments](#-author--acknowledgments)

---

## 🎯 Project Overview

In Security Operations Centers (SOC), analysts handle gigabytes of telemetry daily. Manual log reviews are prone to alert fatigue and miss subtle intrusions.

This tool solves this challenge by implementing an automated **Detection & Incident Response Engine**:
1. **Parses heterogeneous logs** using robust regular expressions (Linux SSH/Syslog & Apache/Nginx combined format).
2. **Tallies failed authentications** grouped by source IP address and flags threshold violations ($\ge 5$ attempts).
3. **Detects high-frequency brute-force bursts** using sliding temporal windows (e.g., $\ge 4$ failures within 60 seconds).
4. **Flags off-hours anomalies** (activity outside 08:00–18:00 Monday–Friday) and unauthorized privileged root sessions.
5. **Identifies known attack vectors** including SQL Injection (SQLi), Path/Directory Traversal (LFI), OS Command Injection (RCE), Cross-Site Scripting (XSS), and automated vulnerability scanners (Nikto, sqlmap, Masscan).
6. **Strictly differentiates routine mistakes from malicious campaigns** to minimize false positives.
7. **Generates publication-ready Markdown (`.md`) and ASCII Grid (`.txt`) Incident Reports** using `tabulate`.
8. **Generates instant remediation firewall rules** (`iptables` and `ufw`) for active perimeter containment.

---

## 🚀 Key Features

- **⚡ Dual Mode Interface**: Available as both a rapid **Command-Line Interface (CLI)** and a sleek, interactive **Streamlit Web Dashboard**.
- **🔍 Regex Log Parser**: Zero-dependency regex patterns matching standard syslog (`Oct 21 14:02:01`), ISO 8601 (`2026-10-21T14:02:01`), and Nginx/Apache Combined Access Log formats.
- **⏱️ Temporal Engine (`datetime`)**: Sliding-window rate limiting, timestamp normalization, and business hours vs. off-hours classification.
- **⚖️ False Positive Reduction**: Distinguishes between internal employees mistyping passwords during business hours and external automated credential stuffers.
- **📊 Tabulate & Markdown Reporting**: Clean tabular presentation of IPs, attack categories, targeted accounts, and chronological anomaly feeds.
- **🛡️ Instant Firewall Containment**: Auto-generates drop rules (`iptables -A INPUT -s <IP> -j DROP`) for high-severity offending hosts.

---

## 🏗️ Technical Architecture

```text
┌────────────────────────────────────────────────────────┐
│             Raw Log Stream (auth.log / nginx)          │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │  src/parsers.py (Regex)   │
              │  - Syslog / SSH Extraction│
              │  - Web Nginx/Apache Parse │
              └─────────────┬─────────────┘
                            │ Structured LogEntries
                            ▼
              ┌───────────────────────────┐
              │  src/analyzer.py (Engine) │
              │  - Threshold Breaches     │
              │  - Rapid Burst Detection  │
              │  - Off-Hours Temporal Eval│
              │  - Attack Signature Match │
              │  - False-Positive Diff    │
              └─────────────┬─────────────┘
                            │ AnalysisResult Model
                            ▼
         ┌──────────────────┴──────────────────┐
         ▼                                     ▼
┌─────────────────────────┐          ┌─────────────────────────┐
│   CLI: log_analyzer.py  │          │    Web UI: app.py       │
│   (Terminal & ASCII)    │          │  (Streamlit Dashboard)  │
└────────────┬────────────┘          └────────────┬────────────┘
             │                                    │
             ▼                                    ▼
┌──────────────────────────────────────────────────────────────┐
│  src/reporter.py -> Markdown (.md) & Tabulate Plaintext (.txt)│
└──────────────────────────────────────────────────────────────┘
```

---

## 🔬 Detection Rules & Threat Engine

| Threat Vector | Rule Logic / Regex Signature | Severity | MITRE ATT&CK Ref |
| :--- | :--- | :--- | :--- |
| **High Failed Logins** | Failed authentication tally $\ge 5$ attempts from single IP | **HIGH / CRITICAL** | T1110 (Brute Force) |
| **Rapid Burst Attack** | $\ge 4$ failed attempts within 60 seconds | **CRITICAL** | T1110.001 (Password Guessing) |
| **Off-Hours Intrusion** | Activity outside 08:00–18:00 Mon–Fri or weekend | **HIGH** | T1078 (Valid Accounts) |
| **Privileged Off-Hours Login** | Successful `root` / `admin` session during off-hours | **CRITICAL** | T1078.003 (Local Accounts) |
| **SQL Injection (SQLi)** | `(?i)(union\s+select|or\s+\d+=\d+|--|drop\s+table)` | **CRITICAL** | T1190 (Exploit Public-Facing App) |
| **Path Traversal (LFI)** | `(\.\./|\.\.\\|/etc/passwd|win\.ini|boot\.ini)` | **HIGH** | T1083 (File & Directory Discovery) |
| **OS Command Injection** | `(;|\$\(|\bexec\b).*(cat\s+/etc/passwd|whoami|bash)` | **CRITICAL** | T1059 (Command & Scripting Interpreter) |
| **Vulnerability Scanners** | User agents: `sqlmap`, `nikto`, `masscan`, `nmap` | **HIGH** | T1595 (Active Scanning) |

---

## 💻 Installation & Setup

### Prerequisites
- Python 3.10 or higher
- `git` version control tool

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/security-log-analyzer.git
cd security-log-analyzer
```

### 2. Create and Activate Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🖥️ Command-Line Interface (CLI)

The CLI tool `log_analyzer.py` offers extensive options for automated batch processing and headless server environments:

### Basic Execution (Default Auth Log)
```bash
python log_analyzer.py --log logs/auth.log
```

### Analyzing Web Server Access Logs
```bash
python log_analyzer.py --log logs/nginx_access.log
```

### Customizing Thresholds and Formats
```bash
python log_analyzer.py \
  --log logs/auth.log \
  --threshold 5 \
  --burst-count 4 \
  --burst-window 60 \
  --format both \
  --output-dir reports
```

### CLI Command Options
- `--log`, `-l`: Path to log file (`logs/auth.log`, `logs/nginx_access.log`, etc.)
- `--threshold`, `-t`: Failed login count threshold per IP (default: `5`)
- `--burst-count`: Number of attempts inside time window to trigger burst alert (default: `4`)
- `--burst-window`: Burst window duration in seconds (default: `60`)
- `--format`, `-f`: Format choice: `markdown`, `text`, or `both` (default: `both`)
- `--output-dir`, `-o`: Directory where reports are saved (default: `reports`)
- `--quiet`, `-q`: Suppress terminal banner and ASCII tables

---

## 🌐 Interactive Web Dashboard (Streamlit)

For an intuitive visual exploration experience, launch the Streamlit web application:

```bash
streamlit run app.py
```

### Dashboard Capabilities:
- **Preset Scenarios & File Uploader:** Switch seamlessly between SSH logs, Web access logs, multi-vector incidents, or upload your own `.log` files.
- **Dynamic Anomaly Sliders:** Tweak thresholds and business hours in real-time with instant recalculation.
- **Interactive KPI Scorecards:** Immediate view of Total Logs, Critical Threats, Malicious IPs, and Routine Typos.
- **Threat Analytics Charts:** Visual representation of threat severities and top offending IP addresses.
- **Differentiated Analysis Tab:** Visual comparison side-by-side between genuine user mistakes and malicious intrusions.
- **One-Click Export:** Download publication-ready `.md` and `.txt` reports with a single click.
- **Remediation Firewall Playbook:** Auto-generated `iptables` and `ufw` drop commands ready for execution.

---

## 📑 Sample Incident Report Output

### Terminal ASCII Grid Format (Sample Excerpt)
```text
================================================================================
                    CYBER SECURITY INCIDENT & ANOMALY REPORT
================================================================================
Target Log:       logs/auth.log
Analysis Time:    2026-11-04 07:20:09
Risk Posture:     CRITICAL (Immediate Action Required)
Total Events:     37 (Auth: 37, Web: 0)
Critical / High:  3 Critical, 5 High
--------------------------------------------------------------------------------

[1] IP SOURCE ACTIVITY SUMMARY:
+---------------+---------+----------+-----------+-------------------------+--------------------+------------+-------------+
| Source IP     |   Total |   Failed |   Success | Targeted Users          | Class              | Severity   | Threshold   |
+===============+=========+==========+===========+=========================+====================+============+=============+
| 203.0.113.88  |      15 |       15 |         0 | admin, administrator... | BRUTE_FORCE_ATTACK | CRITICAL   | YES [ALERT] |
| 198.51.100.23 |       8 |        7 |         1 | admin, backup...        | BRUTE_FORCE_ATTACK | HIGH       | YES [ALERT] |
| 185.220.101.5 |       6 |        6 |         0 | debian, ftpuser...      | BRUTE_FORCE_ATTACK | HIGH       | YES [ALERT] |
| 192.168.1.45  |       3 |        1 |         2 | bob                     | ROUTINE_ERROR      | LOW        | NO          |
| 192.168.1.80  |       2 |        1 |         1 | charlie                 | ROUTINE_ERROR      | LOW        | NO          |
| 192.168.1.10  |       2 |        0 |         2 | alice                   | BENIGN             | LOW        | NO          |
+---------------+---------+----------+-----------+-------------------------+--------------------+------------+-------------+

[2] ROUTINE USER ERRORS VS. MALICIOUS ATTACKS:
- Routine User Typos Detected:     2 instances
- Confirmed Malicious Attackers:    3 host(s)

[3] RECOMMENDED FIREWALL ACTIONS:
  * iptables -A INPUT -s 203.0.113.88 -j DROP  # BRUTE_FORCE_ATTACK (CRITICAL)
  * iptables -A INPUT -s 185.220.101.5 -j DROP  # BRUTE_FORCE_ATTACK (HIGH)
  * iptables -A INPUT -s 198.51.100.23 -j DROP  # BRUTE_FORCE_ATTACK (HIGH)
```

---

## 🧪 Automated Testing Suite

A comprehensive test suite is included in `test_analyzer.py` to validate parsing, detection thresholds, burst logic, attack signatures, and report outputs:

```bash
python test_analyzer.py
```
Output:
```text
.......
----------------------------------------------------------------------
Ran 7 tests in 0.044s

OK
```

---

## 📂 Directory Structure

```text
task4/
│
├── logs/                                       # Sanitized Synthetic Log Datasets
│   ├── auth.log                                # Linux SSH log (Brute-force, bursts, off-hours)
│   ├── nginx_access.log                        # Web log (SQLi, Path Traversal, Scanners, XSS)
│   └── test_mixed.log                          # Multi-vector incident log
│
├── reports/                                    # Generated Security Incident Reports
│   ├── security_incident_report_auth.md        # Formatted Markdown report
│   ├── security_incident_report_auth.txt       # Formatted ASCII text report
│   ├── security_incident_report_nginx_access.md
│   ├── security_incident_report_nginx_access.txt
│   ├── security_incident_report_test_mixed.md
│   └── security_incident_report_test_mixed.txt
│
├── src/                                        # Modular Core Engine
│   ├── __init__.py                             # Package export definitions
│   ├── parsers.py                              # Regex log parsing & timestamp normalization
│   ├── signatures.py                           # Known attack regexes (SQLi, LFI, RCE, XSS)
│   ├── analyzer.py                             # Anomaly detector & False Positive differentiator
│   └── reporter.py                             # Tabulate & Markdown report generator
│
├── log_analyzer.py                             # Primary CLI executable script
├── app.py                                      # Streamlit Interactive Web Application
├── test_analyzer.py                            # Automated unit & integration test suite
├── requirements.txt                            # Project dependencies
├── .gitignore                                  # Git exclusion configuration
├── README.md                                   # Project documentation
├── GITHUB_PUSHING_GUIDE.md                     # Step-by-step Git push manual
└── LINKEDIN_POSTING_GUIDE.md                   # Ready-to-use LinkedIn post templates
```

---

## 🛡️ Git & GitHub Submission Guide

Refer to [GITHUB_PUSHING_GUIDE.md](GITHUB_PUSHING_GUIDE.md) for step-by-step commands to push this project to your GitHub repository and showcase it on your portfolio.

For sharing your achievement on LinkedIn, check out [LINKEDIN_POSTING_GUIDE.md](LINKEDIN_POSTING_GUIDE.md).

---

## 👤 Author & Acknowledgments
- **Project:** Cyber Security Internship — Task 4
- **Domain:** Incident Response & Anomaly Detection
- **Tools Used:** Python, Regular Expressions (`re`), `datetime`, `tabulate`, `streamlit`

