# 🛡️ Security Log Analyzer & Incident Response Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Backend-Flask%203.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Frontend](https://img.shields.io/badge/Frontend-HTML5%20%7C%20CSS3%20%7C%20Chart.js-orange.svg)]()
[![Testing](https://img.shields.io/badge/Tests-Pytest%20(22%20Passed)-green.svg)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

> A defensive **Security Log Analyzer & Incident Response Web Application** built with Python, Flask, Regex, Datetime, and Tabulate.
> It parses Linux authentication logs (`auth.log`/`secure`) and web server access logs (Apache/Nginx), identifies repeated failed authentications, detects brute-force bursts and web attack vectors, strictly differentiates routine user typos from malicious campaigns, and generates structured executive reports in **Markdown (.md)**, **Plaintext (.txt)**, and **CSV (.csv)**.

---

## 📌 Table of Contents
- [1. Project Objectives & Security Guardrails](#1-project-objectives--security-guardrails)
- [2. Technology Stack](#2-technology-stack)
- [3. Complete Project Folder Structure](#3-complete-project-folder-structure)
- [4. The 7 Core Detection Rules](#4-the-7-core-detection-rules)
- [5. 4-Tier Incident Severity Engine](#5-4-tier-incident-severity-engine)
- [6. Synthetic Sample Datasets](#6-synthetic-sample-datasets)
- [7. Installation & Quick Start](#7-installation--quick-start)
- [8. Application Workflow & Demonstration Guide](#8-application-workflow--demonstration-guide)
- [9. Automated Testing (Pytest)](#9-automated-testing-pytest)
- [10. Incident Report Deliverables](#10-incident-report-deliverables)
- [11. Git Pushing & Submission Instructions](#11-git-pushing--submission-instructions)

---

## 1. Project Objectives & Security Guardrails

### Core Objective:
Develop a local, defensive security log analysis tool that accepts sanitized or synthetic authentication and web server log files, analyzes the events, detects suspicious activities, classifies incidents, and generates structured security reports.

### Security & Privacy Guardrails:
- **100% Local Processing:** Runs purely in local memory (`127.0.0.1:5000`); never connects to external servers, external APIs, or cloud backends.
- **Strictly Defensive:** Does not execute network scans, port probes, brute-force testing, or credential harvesting.
- **Non-Execution of Uploads:** Files are validated (`.log` and `.txt` only), sanitized with `werkzeug.utils.secure_filename`, and processed purely as text.
- **XSS & Injection Protection:** All displayed log content is strictly HTML-escaped.
- **Zero Real Target Data:** Works exclusively on sanitized and synthetic datasets with documentation-only IPs (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and private `192.168.1.0/24`).

---

## 2. Technology Stack

- **Backend:** Python 3, Flask 3.0, Regular Expressions (`re`), Datetime, Pandas, Werkzeug
- **Frontend:** HTML5, Modern CSS3 (Inter & JetBrains Mono typography), Vanilla JavaScript, Chart.js 4 (via CDN)
- **Testing:** Pytest (22 passing unit and integration tests)
- **Reporting:** Tabulate, Markdown (.md), Plaintext (.txt), Comma-Separated Values (.csv)

---

## 3. Complete Project Folder Structure

```text
security-log-analyzer/
│
├── app.py                                      # Flask web application entrypoint & API
├── config.py                                   # Global configuration, thresholds, and limits
├── requirements.txt                            # Python dependencies
├── README.md                                   # Complete documentation & user guide
├── GITHUB_PUSHING_GUIDE.md                     # Step-by-step Git push manual
├── LINKEDIN_POSTING_GUIDE.md                   # Ready-to-use LinkedIn post templates
│
├── analyzer/                                   # Modular Detection & Parsing Package
│   ├── __init__.py                             # Package exports
│   ├── normalizer.py                           # Standardized LogEvent & Incident dataclasses
│   ├── auth_parser.py                          # Linux auth.log/secure regex parser with year inference
│   ├── web_parser.py                           # Apache & Nginx Combined/CLF access log parser
│   ├── parser.py                               # MasterParser dispatcher & format auto-detection
│   ├── detection.py                            # 7 SOC detection rules engine
│   ├── severity.py                             # 4-tier incident severity classifier
│   └── report_generator.py                     # Markdown, Text, and CSV report generator
│
├── templates/                                  # Responsive SOC-Themed Jinja2 Templates
│   ├── base.html                               # Navigation bar, status indicator, flash alerts, footer
│   ├── index.html                              # Upload logs page with drag-and-drop & quick sample loader
│   ├── dashboard.html                          # Executive dashboard with Chart.js analytics & KPI cards
│   ├── events.html                             # Security events browser with multi-field search & filters
│   ├── incidents.html                          # Incidents page with severity filters & firewall commands
│   ├── reports.html                            # In-browser report preview and one-click download buttons
│   └── about.html                              # Architecture, methodology, and MITRE ATT&CK mapping
│
├── static/                                     # Static Assets
│   ├── css/
│   │   └── style.css                           # Light SOC design, navy text, blue accents, severity colors
│   └── js/
│       └── dashboard.js                        # Chart.js initialization and drag-and-drop listeners
│
├── samples/                                    # Synthetic Sanitized Test Logs
│   ├── normal_auth.log                         # Legitimate business-hours authentications
│   ├── brute_force_sample.log                  # High-velocity dictionary attacks & bursts
│   ├── off_hours_sample.log                    # Nighttime logins (02:14 - 05:22) and root access
│   ├── web_access_sample.log                   # Web access logs with SQLi, Traversal, 401/403 bursts
│   └── mixed_sample.log                        # Multi-vector incident log with malformed entries
│
├── reports/                                    # Generated Incident Reports
│   ├── security_incident_report_auth.md
│   ├── security_incident_report_auth.txt
│   ├── security_incident_report_nginx_access.md
│   ├── security_incident_report_nginx_access.txt
│   ├── security_incident_report_test_mixed.md
│   └── security_incident_report_test_mixed.txt
│
└── tests/                                      # Automated Pytest Suite
    ├── test_parser.py                          # Auth and Web parser validation
    ├── test_detection.py                       # 7 detection rules validation
    ├── test_severity.py                        # Severity scaling and off-hours check
    └── test_reports.py                         # MD, TXT, and CSV generation checks
```

---

## 4. The 7 Core Detection Rules

| # | Rule Name | Trigger Criteria | Default Severity | MITRE ATT&CK |
|---|:---|:---|:---:|:---:|
| **1** | **Repeated Failed Authentication** | Groups failed logins by IP. 1–3: LOW, 4–5: MEDIUM, $\ge 6$: HIGH, $\ge 15$: CRITICAL. | **MEDIUM / HIGH** | T1110 |
| **2** | **Rapid Sequential Login Attempts** | $\ge 4$ failed login attempts within a 60-second sliding window from the same IP. | **HIGH / CRITICAL** | T1110.001 |
| **3** | **Multiple Usernames Targeted** | Single source IP targeting $\ge 3$ distinct usernames (credential stuffing / dictionary scan). | **HIGH** | T1110.004 |
| **4** | **Successful Login Following Failures** | An IP has $\ge 3$ consecutive failed attempts followed immediately by a successful authentication (Compromise alert). | **CRITICAL** | T1078 |
| **5** | **Off-Hours Login Activity** | Authentication attempts outside 08:00–18:00 Mon–Fri. *(Never classified as CRITICAL solely for off-hours)*. | **MEDIUM / HIGH** | T1078.003 |
| **6** | **HTTP 401 & 403 Error Bursts** | $\ge 5$ web client access denial responses from single IP in short timeframe (endpoint probing). | **MEDIUM** | T1595.002 |
| **7** | **Suspicious URL Patterns** | Regex detection for SQLi (`UNION SELECT`), Path Traversal (`../etc/passwd`), Command Injection, and scanners (`nikto`, `sqlmap`). | **HIGH / CRITICAL** | T1190 / T1083 |

---

## 5. 4-Tier Incident Severity Engine

1. **LOW (Green):**
   - Routine password typos during regular business hours followed by successful login.
   - Isolated single failed attempts below threshold.
2. **MEDIUM (Orange):**
   - 4–5 failed attempts (exceeding normal typo tolerance).
   - Off-hours authentication events without privilege escalation.
   - HTTP 401/403 access denial bursts.
3. **HIGH (Red):**
   - Failed logins $\ge 6$ attempts (threshold breach).
   - Rapid sequential login bursts ($\ge 4$ in 60s).
   - Credential stuffing targeting multiple usernames.
   - Path Traversal and automated vulnerability scanner probes.
4. **CRITICAL (Dark Red):**
   - **Successful authentication immediately following repeated brute-force failures** (Potential Account Compromise).
   - Extreme brute-force volume ($\ge 15$ attempts).
   - Exploitation payloads: SQL Injection (`UNION SELECT`), OS Command Injection.

---

## 6. Synthetic Sample Datasets

All sample datasets in `samples/` are purely synthetic and use RFC-reserved IP addresses:

1. `samples/normal_auth.log`: Normal user logins during business hours (`alice`, `bob`, `charlie`).
2. `samples/brute_force_sample.log`: Rapid SSH dictionary attack from `203.0.113.88` targeting `root`, `admin`, `oracle`, `postgres`, `git`, `deploy`.
3. `samples/off_hours_sample.log`: Suspicious off-hours attacks at 02:14, 03:52, and 05:22.
4. `samples/web_access_sample.log`: Web traffic containing SQLi, Path Traversal (`../../etc/passwd`), 401/403 bursts, and `sqlmap`/`Nikto` probes.
5. `samples/mixed_sample.log`: Combined scenario featuring legitimate logins, malformed lines, SQLi, and a critical **successful login following repeated failed attempts**.

---

## 7. Installation & Quick Start

### 1. Clone or Open the Repository
```bash
git clone https://github.com/<your-username>/security-log-analyzer.git
cd security-log-analyzer
```

### 2. Set Up Virtual Environment (Recommended)
```bash
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Flask Web Application
```bash
python app.py
```
Open your browser and navigate to:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 8. Application Workflow & Demonstration Guide

1. **Upload / Quick-Load Page (`/`):**
   - Click any sample card (e.g., `mixed_sample.log` or `brute_force_sample.log`) to load and inspect instantly.
   - Alternatively, drag and drop any `.log` or `.txt` file into the upload zone.
2. **SOC Dashboard (`/dashboard`):**
   - View 6 calculated KPI cards: Total Events, Successful Logins, Failed Logins, Suspicious IPs, Anomalies, Critical Incidents.
   - Explore interactive **Chart.js** visualizations:
     - Authentication Activity Timeline (Hourly Failed vs. Successful Logins).
     - Incident Severity Distribution Doughnut Chart.
   - Inspect the Top Offending Source IPs table.
3. **Security Events Explorer (`/events`):**
   - Filter events by Source IP (e.g. `203.0.113.88`).
   - Filter by Username (e.g. `root`, `admin`).
   - Filter by Event Type (`LOGIN_FAILED`, `LOGIN_SUCCESS`, `WEB_REQUEST`).
   - Events are automatically sorted recent first.
4. **Detected Incidents (`/incidents`):**
   - Filter by severity tabs (CRITICAL, HIGH, MEDIUM, LOW).
   - Review rule triggers, technical reasons, and recommended response playbooks.
   - Copy auto-generated `iptables` perimeter containment commands for malicious hosts.
5. **Reports Hub (`/reports`):**
   - Download the full incident report in **Markdown (.md)**, **Plaintext (.txt)**, or **CSV (.csv)**.

---

## 9. Automated Testing (Pytest)

The project includes an automated test suite verifying all parsers, detection heuristics, severity rankings, and report exports:

```bash
pytest -v
```

### Test Results:
```text
============================= test session starts =============================
platform win32 -- Python 3.12.3, pytest-9.1.1
collected 22 items

tests/test_parser.py::test_auth_parser_valid_failed_login PASSED         [  4%]
tests/test_parser.py::test_auth_parser_invalid_user PASSED               [  9%]
tests/test_parser.py::test_auth_parser_accepted_login PASSED             [ 13%]
tests/test_parser.py::test_web_parser_combined_format PASSED             [ 18%]
tests/test_parser.py::test_master_parser_with_malformed_lines PASSED     [ 22%]
tests/test_detection.py::test_failed_login_grouping_and_threshold PASSED [ 27%]
tests/test_detection.py::test_successful_login_after_failures PASSED     [ 31%]
tests/test_detection.py::test_rapid_burst_detection PASSED               [ 36%]
tests/test_detection.py::test_multiple_usernames_targeted PASSED         [ 40%]
tests/test_detection.py::test_off_hours_detection PASSED                 [ 45%]
tests/test_detection.py::test_web_signatures_and_error_burst PASSED      [ 50%]
tests/test_severity.py::test_failed_login_severity_scaling PASSED        [ 54%]
tests/test_severity.py::test_off_hours_never_critical_alone PASSED       [ 59%]
tests/test_severity.py::test_attack_signature_severity PASSED            [ 63%]
tests/test_reports.py::test_report_generation_formats PASSED             [ 68%]
... (22 passed in 0.60s)
============================= 22 passed in 0.60s ==============================
```

---

## 10. Incident Report Deliverables

Pre-generated reports are stored in `reports/`:
- `reports/security_incident_report_auth.md` & `.txt`
- `reports/security_incident_report_nginx_access.md` & `.txt`
- `reports/security_incident_report_test_mixed.md` & `.txt`

Every report contains all 11 required sections:
1. Executive Summary
2. Analysis Metadata
3. Total Events & Authentication Metrics
4. Severity Classification Breakdown
5. Suspicious IP Addresses & Threat Attribution
6. Detected Security Anomalies & Incident Timeline
7. Relevant Event Evidence (Raw Log Extract)
8. Recommended Investigation Steps & Firewall Playbook
9. False-Positive Disclaimer

---

## 11. Git Pushing & Submission Instructions

Please refer to:
- [`GITHUB_PUSHING_GUIDE.md`](GITHUB_PUSHING_GUIDE.md) for full Git repository push instructions.
- [`LINKEDIN_POSTING_GUIDE.md`](LINKEDIN_POSTING_GUIDE.md) for ready-to-copy LinkedIn / Portfolio showcase posts.

---

## 👤 Project Status
- **Module:** Task 4 — Security Log Analyzer (Incident Response & Anomaly Detection)
- **Status:** Complete, Verified & Tested (22/22 Tests Passing)
