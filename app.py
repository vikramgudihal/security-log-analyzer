"""
Interactive Web Application for Security Log Analysis (Streamlit Interface).
TASK 4: Incident Response & Anomaly Detection Dashboard.
"""

import os
import streamlit as st
import pandas as pd
from datetime import datetime
from src.parsers import LogParser
from src.analyzer import SecurityLogAnalyzer
from src.reporter import SecurityReportGenerator

st.set_page_config(
    page_title="SOC Anomaly & Incident Response Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1E293B;
        margin-bottom: 0px;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748B;
        margin-bottom: 25px;
    }
    .metric-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #FFEDD5;
        color: #9A3412;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    .badge-routine {
        background-color: #DCFCE7;
        color: #166534;
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: bold;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Sidebar Controls
st.sidebar.title("🛡️ Analyzer Controls")
st.sidebar.markdown("Configure parsing & anomaly thresholds:")

sample_option = st.sidebar.selectbox(
    "Select Sample Log or Upload",
    ["logs/auth.log (Linux SSH & Brute-Force)", "logs/nginx_access.log (Web Exploits & SQLi)", "logs/test_mixed.log (Multi-Vector Incident)", "Upload Custom Log File"],
)

uploaded_file = None
if sample_option == "Upload Custom Log File":
    uploaded_file = st.sidebar.file_uploader("Upload server log file (.log, .txt)", type=["log", "txt"])

st.sidebar.markdown("---")
st.sidebar.subheader("Detection Thresholds")
failed_threshold = st.sidebar.slider("Failed Login Threshold", min_value=2, max_value=20, value=5, help="Tally of failed logins per IP to trigger alert")
burst_count = st.sidebar.slider("Burst Failure Count", min_value=2, max_value=10, value=4, help="Consecutive attempts within window")
burst_window = st.sidebar.slider("Burst Window (Seconds)", min_value=10, max_value=300, value=60, help="Window to detect rapid brute-force")
biz_start = st.sidebar.slider("Business Hours Start (Hour)", min_value=0, max_value=23, value=8)
biz_end = st.sidebar.slider("Business Hours End (Hour)", min_value=0, max_value=23, value=18)

# Load log content
log_text = ""
log_filename = ""

if uploaded_file is not None:
    log_text = uploaded_file.getvalue().decode("utf-8", errors="replace")
    log_filename = uploaded_file.name
else:
    file_path = sample_option.split()[0]
    log_filename = os.path.basename(file_path)
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            log_text = f.read()
    else:
        st.error(f"Sample log file '{file_path}' not found.")

# Dashboard Title
st.markdown("<div class='main-header'>🛡️ Security Log Analyzer & Incident Response Engine</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='sub-header'>Real-Time Anomaly Detection, Brute-Force Identification & Automated Report Generation | Task 4</div>",
    unsafe_allow_html=True,
)

if log_text:
    # Parsing
    parser = LogParser()
    entries = []
    for idx, line in enumerate(log_text.splitlines(), start=1):
        parsed = parser.parse_line(line, line_number=idx)
        if parsed:
            entries.append(parsed)

    analyzer = SecurityLogAnalyzer(
        failed_login_threshold=failed_threshold,
        burst_threshold=burst_count,
        burst_window_seconds=burst_window,
        business_start_hour=biz_start,
        business_end_hour=biz_end,
    )
    result = analyzer.analyze(entries)
    reporter = SecurityReportGenerator(result, log_filename=log_filename)
    markdown_report = reporter.generate_markdown()
    text_report = reporter.generate_text()

    # KPI Top Row
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.metric("Total Logs Parsed", result.total_logs_analyzed)
    with kpi2:
        st.metric("Critical Anomalies", result.severity_counts.get("CRITICAL", 0))
    with kpi3:
        st.metric("High Threats", result.severity_counts.get("HIGH", 0))
    with kpi4:
        st.metric("Malicious IPs", len(result.malicious_attacks))
    with kpi5:
        st.metric("Routine Typos", len(result.routine_errors))

    st.markdown("---")

    # Main Tabs
    tab_overview, tab_ips, tab_anomalies, tab_diff, tab_report, tab_playbook = st.tabs(
        [
            "📊 Executive Dashboard",
            "🌐 Source IP Intel",
            "🚨 Flagged Anomalies",
            "⚖️ Routine vs Malicious",
            "📄 Exportable Reports",
            "🛡️ Remediation Playbook",
        ]
    )

    with tab_overview:
        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.subheader("Threat Severity Distribution")
            sev_data = pd.DataFrame(
                list(result.severity_counts.items()),
                columns=["Severity", "Count"]
            ).set_index("Severity")
            st.bar_chart(sev_data, color="#E11D48")

        with col_right:
            st.subheader("Top Offending Source IPs")
            if result.top_offending_ips:
                top_df = pd.DataFrame(
                    result.top_offending_ips,
                    columns=["IP Address", "Failed Logins"]
                ).set_index("IP Address")
                st.bar_chart(top_df, color="#2563EB")
            else:
                st.info("No repeated failed login attempts recorded.")

        st.subheader("Log Activity Snapshot")
        log_sample_df = pd.DataFrame([
            {
                "Line": e.line_number,
                "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Source IP": e.ip,
                "Type": e.log_type,
                "Event": e.event_type,
                "Target User / URI": e.user or (e.url[:40] if e.url else "N/A"),
                "HTTP Status / Port": e.status_code or e.port or "-",
            }
            for e in entries[:15]
        ])
        st.dataframe(log_sample_df, use_container_width=True)

    with tab_ips:
        st.subheader("Source IP Threat Profiling & Activity Matrix")
        ip_rows = []
        for ip, s in result.ip_summaries.items():
            ip_rows.append({
                "Source IP": ip,
                "Total Events": s.total_events,
                "Failed Logins": s.failed_logins,
                "Successes": s.successful_logins,
                "Targeted Users": ", ".join(s.targeted_users) or "N/A",
                "Burst Detected": "🚨 YES" if s.is_burst_detected else "No",
                "Off-Hours Activity": "⚠️ YES" if s.is_off_hours_active else "No",
                "Classification": s.classification,
                "Threat Severity": s.threat_severity,
                "Threshold Breached": "CRITICAL / HIGH" if s.failed_logins >= failed_threshold else "Normal",
            })
        if ip_rows:
            ip_df = pd.DataFrame(ip_rows).sort_values(by="Failed Logins", ascending=False)
            st.dataframe(ip_df, use_container_width=True)

    with tab_anomalies:
        st.subheader("Chronological Incident & Anomaly Feed")
        if result.anomalies:
            anom_rows = [
                {
                    "Timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "Source IP": a.ip,
                    "Anomaly Vector": a.anomaly_type,
                    "Severity": a.severity,
                    "Technical Detail": a.description,
                }
                for a in result.anomalies
            ]
            st.dataframe(pd.DataFrame(anom_rows), use_container_width=True)
        else:
            st.success("No anomalies or threats detected within the current thresholds.")

    with tab_diff:
        st.subheader("Differentiating Routine Mistakes from Malicious Attacks")
        st.write(
            "Security systems must avoid false positives. This engine cross-references failure count, business hours, and account validity."
        )

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.markdown("### 🟢 Benign / Routine Login Mistakes")
            st.caption("Low failures (< threshold), standard business hours, genuine user typos.")
            if result.routine_errors:
                st.dataframe(pd.DataFrame(result.routine_errors), use_container_width=True)
            else:
                st.info("No routine login typos observed.")

        with d_col2:
            st.markdown("### 🔴 Confirmed Malicious Attacks")
            st.caption("Automated bursts, exploit signatures, dictionary attacks, or off-hours intrusions.")
            if result.malicious_attacks:
                st.dataframe(pd.DataFrame(result.malicious_attacks), use_container_width=True)
            else:
                st.info("No malicious attacks detected.")

    with tab_report:
        st.subheader("Generated Security Incident Report")
        st.caption("Export publication-grade Markdown and ASCII reports directly for stakeholders or documentation.")

        rep_col1, rep_col2 = st.columns(2)
        with rep_col1:
            st.download_button(
                label="📥 Download Markdown Report (.md)",
                data=markdown_report,
                file_name=f"Security_Incident_Report_{log_filename}.md",
                mime="text/markdown",
            )
        with rep_col2:
            st.download_button(
                label="📥 Download Plaintext Report (.txt)",
                data=text_report,
                file_name=f"Security_Incident_Report_{log_filename}.txt",
                mime="text/plain",
            )

        st.markdown("---")
        st.markdown(markdown_report)

    with tab_playbook:
        st.subheader("Incident Response & Containment Playbook")
        st.markdown("Automated containment firewall commands for detected malicious IPs:")

        fw_rules = []
        for ip, s in result.ip_summaries.items():
            if s.threat_severity in ("HIGH", "CRITICAL"):
                fw_rules.append(f"# Block {ip} - {s.classification} ({s.threat_severity})\niptables -A INPUT -s {ip} -j DROP\nufw deny from {ip}\n")

        if fw_rules:
            st.code("\n".join(fw_rules), language="bash")
        else:
            st.info("No immediate perimeter blocks required for this log dataset.")

        st.markdown("#### Recommended Hardening Steps:")
        st.markdown(
            """
            1. **SSH Key Enforcement:** Ensure `PasswordAuthentication no` in `/etc/ssh/sshd_config`.
            2. **Fail2ban Integration:** Activate `jail.local` with ban-time scaling for repeated offenders.
            3. **WAF Rule Implementation:** Block payloads containing `UNION SELECT` and `../` patterns at edge proxy.
            """
        )
else:
    st.warning("Please upload or select a log file to begin analysis.")

