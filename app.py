"""
Flask Web Application for Security Log Analyzer (CodeNova Task 4).
Full SOC-style interface featuring Dashboards, Event Filtering, Incident Inspection,
MITRE ATT&CK Correlation, Threat Dossiers, and Dynamic Remediation.
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from werkzeug.utils import secure_filename
from config import Config
from analyzer import MasterParser, DetectionEngine, ReportGenerator

app = Flask(__name__)
app.config.from_object(Config)

# Ensure required directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['SAMPLES_FOLDER'], exist_ok=True)

# In-memory storage for the active SOC analysis session
SESSION_DATA = {
    "filename": "mixed_sample.log",
    "events": [],
    "stats": {},
    "analysis": {},
    "quarantined_ips": set(),
    "thresholds": {
        "failed_low": Config.FAILED_LOGIN_LOW_MIN,
        "failed_med": Config.FAILED_LOGIN_MED_MIN,
        "failed_high": Config.FAILED_LOGIN_HIGH_MIN,
        "burst_count": Config.BURST_COUNT_THRESHOLD,
        "burst_window": Config.BURST_WINDOW_SECONDS,
        "multiple_users": Config.MULTIPLE_USERNAMES_THRESHOLD,
        "http_burst": Config.HTTP_ERROR_BURST_THRESHOLD,
        "biz_start": Config.BUSINESS_HOURS_START,
        "biz_end": Config.BUSINESS_HOURS_END,
    }
}


def load_and_analyze(content: str, filename: str):
    """Parses log content, runs detection engine, and stores in session."""
    parser = MasterParser(default_year=app.config['DEFAULT_YEAR'], timezone=app.config['TIMEZONE'])
    events, stats = parser.parse_content(content)

    t = SESSION_DATA["thresholds"]
    detector = DetectionEngine(
        failed_low_min=t["failed_low"],
        failed_med_min=t["failed_med"],
        failed_high_min=t["failed_high"],
        burst_count=t["burst_count"],
        burst_window_seconds=t["burst_window"],
        multiple_users_threshold=t["multiple_users"],
        http_burst_threshold=t["http_burst"],
        business_start=t["biz_start"],
        business_end=t["biz_end"],
    )
    analysis = detector.analyze(events)

    SESSION_DATA["filename"] = filename
    SESSION_DATA["events"] = events
    SESSION_DATA["stats"] = stats.to_dict()
    SESSION_DATA["analysis"] = analysis


# Initialize with default sample log on startup
default_sample_path = os.path.join(app.config['SAMPLES_FOLDER'], "mixed_sample.log")
if os.path.exists(default_sample_path):
    with open(default_sample_path, "r", encoding="utf-8", errors="replace") as f:
        load_and_analyze(f.read(), "mixed_sample.log")


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/')
def index():
    """Upload and initial landing page with sample log triggers."""
    samples = [
        {"name": "normal_auth.log", "desc": "Legitimate enterprise authentications during business hours (Alice, Bob).", "badge": "BENIGN"},
        {"name": "brute_force_sample.log", "desc": "High-velocity SSH dictionary attack & bursts from 203.0.113.88.", "badge": "BRUTE FORCE"},
        {"name": "off_hours_sample.log", "desc": "Nighttime authentication attempts (02:14 - 05:22) and root access.", "badge": "OFF-HOURS"},
        {"name": "web_access_sample.log", "desc": "Web access logs with SQLi, Directory Traversal, and HTTP 401/403 bursts.", "badge": "EXPLOITS"},
        {"name": "mixed_sample.log", "desc": "Comprehensive multi-vector dataset with malformed lines and breach alerts.", "badge": "MULTI-VECTOR"},
    ]
    return render_template('index.html', samples=samples, current_file=SESSION_DATA["filename"])


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles file uploads with validation and error checking."""
    if 'logfile' not in request.files:
        flash('No file part selected in request.', 'error')
        return redirect(url_for('index'))

    file = request.files['logfile']
    if file.filename == '':
        flash('No file was selected for upload.', 'error')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        safe_name = secure_filename(file.filename)
        try:
            content = file.read().decode('utf-8', errors='replace')
            if not content.strip():
                flash('The uploaded log file is empty. Please upload a valid log file.', 'warning')
                return redirect(url_for('index'))

            load_and_analyze(content, safe_name)
            flash(f"Successfully processed '{safe_name}'! Detected: {SESSION_DATA['stats']['format_detected']}.", 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Error parsing log file: {str(e)}", 'error')
            return redirect(url_for('index'))
    else:
        flash('Invalid file format. Only sanitized .log and .txt files are supported.', 'error')
        return redirect(url_for('index'))


@app.route('/sample/<sample_name>')
def load_sample(sample_name):
    """Loads a pre-packaged synthetic sample log."""
    safe_name = secure_filename(sample_name)
    sample_path = os.path.join(app.config['SAMPLES_FOLDER'], safe_name)
    if os.path.exists(sample_path):
        with open(sample_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        load_and_analyze(content, safe_name)
        flash(f"Loaded synthetic dataset '{safe_name}'!", 'info')
        return redirect(url_for('dashboard'))
    else:
        flash(f"Sample '{safe_name}' not found.", 'error')
        return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """SOC Executive Dashboard displaying statistics, charts, and recent events."""
    a = SESSION_DATA["analysis"]
    stats = SESSION_DATA["stats"]
    events = SESSION_DATA["events"]

    # Recent events (first 10 for dashboard widget)
    recent_events = [e.to_dict() for e in events[:10]]

    # Incidents to dict
    incidents_dict = [inc.to_dict() for inc in a.get("incidents", [])]

    # Overall DEFCON level
    counts = a.get("severity_counts", {})
    if counts.get("CRITICAL", 0) > 0:
        defcon = {"level": "CRITICAL", "class": "defcon-critical", "label": "DEFCON 1 - CRITICAL BREACH RISK"}
    elif counts.get("HIGH", 0) > 0:
        defcon = {"level": "HIGH", "class": "defcon-high", "label": "DEFCON 2 - ELEVATED ATTACK SURFACE"}
    elif counts.get("MEDIUM", 0) > 0:
        defcon = {"level": "MEDIUM", "class": "defcon-medium", "label": "DEFCON 3 - SUSPICIOUS ANOMALIES"}
    else:
        defcon = {"level": "NOMINAL", "class": "defcon-low", "label": "DEFCON 5 - NORMAL OPERATIONS"}

    return render_template(
        'dashboard.html',
        filename=SESSION_DATA["filename"],
        total_events=a.get("total_events", 0),
        successful_logins=a.get("successful_logins", 0),
        failed_logins=a.get("failed_logins", 0),
        suspicious_ip_count=a.get("suspicious_ip_count", 0),
        detected_anomalies_count=a.get("detected_anomalies_count", 0),
        severity_counts=a.get("severity_counts", {}),
        top_suspicious_ips=a.get("top_suspicious_ips", [])[:5],
        recent_events=recent_events,
        incidents=incidents_dict[:5],
        stats=stats,
        hourly_activity=a.get("hourly_activity", {}),
        mitre_matrix=a.get("mitre_matrix", {}),
        defcon=defcon,
        quarantined_ips=SESSION_DATA["quarantined_ips"],
        thresholds=SESSION_DATA["thresholds"]
    )


@app.route('/events')
def events():
    """Security Events Explorer with full search and filtering."""
    all_events = [e.to_dict() for e in SESSION_DATA["events"]]

    ip_filter = request.args.get('ip', '').strip()
    user_filter = request.args.get('user', '').strip()
    event_type_filter = request.args.get('event_type', '').strip()
    status_filter = request.args.get('status', '').strip()
    query_search = request.args.get('q', '').strip()

    filtered = all_events
    if query_search:
        filtered = [
            e for e in filtered if (
                query_search.lower() in e["message"].lower() or
                query_search.lower() in e["source_ip"].lower() or
                query_search.lower() in e["username"].lower() or
                query_search.lower() in e["url"].lower()
            )
        ]
    if ip_filter:
        filtered = [e for e in filtered if ip_filter.lower() in e["source_ip"].lower()]
    if user_filter:
        filtered = [e for e in filtered if user_filter.lower() in e["username"].lower()]
    if event_type_filter and event_type_filter != "ALL":
        filtered = [e for e in filtered if e["event_type"] == event_type_filter]
    if status_filter and status_filter != "ALL":
        filtered = [e for e in filtered if e["auth_status"] == status_filter]

    filtered.sort(key=lambda x: x["timestamp"], reverse=True)

    return render_template(
        'events.html',
        events=filtered,
        total_count=len(all_events),
        filtered_count=len(filtered),
        ip_filter=ip_filter,
        user_filter=user_filter,
        event_type_filter=event_type_filter,
        status_filter=status_filter,
        query_search=query_search,
        filename=SESSION_DATA["filename"],
    )


@app.route('/incidents')
def incidents():
    """Detected Incidents and Anomalies page with MITRE matrix and containment controls."""
    a = SESSION_DATA["analysis"]
    all_incidents = [inc.to_dict() for inc in a.get("incidents", [])]

    sev_filter = request.args.get('severity', '').strip()
    filtered = all_incidents
    if sev_filter and sev_filter != "ALL":
        filtered = [inc for inc in filtered if inc["severity"] == sev_filter]

    return render_template(
        'incidents.html',
        incidents=filtered,
        total_count=len(all_incidents),
        filtered_count=len(filtered),
        sev_filter=sev_filter,
        severity_counts=a.get("severity_counts", {}),
        mitre_matrix=a.get("mitre_matrix", {}),
        quarantined_ips=SESSION_DATA["quarantined_ips"],
        filename=SESSION_DATA["filename"]
    )


@app.route('/investigate/<ip>')
def investigate_ip(ip):
    """Deep-dive SOC Threat Dossier for a specific IP address."""
    a = SESSION_DATA["analysis"]
    events = [e.to_dict() for e in SESSION_DATA["events"] if e.source_ip == ip]
    incidents = [inc.to_dict() for inc in a.get("incidents", []) if inc.source_ip == ip]
    ip_summary = a.get("ip_groups", {}).get(ip, None)

    if not ip_summary:
        flash(f"No activity records found for IP {ip}.", "warning")
        return redirect(url_for('dashboard'))

    return render_template(
        'investigate.html',
        ip=ip,
        summary=ip_summary,
        incidents=incidents,
        events=events,
        is_quarantined=(ip in SESSION_DATA["quarantined_ips"]),
        filename=SESSION_DATA["filename"]
    )


@app.route('/api/contain-ip', methods=['POST'])
def contain_ip():
    """Simulates one-click SOC containment & firewall rule generation for an IP."""
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "No IP provided"}), 400

    SESSION_DATA["quarantined_ips"].add(ip)
    iptables_cmd = f"iptables -A INPUT -s {ip} -j DROP"
    ufw_cmd = f"ufw deny from {ip}"
    powershell_cmd = f"New-NetFirewallRule -DisplayName 'Block_{ip}' -Direction Inbound -Action Block -RemoteAddress {ip}"

    return jsonify({
        "success": True,
        "ip": ip,
        "status": "QUARANTINED",
        "commands": {
            "iptables": iptables_cmd,
            "ufw": ufw_cmd,
            "powershell": powershell_cmd
        }
    })


@app.route('/api/reconfigure', methods=['POST'])
def reconfigure_thresholds():
    """Dynamically re-tunes thresholds and re-runs detection without page reload."""
    data = request.get_json() or {}
    t = SESSION_DATA["thresholds"]

    if "failed_high" in data:
        t["failed_high"] = int(data["failed_high"])
    if "burst_count" in data:
        t["burst_count"] = int(data["burst_count"])
    if "burst_window" in data:
        t["burst_window"] = int(data["burst_window"])

    # Re-run detection on existing parsed events
    detector = DetectionEngine(
        failed_low_min=t["failed_low"],
        failed_med_min=t["failed_med"],
        failed_high_min=t["failed_high"],
        burst_count=t["burst_count"],
        burst_window_seconds=t["burst_window"],
        multiple_users_threshold=t["multiple_users"],
        http_burst_threshold=t["http_burst"],
        business_start=t["biz_start"],
        business_end=t["biz_end"],
    )
    SESSION_DATA["analysis"] = detector.analyze(SESSION_DATA["events"])

    return jsonify({"success": True, "message": "Detection thresholds updated & engine re-calculated!"})


@app.route('/reports')
def reports():
    """Report Generation & Preview Page."""
    a = SESSION_DATA["analysis"]
    events = SESSION_DATA["events"]
    filename = SESSION_DATA["filename"]

    generator = ReportGenerator(a, events, filename=filename)
    md_content = generator.generate_markdown()
    txt_content = generator.generate_text()

    return render_template(
        'reports.html',
        filename=filename,
        md_content=md_content,
        txt_content=txt_content,
        analysis=a
    )


@app.route('/export/<format_type>')
def export_report(format_type):
    """Exports and downloads reports in Markdown, Plaintext, or CSV."""
    a = SESSION_DATA["analysis"]
    events = SESSION_DATA["events"]
    filename = SESSION_DATA["filename"]
    base_name = os.path.splitext(filename)[0]

    generator = ReportGenerator(a, events, filename=filename)

    if format_type == "markdown":
        content = generator.generate_markdown()
        return Response(
            content,
            mimetype="text/markdown",
            headers={"Content-Disposition": f"attachment;filename=Security_Report_{base_name}.md"}
        )
    elif format_type == "text":
        content = generator.generate_text()
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment;filename=Security_Report_{base_name}.txt"}
        )
    elif format_type == "csv":
        content = generator.generate_csv()
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=Security_Incidents_{base_name}.csv"}
        )
    else:
        flash("Unsupported export format.", "error")
        return redirect(url_for('reports'))


@app.route('/about')
def about():
    """About page outlining methodology, MITRE ATT&CK mappings, and architecture."""
    return render_template('about.html')


@app.route('/api/stats')
def api_stats():
    """JSON API endpoint for dynamic dashboard chart updates."""
    a = SESSION_DATA["analysis"]
    return jsonify({
        "total_events": a.get("total_events", 0),
        "failed_logins": a.get("failed_logins", 0),
        "successful_logins": a.get("successful_logins", 0),
        "severity_counts": a.get("severity_counts", {}),
        "hourly_activity": a.get("hourly_activity", {}),
        "mitre_matrix": a.get("mitre_matrix", {}),
    })


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
