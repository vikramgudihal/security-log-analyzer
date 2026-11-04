"""
Flask Web Application for Security Log Analyzer (CodeNova Task 4).
Full SOC-style interface featuring Dashboards, Event Filtering, Incident Inspection, and Report Generation.
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, send_file
from werkzeug.utils import secure_filename
from config import Config
from analyzer import MasterParser, DetectionEngine, ReportGenerator

app = Flask(__name__)
app.config.from_object(Config)

# Ensure required directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['SAMPLES_FOLDER'], exist_ok=True)

# In-memory storage for the active analysis session
SESSION_DATA = {
    "filename": "brute_force_sample.log",
    "events": [],
    "stats": {},
    "analysis": {},
}


def load_and_analyze(content: str, filename: str):
    """Parses log content, runs detection engine, and stores in session."""
    parser = MasterParser(default_year=app.config['DEFAULT_YEAR'], timezone=app.config['TIMEZONE'])
    events, stats = parser.parse_content(content)

    detector = DetectionEngine(
        failed_low_min=app.config['FAILED_LOGIN_LOW_MIN'],
        failed_med_min=app.config['FAILED_LOGIN_MED_MIN'],
        failed_high_min=app.config['FAILED_LOGIN_HIGH_MIN'],
        burst_count=app.config['BURST_COUNT_THRESHOLD'],
        burst_window_seconds=app.config['BURST_WINDOW_SECONDS'],
        multiple_users_threshold=app.config['MULTIPLE_USERNAMES_THRESHOLD'],
        http_burst_threshold=app.config['HTTP_ERROR_BURST_THRESHOLD'],
        business_start=app.config['BUSINESS_HOURS_START'],
        business_end=app.config['BUSINESS_HOURS_END'],
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
        {"name": "normal_auth.log", "desc": "Legitimate enterprise authentications during business hours (Alice, Bob)."},
        {"name": "brute_force_sample.log", "desc": "High-velocity SSH dictionary attack & bursts from 203.0.113.88."},
        {"name": "off_hours_sample.log", "desc": "Nighttime authentication attempts (02:14 - 05:22) and root access."},
        {"name": "web_access_sample.log", "desc": "Web access logs with SQLi, Directory Traversal, and HTTP 401/403 bursts."},
        {"name": "mixed_sample.log", "desc": "Comprehensive multi-vector dataset with malformed lines and breach alerts."},
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
        # Read content directly into memory (security: do not execute or persist permanently)
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
        hourly_activity=a.get("hourly_activity", {})
    )


@app.route('/events')
def events():
    """Security Events Explorer with full search and filtering."""
    all_events = [e.to_dict() for e in SESSION_DATA["events"]]

    # Filtering parameters from query string
    ip_filter = request.args.get('ip', '').strip()
    user_filter = request.args.get('user', '').strip()
    event_type_filter = request.args.get('event_type', '').strip()
    status_filter = request.args.get('status', '').strip()

    filtered = all_events
    if ip_filter:
        filtered = [e for e in filtered if ip_filter.lower() in e["source_ip"].lower()]
    if user_filter:
        filtered = [e for e in filtered if user_filter.lower() in e["username"].lower()]
    if event_type_filter and event_type_filter != "ALL":
        filtered = [e for e in filtered if e["event_type"] == event_type_filter]
    if status_filter and status_filter != "ALL":
        filtered = [e for e in filtered if e["auth_status"] == status_filter]

    # Sort recent first
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
        filename=SESSION_DATA["filename"],
    )


@app.route('/incidents')
def incidents():
    """Detected Incidents and Anomalies page."""
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
        filename=SESSION_DATA["filename"]
    )


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
    })


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
