"""
Flask Backend — API routes for RedSee web dashboard.

Routes:
    GET  /                          → Serves dashboard
    POST /scan                      → Start a new scan
    GET  /scan/<id>/status          → Poll scan progress
    GET  /scan/<id>/findings        → Get all findings
    POST /scan/<id>/report          → Generate red team PDF
    POST /analyze-logs              → Upload + parse SIEM logs
    POST /fetch-wazuh-alerts        → Fetch live Wazuh alerts
    POST /generate-blue-report      → Generate blue team PDF
    GET  /downloads/<filename>      → Serve generated PDFs

Owner: Member 4
"""

import os
import json
import uuid
import threading
from pathlib import Path
from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

OUTPUTS_DIR = Path("outputs")
OUTPUTS_DIR.mkdir(exist_ok=True)

# In-memory state stores (no DB needed for prototype)
scans = {}           # scan_id → {status, findings, target_url, ...}
blue_analyses = {}   # analysis_id → {events, event_count, report_path}


# ─── ROUTE: Dashboard ──────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ─── ROUTE: Start Scan ─────────────────────────────────────
@app.route("/scan", methods=["POST"])
def start_scan():
    """
    Body:    { "target_url": "https://..." }
    Returns: { "scan_id": "abc123", "status": "in_progress" }
    """
    data = request.get_json()
    if not data or not data.get("target_url", "").strip():
        return jsonify({"error": "target_url is required"}), 400

    target_url = data["target_url"].strip()
    scan_id = str(uuid.uuid4())[:8]

    scans[scan_id] = {
        "status": "starting",
        "target_url": target_url,
        "findings": [],
        "findings_count": 0,
        "current_module": "",
        "report_path": None,
        "error": None
    }

    # ── PHASE 1 STUB: simulate scan in background thread ──
    thread = threading.Thread(
        target=_run_scan_background,
        args=(scan_id, target_url),
        daemon=True
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "in_progress"})


# ─── ROUTE: Scan Status ────────────────────────────────────
@app.route("/scan/<scan_id>/status")
def scan_status(scan_id):
    """
    Returns: {
        "status": "crawling|testing_sqli|testing_xss|testing_idor|testing_auth|done|error",
        "findings_count": 5,
        "current_module": "IDOR"
    }
    """
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "status": scan["status"],
        "findings_count": scan["findings_count"],
        "current_module": scan.get("current_module", ""),
        "error": scan.get("error")
    })


# ─── ROUTE: Scan Findings ──────────────────────────────────
@app.route("/scan/<scan_id>/findings")
def scan_findings(scan_id):
    """Returns: { "findings": [ ...Finding dicts... ] }"""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({"findings": scan["findings"]})


# ─── ROUTE: Generate Red Team Report ──────────────────────
@app.route("/scan/<scan_id>/report", methods=["POST"])
def generate_report(scan_id):
    """Returns: { "report_url": "/downloads/red_report_abc123.pdf" }"""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if not scan["findings"]:
        return jsonify({"error": "No findings to report"}), 400

    try:
        # ── PHASE 1 STUB ── Replace in Phase 4:
        # from red_report import generate_red_report
        # report_path = generate_red_report(scan["findings"], scan_id=scan_id)
        mock_filename = f"red_report_{scan_id}.pdf"
        return jsonify({"report_url": f"/downloads/{mock_filename}",
                        "note": "stub — real PDF generation in Phase 4"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── ROUTE: Upload & Analyze SIEM Logs ────────────────────
@app.route("/analyze-logs", methods=["POST"])
def analyze_logs():
    """
    Accepts: multipart/form-data with 'file' OR JSON body
    Returns: { "analysis_id": "xyz789", "event_count": 10, "events": [...] }
    """
    analysis_id = str(uuid.uuid4())[:8]

    try:
        if "file" in request.files:
            file = request.files["file"]
            temp_path = OUTPUTS_DIR / f"temp_logs_{analysis_id}.json"
            file.save(str(temp_path))

            # ── PHASE 1 STUB ── Replace in Phase 4:
            # from log_ingestor import ingest_log_file
            # events = ingest_log_file(str(temp_path))
            events = _mock_events()
            temp_path.unlink(missing_ok=True)

        elif request.is_json:
            # ── PHASE 1 STUB ──
            events = _mock_events()
        else:
            return jsonify({"error": "No file or JSON data provided"}), 400

        blue_analyses[analysis_id] = {
            "events": events,
            "event_count": len(events),
            "report_path": None
        }

        return jsonify({
            "analysis_id": analysis_id,
            "event_count": len(events),
            "events": events
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── ROUTE: Fetch Live Wazuh Alerts ───────────────────────
@app.route("/fetch-wazuh-alerts", methods=["POST"])
def fetch_wazuh_alerts():
    """
    Body:    { "minutes": 30 }
    Returns: { "event_count": 12, "events": [...] }
    """
    data = request.get_json() or {}
    minutes = data.get("minutes", 30)
    analysis_id = str(uuid.uuid4())[:8]

    try:
        # ── PHASE 1 STUB ── Replace in Phase 4:
        # from log_ingestor import fetch_wazuh_alerts as wazuh_fetch
        # events = [e.to_dict() for e in wazuh_fetch(minutes=minutes)]
        events = _mock_events()

        blue_analyses[analysis_id] = {
            "events": events,
            "event_count": len(events),
            "report_path": None
        }

        return jsonify({
            "analysis_id": analysis_id,
            "event_count": len(events),
            "events": events
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── ROUTE: Generate Blue Team Report ─────────────────────
@app.route("/generate-blue-report", methods=["POST"])
def generate_blue_report_route():
    """
    Body:    { "analysis_id": "xyz789" } OR { "events": [...] }
    Returns: { "report_url": "/downloads/blue_report_xyz789.pdf" }
    """
    data = request.get_json() or {}

    try:
        analysis_id = data.get("analysis_id")
        if analysis_id and analysis_id in blue_analyses:
            events = blue_analyses[analysis_id]["events"]
        elif "events" in data:
            events = data["events"]
            analysis_id = str(uuid.uuid4())[:8]
        else:
            return jsonify({"error": "No events data provided"}), 400

        # ── PHASE 1 STUB ── Replace in Phase 4:
        # from blue_report import generate_blue_report
        # report_path = generate_blue_report(events, report_id=analysis_id)
        mock_filename = f"blue_report_{analysis_id}.pdf"

        if analysis_id in blue_analyses:
            blue_analyses[analysis_id]["report_path"] = mock_filename

        return jsonify({"report_url": f"/downloads/{mock_filename}",
                        "note": "stub — real PDF generation in Phase 4"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── ROUTE: Download PDF ───────────────────────────────────
@app.route("/downloads/<filename>")
def download_file(filename):
    """Serve generated PDF from outputs/ directory."""
    filepath = OUTPUTS_DIR / filename
    if not filepath.exists():
        return jsonify({"error": f"File not found: {filename}"}), 404
    return send_file(str(filepath.absolute()), as_attachment=True)


# ─── BACKGROUND SCAN WORKER ────────────────────────────────

def _run_scan_background(scan_id: str, target_url: str):
    """
    PHASE 1: Simulates the scan pipeline with mock data and delays.
    PHASE 4: Replace with real integration.run_full_scan() call.
    """
    import time

    try:
        # ── PHASE 1 STUB ──
        # Simulate scan pipeline progression
        stages = [
            ("crawling", "Crawler", 1.5),
            ("testing_sqli", "SQLi", 1.5),
            ("testing_xss", "XSS", 1.5),
            ("testing_idor", "IDOR", 1.5),
            ("testing_auth", "BrokenAuth", 1.5),
        ]

        mock_findings = _load_mock_findings()

        for status, module, delay in stages:
            scans[scan_id]["status"] = status
            scans[scan_id]["current_module"] = module
            time.sleep(delay)

        scans[scan_id].update({
            "status": "done",
            "findings": mock_findings,
            "findings_count": len(mock_findings),
            "current_module": "Complete"
        })

        # ── PHASE 4 REPLACEMENT ──
        # from integration import run_full_scan
        # result = run_full_scan(target_url, scan_id=scan_id)
        # scans[scan_id].update({
        #     "status": "done",
        #     "findings": result["findings"],
        #     "findings_count": result["findings_count"],
        # })

    except Exception as e:
        scans[scan_id].update({"status": "error", "error": str(e)})


# ─── STUB HELPERS ──────────────────────────────────────────

def _load_mock_findings() -> list[dict]:
    """Load mock findings — replaced in Phase 4 with real scan results."""
    mock_path = Path("sample_data/mock_findings.json")
    if mock_path.exists():
        with open(mock_path) as f:
            return json.load(f)

    # Inline fallback if mock_findings.json not yet committed by Member 1
    return [
        {
            "type": "IDOR", "url": "http://example.com/api/users/1",
            "parameter": "URL path ID (1 → 2)",
            "payload": "http://example.com/api/users/2",
            "evidence": "Accessed resource ID 2 without authorization. Got 200 OK with different data.",
            "severity": "High", "timestamp": "2025-06-01T14:35:00Z"
        },
        {
            "type": "BrokenAuth", "url": "http://example.com/login",
            "parameter": "username/password",
            "payload": "admin:admin",
            "evidence": "Default credentials accepted. Response: 302 redirect to dashboard.",
            "severity": "Critical", "timestamp": "2025-06-01T14:34:00Z"
        }
    ]


def _mock_events() -> list[dict]:
    """Return mock normalized SIEM events for Phase 1 stubs."""
    return [
        {
            "source": "Wazuh", "timestamp": "2025-06-01T14:32:00Z",
            "rule_id": "31103", "description": "SQL injection attempt detected",
            "severity_level": 12, "src_ip": "192.168.1.100",
            "target_url": "/vulnerabilities/sqli/?id=1'+OR+1%3D1--",
            "raw_payload": "id=1' OR 1=1--"
        },
        {
            "source": "Wazuh", "timestamp": "2025-06-01T14:34:00Z",
            "rule_id": "5720", "description": "Brute force — 50+ failed logins in 30s",
            "severity_level": 14, "src_ip": "192.168.1.100",
            "target_url": "/login.php", "raw_payload": ""
        }
    ]


# ─── APP STARTUP ───────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  RedSee — Starting Web Dashboard")
    print("=" * 60)
    print("Open: http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
