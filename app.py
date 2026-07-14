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
    GET  /downloads/filename        → Serve generated PDFs

Owner: Member 4 (PHASE 4 wiring by integration agent)
"""

# Load .env before anything else reads config — including the transitive
# imports below (integration -> red_report reads os.getenv(...) at its own
# module level). No need to `source .env` first; real exported env vars still
# win (load_env uses override=False), and this degrades to a no-op if
# python-dotenv isn't installed.
from engine.env import load_env
load_env()

import os
import json
import uuid
import secrets
import threading
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_file, render_template, Response
from flask_cors import CORS

from log_ingestor import ingest_log_file, fetch_wazuh_alerts

# Spine: persistent scan store (queue + status + history) over the unified
# orchestrator (modules.scan.run_scan). The dashboard's RED OPS view drives
# this; scope is authorized per-scan from the operator's attestation in the UI.
from storage import scan_store
from engine.scope import ScopeConfig, ScopeError

# PDF report generation (red/blue) and the legacy integration pipeline depend on
# weasyprint/markdown, which need system libraries that may be absent in a given
# environment. They are LEAF features — the console (spine-backed scans + SIEM
# ingest) must boot without them, so import lazily/gracefully and degrade the
# specific routes that need them rather than failing the whole app.
try:
    from integration import run_full_scan, get_scan_status, _scan_status
    _HAS_INTEGRATION = True
except Exception as _exc:                     # noqa: BLE001 - optional pipeline
    _HAS_INTEGRATION = False
    _INTEGRATION_ERR = str(_exc)

app = Flask(__name__)
CORS(app)

OUTPUTS_DIR = Path("outputs")
OUTPUTS_DIR.mkdir(exist_ok=True)

# ─── HTTP Basic Auth gate ──────────────────────────────────
# The console is a pentest control surface; when exposed on a network it must not
# be open. Credentials come from the environment (REDSEE_DASH_USER / _PASS, loaded
# from .env). Auth is enforced whenever a password is configured; if none is set
# (local dev), the gate is a no-op so the app still runs without credentials.
_DASH_USER = os.environ.get("REDSEE_DASH_USER", "admin")
_DASH_PASS = os.environ.get("REDSEE_DASH_PASS", "")


@app.before_request
def _require_basic_auth():
    if not _DASH_PASS:
        return None                       # no password configured → auth disabled (dev)
    auth = request.authorization
    ok = (
        auth is not None
        and (auth.type or "").lower() == "basic"
        and secrets.compare_digest(auth.username or "", _DASH_USER)
        and secrets.compare_digest(auth.password or "", _DASH_PASS)
    )
    if ok:
        return None
    return Response(
        "RedSee console — authentication required.",
        401, {"WWW-Authenticate": 'Basic realm="RedSee Security Operations Console"'},
    )

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

    if not _HAS_INTEGRATION:
        return jsonify({"error": "The legacy scan pipeline is unavailable here. Use the RED OPS console (POST /api/scans)."}), 503

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
    # Background thread calls integration.run_full_scan(); status updates pushed to integration._scan_status
    thread = threading.Thread(
        target=_run_scan_background,
        args=(scan_id, target_url),
        daemon=True
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "in_progress"})


# ─── SPINE API: persistent scan queue / status / history ───
# The RED OPS dashboard runs on these (storage.scan_store over modules.scan.run_scan),
# not the legacy /scan route above. Authorization is attested per-scan in the UI and
# enforced by engine.scope BEFORE anything is queued — an unauthorized target is refused.

@app.route("/api/scans", methods=["POST"])
def api_create_scan():
    """Body: { "target_url": "http://host:port/", "authorized": true, "mode": "standard" }
    Returns: { "scan_id": "...", "status": "queued", "mode": "..." } — 403 if not authorized/in scope."""
    data = request.get_json(silent=True) or {}
    target_url = (data.get("target_url") or "").strip()
    authorized = bool(data.get("authorized"))
    # Scan mode tunes breadth/depth/recon; an unknown value degrades to standard
    # inside the orchestrator, so accept it here and let the spine normalize.
    mode = (data.get("mode") or "standard").strip().lower()
    if mode not in ("fast", "standard", "deep"):
        mode = "standard"
    if not target_url:
        return jsonify({"error": "A target URL is required."}), 400

    host = urlparse(target_url).hostname
    if not host:
        return jsonify({"error": "Could not read a host from that URL. Include the scheme, e.g. http://host:3000/"}), 400

    # The operator's authorization attestation + the target's own host become the
    # scope for this scan (allow-list of exactly one host). enqueue_scan gates on it.
    scope = ScopeConfig(target_url=target_url, allowed_hosts=[host], authorized=authorized)
    try:
        scan_id = scan_store.enqueue_scan(target_url, scope_config=scope, mode=mode)
    except ScopeError as exc:
        return jsonify({"error": str(exc)}), 403
    return jsonify({"scan_id": scan_id, "status": "queued", "mode": mode}), 201


@app.route("/api/scans")
def api_list_scans():
    """Returns: { "scans": [ ...summary rows, newest first... ] }"""
    try:
        limit = min(200, max(1, int(request.args.get("limit", 50))))
    except (TypeError, ValueError):
        limit = 50
    status = request.args.get("status") or None
    return jsonify({"scans": scan_store.list_scans(limit=limit, status=status)})


@app.route("/api/scans/<scan_id>")
def api_get_scan(scan_id):
    """Returns the summary row + the full scan_<id>.json record under "scan"."""
    row = scan_store.get_scan(scan_id)
    if row is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(row)


# ─── ROUTE: Scan Status ────────────────────────────────────
@app.route("/scan/<scan_id>/status")
def scan_status(scan_id):
    """
    Returns: {
        "status": "crawling|testing_sqli|testing_xss|testing_idor|testing_auth|generating_report|done|error",
        "findings_count": 5,
        "current_module": "IDOR"
    }

    Reads live status from integration._scan_status via get_scan_status().
    """
    if not _HAS_INTEGRATION:
        return jsonify({"error": "Legacy scan status is unavailable here. Use GET /api/scans/<id>."}), 503
    status_data = get_scan_status(scan_id)
    if status_data.get("status") == "not_found":
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "status": status_data.get("status", "unknown"),
        "findings_count": status_data.get("findings_count", 0),
        "current_module": status_data.get("current_module", ""),
        "report_path": status_data.get("report_path"),
        "error": status_data.get("error")
    })


# ─── ROUTE: Scan Findings ──────────────────────────────────
@app.route("/scan/<scan_id>/findings")
def scan_findings(scan_id):
    """Returns: { "findings": [ ...Finding dicts... ] }

    Reads findings from outputs/findings_{scan_id}.json (saved by integration.run_full_scan).
    Falls back to in-memory cache if file is missing.
    """
    findings_path = OUTPUTS_DIR / f"findings_{scan_id}.json"
    if findings_path.exists():
        with open(findings_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        return jsonify({"findings": findings})

    # Fallback to in-memory cache (mock/test scans)
    scan = scans.get(scan_id)
    if scan is not None:
        return jsonify({"findings": scan.get("findings", [])})

    return jsonify({"findings": [], "error": "Scan not found"}), 404

# ─── ROUTE: Generate Red Team Report ──────────────────────
@app.route("/scan/<scan_id>/report", methods=["POST"])
def generate_report(scan_id):
    """Returns: { "report_url": "/downloads/red_report_<scan_id>.pdf" }

    Reads findings from outputs/findings_{scan_id}.json and calls
    red_report.generate_red_report() to produce the PDF.
    """
    findings_path = OUTPUTS_DIR / f"findings_{scan_id}.json"
    findings: list[dict] = []

    if findings_path.exists():
        with open(findings_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
    else:
        # Fallback to in-memory cache
        scan = scans.get(scan_id)
        if scan is not None:
            findings = scan.get("findings", [])

    if not findings:
        return jsonify({"error": "No findings available for this scan"}), 400

    try:
        from red_report import generate_red_report   # lazy: needs weasyprint/markdown
    except Exception as exc:                          # noqa: BLE001
        return jsonify({"error": f"PDF generation is unavailable in this environment: {exc}"}), 503

    try:
        report_path = generate_red_report(findings, scan_id=scan_id)
        filename = Path(report_path).name
        return jsonify({"report_url": f"/downloads/{filename}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── ROUTE: Upload & Analyze SIEM Logs ────────────────────
@app.route("/analyze-logs", methods=["POST"])
def analyze_logs():
    """
    Accepts: multipart/form-data with 'file' OR JSON body with 'events'
    Returns: { "analysis_id": "xyz789", "event_count": 10, "events": [...] }
    """
    analysis_id = str(uuid.uuid4())[:8]

    try:
        if "file" in request.files:
            file = request.files["file"]
            if not file.filename:
                return jsonify({"error": "Empty filename"}), 400

            # Save to temp file with safe suffix
            suffix = Path(file.filename).suffix or ".json"
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix=f"redsee_logs_{analysis_id}_")
            os.close(tmp_fd)
            file.save(tmp_path)

            try:
                events = ingest_log_file(tmp_path)
                events_dicts = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        elif request.is_json:
            # Allow inline events JSON (already normalized or raw)
            payload = request.get_json() or {}
            events_in = payload.get("events", [])
            if not events_in:
                return jsonify({"error": "No events data provided"}), 400

            # Save to temp file and re-ingest so the same parser handles both formats
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix=f"redsee_logs_{analysis_id}_")
            os.close(tmp_fd)
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(events_in, fh)
            try:
                events = ingest_log_file(tmp_path)
                events_dicts = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        else:
            return jsonify({"error": "No file or JSON data provided"}), 400

        blue_analyses[analysis_id] = {
            "events": events_dicts,
            "event_count": len(events_dicts),
            "report_path": None
        }

        return jsonify({
            "analysis_id": analysis_id,
            "event_count": len(events_dicts),
            "events": events_dicts
        })

    except ValueError as ve:
        return jsonify({"error": str(ve), "event_count": 0, "events": []}), 400
    except Exception as e:
        return jsonify({"error": str(e), "event_count": 0, "events": []}), 500
@app.route("/fetch-wazuh-alerts", methods=["POST"])
def fetch_wazuh_alerts_route():
    """
    Body:    { "minutes": 30 }
    Returns: { "analysis_id": "xyz789", "event_count": 12, "events": [...] }
    """
    from log_ingestor import fetch_wazuh_alerts as _fetch_wazuh
    data = request.get_json() or {}
    minutes = int(data.get("minutes", 30))
    analysis_id = str(uuid.uuid4())[:8]

    try:
        events = _fetch_wazuh(minutes=minutes)
        events_dicts = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]

        blue_analyses[analysis_id] = {
            "events": events_dicts,
            "event_count": len(events_dicts),
            "report_path": None
        }

        return jsonify({
            "analysis_id": analysis_id,
            "event_count": len(events_dicts),
            "events": events_dicts
        })

    except (ConnectionError, ValueError) as wazuh_err:
        # Wazuh unreachable or auth failure — return 500 JSON (no unhandled exception)
        return jsonify({
            "error": f"Wazuh fetch failed: {wazuh_err}",
            "event_count": 0,
            "events": []
        }), 500
    except Exception as e:
        return jsonify({"error": str(e), "event_count": 0, "events": []}), 500


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

        try:
            from blue_report import generate_blue_report   # lazy: needs weasyprint/markdown
        except Exception as imp_err:                        # noqa: BLE001
            return jsonify({"error": f"PDF generation is unavailable in this environment: {imp_err}"}), 503

        try:
            report_path = generate_blue_report(events, report_id=analysis_id)
        except Exception as gen_err:
            return jsonify({"error": f"PDF generation failed: {gen_err}"}), 500

        filename = Path(report_path).name

        if analysis_id in blue_analyses:
            blue_analyses[analysis_id]["report_path"] = filename

        return jsonify({"report_url": f"/downloads/{filename}"})

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
    Run the real red-team pipeline via integration.run_full_scan().

    Status updates are pushed into integration._scan_status by run_full_scan;
    app.py /scan/<id>/status reads from there via get_scan_status().
    Findings are written to outputs/findings_{scan_id}.json by run_full_scan;
    app.py /scan/<id>/findings reads from that path.
    """
    # Seed local cache so polling has a target the moment the thread starts
    scans[scan_id] = {
        "status": "starting",
        "target_url": target_url,
        "findings": [],
        "findings_count": 0,
        "current_module": "",
        "report_path": None,
        "error": None
    }

    try:
        result = run_full_scan(target_url, scan_id=scan_id)

        # Mirror result into local cache for any callers that prefer local state
        scans[scan_id].update({
            "status": "done",
            "findings": result.get("findings", []),
            "findings_count": result.get("findings_count", 0),
            "report_path": result.get("report_path")
        })
    except Exception as e:
        # run_full_scan already pushed status="error" into integration._scan_status
        scans[scan_id].update({"status": "error", "error": str(e)})
        print(f"[app.py] Background scan {scan_id} error: {e}")


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
