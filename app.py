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
from flask import (
    Flask, request, jsonify, send_file, render_template, Response,
    session, redirect, url_for,
)
from flask_cors import CORS

from log_ingestor import (
    ingest_log_file, fetch_wazuh_alerts, WAZUH_ALERTS_DEFAULT_PATH,
)

# Default cap so a huge alerts.json (1000s of lines) never floods the UI in one
# ingest; the operator can override per-request via `last_n`.
_INGEST_DEFAULT_LAST_N = 500

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

# Signs the session cookie that carries the login flag. Set REDSEE_SECRET_KEY in
# .env to keep sessions valid across restarts; unset falls back to a per-process
# random key (every restart invalidates existing sessions — fine for dev).
app.secret_key = os.environ.get("REDSEE_SECRET_KEY") or secrets.token_hex(32)

OUTPUTS_DIR = Path("outputs")
OUTPUTS_DIR.mkdir(exist_ok=True)

# ─── Session login gate ────────────────────────────────────
# The console is a pentest control surface; when exposed on a network it must not
# be open. Credentials come from the environment (REDSEE_DASH_USER / _PASS, loaded
# from .env). Auth is enforced whenever a password is configured; if none is set
# (local dev), the gate is a no-op so the app still runs without credentials.
#
# Flow: public landing (/) → /login (form) → session["authed"] set → /console
# (the dashboard). Replaces the old browser-native HTTP Basic Auth (no more
# WWW-Authenticate popup); a signed Flask session cookie carries the auth state.
_DASH_USER = os.environ.get("REDSEE_DASH_USER", "admin")
_DASH_PASS = os.environ.get("REDSEE_DASH_PASS", "")

# Routes reachable without a session. Everything else requires login when a
# password is configured. /static/* is matched by prefix (see _wants_json_401).
_PUBLIC_PATHS = {"/", "/login", "/logout"}


def _check_credentials(username: str, password: str) -> bool:
    """Constant-time compare of both fields (same discipline the old Basic Auth
    used). Never reveals which field was wrong to the caller."""
    return (
        secrets.compare_digest(username or "", _DASH_USER)
        and secrets.compare_digest(password or "", _DASH_PASS)
    )


def _wants_json_401() -> bool:
    """An unauthenticated request should get a JSON 401 (not an HTML redirect)
    when it's an API/XHR/fetch call — otherwise fetch() would silently follow the
    redirect and receive the login HTML as a 200. True = return 401 JSON; False =
    redirect the browser to /login."""
    if request.path.startswith("/api/"):
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    # A genuine top-level browser navigation asks for text/html and (modern
    # browsers) sends Sec-Fetch-Mode: navigate. script.js's fetch() calls send
    # neither, so they fall through to the JSON branch.
    is_navigation = "text/html" in accept and \
        request.headers.get("Sec-Fetch-Mode", "navigate") == "navigate"
    return not is_navigation


@app.before_request
def _require_login():
    if not _DASH_PASS:
        return None                       # no password configured → auth disabled (dev)
    if request.path in _PUBLIC_PATHS or request.path.startswith("/static/"):
        return None
    if session.get("authed"):
        return None
    if _wants_json_401():
        return jsonify({"error": "Authentication required. Sign in at /login."}), 401
    return redirect(url_for("login"))

# In-memory state stores (no DB needed for prototype)
scans = {}           # scan_id → {status, findings, target_url, ...}
blue_analyses = {}   # analysis_id → {events, event_count, report_path}


# ─── ROUTE: Public landing page ────────────────────────────
@app.route("/")
def home():
    """Public marketing/landing page. No auth."""
    return render_template("home.html")


# ─── ROUTE: Login / logout ─────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    """GET renders the login form; POST validates credentials and, on success,
    sets the session and redirects to the console. No auth required to reach it.
    On failure: a single generic error (never leaks which field was wrong)."""
    # If auth is disabled (dev) or already signed in, skip straight to the console.
    if not _DASH_PASS or session.get("authed"):
        return redirect(url_for("console"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if _check_credentials(username, password):
            session["authed"] = True
            return redirect(url_for("console"))
        # Generic failure — do not reveal whether user or password was wrong.
        return render_template("login.html", error="Invalid credentials."), 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear the session and return to the public landing page."""
    session.clear()
    return redirect(url_for("home"))


# ─── ROUTE: Dashboard (console) ────────────────────────────
@app.route("/console")
def console():
    """The operations console (the single-page dashboard). Auth-gated by
    _require_login when a password is configured."""
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
    """Returns: { "report_url": "/downloads/red_report_<scan_id>.<ext>", "format": "pdf"|"html" }

    Prefers the unified outputs/scan_{scan_id}.json (D-024 — full target/mode/
    tools_run/recon context), falling back to the legacy outputs/findings_{scan_id}
    .json (bare findings array, e.g. from a standalone modules/sqli.py run) and
    then the in-memory cache, so any known scan_id can still get a report.

    Uses red_report.generate_deterministic_report — evidence-derived, NOT an LLM
    call — so this route needs neither weasyprint nor an LLM API key to succeed:
    it renders a PDF when weasyprint happens to be installed, else a self-
    contained HTML report. A scan with 0 findings still gets a real report (a
    clean result is a legitimate deliverable); only a scan with NO data at all
    (never ran / unknown id) is refused, with a clear reason — never a dead click.
    """
    scan_json_path = OUTPUTS_DIR / f"scan_{scan_id}.json"
    findings_path = OUTPUTS_DIR / f"findings_{scan_id}.json"

    record: dict | None = None
    if scan_json_path.exists():
        with open(scan_json_path, "r", encoding="utf-8") as f:
            record = json.load(f)
    elif findings_path.exists():
        with open(findings_path, "r", encoding="utf-8") as f:
            record = {"scan_id": scan_id, "findings": json.load(f)}
    else:
        # Fallback to in-memory cache (legacy /scan pipeline's own findings, if any).
        scan = scans.get(scan_id)
        if scan is not None and scan.get("findings"):
            record = {"scan_id": scan_id, "findings": scan.get("findings")}

    if record is None:
        return jsonify({"error": f"No scan data found for '{scan_id}' — it may "
                        "still be queued/running, or the id is unknown."}), 404

    try:
        from red_report import generate_deterministic_report   # lazy: only needs markdown (always present)
        report_path, fmt = generate_deterministic_report(record, scan_id=scan_id)
    except Exception as e:                            # noqa: BLE001 - never let this 500 opaquely
        return jsonify({"error": f"Report generation failed: {e}"}), 500

    filename = Path(report_path).name
    return jsonify({"report_url": f"/downloads/{filename}", "format": fmt})

# ─── ROUTE: Upload & Analyze SIEM Logs ────────────────────
@app.route("/analyze-logs", methods=["POST"])
def analyze_logs():
    """
    Ingest SIEM logs into normalized Event dicts (the shape the Blue tab feed
    expects). Three input modes:
      * multipart/form-data with 'file'  → parse the uploaded log (JSON or JSONL)
      * JSON body { "path": "..." }       → read a server-side log file; defaults
                                            to Wazuh's alerts.json when omitted
      * JSON body { "events": [...] }      → parse inline raw/normalized events

    Optional (JSON body or form field): "last_n" (default 500 — bounds a huge
    alerts.json), "minutes" (only alerts newer than N minutes).

    Returns: { "analysis_id": "xyz789", "event_count": 10, "events": [...] }
    """
    analysis_id = str(uuid.uuid4())[:8]

    def _as_int(val, default=None):
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    try:
        if "file" in request.files:
            file = request.files["file"]
            if not file.filename:
                return jsonify({"error": "Empty filename"}), 400

            last_n = _as_int(request.form.get("last_n"), _INGEST_DEFAULT_LAST_N)
            minutes = _as_int(request.form.get("minutes"), None)

            # Save to temp file with safe suffix
            suffix = Path(file.filename).suffix or ".json"
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix=f"redsee_logs_{analysis_id}_")
            os.close(tmp_fd)
            file.save(tmp_path)

            try:
                events = ingest_log_file(tmp_path, last_n=last_n, since_minutes=minutes)
                events_dicts = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        elif request.is_json:
            payload = request.get_json() or {}
            last_n = _as_int(payload.get("last_n"), _INGEST_DEFAULT_LAST_N)
            minutes = _as_int(payload.get("minutes"), None)
            events_in = payload.get("events")

            if events_in:
                # Inline events JSON (already normalized or raw). Save + re-ingest
                # so the same parser handles both formats.
                tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix=f"redsee_logs_{analysis_id}_")
                os.close(tmp_fd)
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    json.dump(events_in, fh)
                try:
                    events = ingest_log_file(tmp_path, last_n=last_n, since_minutes=minutes)
                    events_dicts = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
            else:
                # Server-side path — defaults to the live Wazuh alerts.json (JSONL).
                path = (payload.get("path") or WAZUH_ALERTS_DEFAULT_PATH).strip()
                try:
                    events = ingest_log_file(path, last_n=last_n, since_minutes=minutes)
                except FileNotFoundError:
                    return jsonify({"error": f"Log file not found on server: {path}",
                                    "event_count": 0, "events": []}), 404
                except PermissionError:
                    return jsonify({"error": f"Permission denied reading {path} "
                                    "(the console user needs read access to the Wazuh log).",
                                    "event_count": 0, "events": []}), 403
                events_dicts = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]
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
    Returns: { "report_url": "/downloads/blue_report_xyz789.<ext>", "format": "pdf"|"html" }

    Uses blue_report.generate_deterministic_blue_report — evidence-derived, NOT
    an LLM call — so this route needs neither weasyprint nor an LLM API key: it
    renders a PDF when weasyprint is installed, else a self-contained HTML report.
    The "Generate Blue Report" button therefore always produces a real file.
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
            from blue_report import generate_deterministic_blue_report  # lazy: only needs markdown
        except Exception as imp_err:                        # noqa: BLE001
            return jsonify({"error": f"Blue report generation is unavailable: {imp_err}"}), 503

        try:
            report_path, fmt = generate_deterministic_blue_report(events, report_id=analysis_id)
        except Exception as gen_err:
            return jsonify({"error": f"Blue report generation failed: {gen_err}"}), 500

        filename = Path(report_path).name

        if analysis_id in blue_analyses:
            blue_analyses[analysis_id]["report_path"] = filename

        return jsonify({"report_url": f"/downloads/{filename}", "format": fmt})

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
