# integration.py
"""
Pipeline Orchestrator — connects crawler → vuln modules → report engine.
This is the central nervous system of RedSee.
Member 1 (Team Lead) owns this file. Do not modify without team lead approval.

Usage:
    from integration import run_full_scan, run_blue_analysis, get_scan_status

    # Red team flow:
    result = run_full_scan("http://localhost")
    pdf_path = result["report_path"]

    # Blue team flow:
    result = run_blue_analysis("path/to/wazuh_alerts.json")
    pdf_path = result["report_path"]
"""

import json
import uuid
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from schemas import Finding, Event, Sitemap, ScanResult
from red_report import generate_red_report
from blue_report import generate_blue_report

# ── Module imports with stub fallbacks ─────────────────
# Replace each try/except block's stub with the real import
# as members merge their code to main.

try:
    from crawler import crawl as _crawl_real
    _has_crawler = True
except ImportError:
    _has_crawler = False

try:
    from modules.sqli import scan_sqli as _scan_sqli_real
    _has_sqli = True
except ImportError:
    _has_sqli = False

try:
    from modules.xss import scan_xss as _scan_xss_real
    _has_xss = True
except ImportError:
    _has_xss = False

try:
    from modules.idor import scan_idor as _scan_idor_real
    _has_idor = True
except ImportError:
    _has_idor = False

try:
    from modules.auth import scan_auth as _scan_auth_real
    _has_auth = True
except ImportError:
    _has_auth = False

try:
    from log_ingestor import ingest_log_file as _ingest_real
    _has_ingestor = True
except ImportError:
    _has_ingestor = False


# ── Stubs (used when real module not available) ─────────

def _stub_crawl(target_url: str) -> Sitemap:
    """Stub crawler — returns a minimal sitemap for integration testing."""
    from schemas import Endpoint
    print(f"  [STUB] crawl({target_url}) — using stub response")
    return Sitemap(
        target_url=target_url,
        crawl_timestamp=datetime.now().isoformat() + "Z",
        endpoints=[
            Endpoint(url=f"{target_url}/vulnerabilities/sqli/", method="GET",
                     form_action="#", inputs=["id", "Submit"],
                     cookies_needed=["PHPSESSID", "security"], endpoint_type="form"),
            Endpoint(url=f"{target_url}/login.php", method="POST",
                     form_action="login.php", inputs=["username", "password"],
                     cookies_needed=[], endpoint_type="form"),
        ],
        total_pages=5, total_forms=3, total_api_endpoints=0
    )


def _stub_scan(module_name: str, endpoints: list) -> list[Finding]:
    """Generic stub scanner — returns one mock finding per module."""
    print(f"  [STUB] {module_name} scan — using stub response")
    url = endpoints[0].url if endpoints else "http://stub-target.com/"
    return [Finding(
        type=module_name, url=url, parameter="stub_param",
        payload="[STUB] no real scan performed",
        evidence=f"[STUB] Mock {module_name} finding for integration testing",
        severity="High", timestamp=datetime.now().isoformat() + "Z"
    )]


def _stub_ingest(log_file_path: str) -> list[Event]:
    """Stub log ingestor — returns mock events for integration testing."""
    print(f"  [STUB] ingest_log_file({log_file_path}) — using stub response")
    return [Event(
        source="Wazuh", timestamp=datetime.now().isoformat() + "Z",
        rule_id="31103", description="[STUB] SQL injection detected",
        severity_level=12, src_ip="192.168.1.100",
        target_url="/vulnerabilities/sqli/", raw_payload="id=1' OR 1=1--"
    )]


# ── Resolved callables ──────────────────────────────────
def _crawl(target_url: str) -> Sitemap:
    return _crawl_real(target_url) if _has_crawler else _stub_crawl(target_url)

def _scan_sqli(endpoints: list) -> list[Finding]:
    return _scan_sqli_real(endpoints) if _has_sqli else _stub_scan("SQLi", endpoints)

def _scan_xss(endpoints: list) -> list[Finding]:
    return _scan_xss_real(endpoints) if _has_xss else _stub_scan("XSS", endpoints)

def _scan_idor(endpoints: list) -> list[Finding]:
    return _scan_idor_real(endpoints) if _has_idor else _stub_scan("IDOR", endpoints)

def _scan_auth(endpoints: list) -> list[Finding]:
    return _scan_auth_real(endpoints) if _has_auth else _stub_scan("BrokenAuth", endpoints)

def _ingest_log_file(path: str) -> list[Event]:
    return _ingest_real(path) if _has_ingestor else _stub_ingest(path)


# ── Status tracking (for frontend polling) ─────────────
_scan_status: dict = {}


def get_scan_status(scan_id: str) -> dict:
    """Get current status of a running or completed scan. Used by app.py."""
    return _scan_status.get(scan_id, {"status": "not_found"})


def _update_status(scan_id: str, status: str, **kwargs):
    """Internal — update scan status dict for frontend polling."""
    if scan_id not in _scan_status:
        _scan_status[scan_id] = {}
    _scan_status[scan_id].update({"status": status, **kwargs})


# ── Red Team Pipeline ──────────────────────────────────
def run_full_scan(target_url: str, scan_id: str = None) -> dict:
    """
    Execute the complete red team pipeline:
    1. Crawl target → sitemap
    2. Run all vuln modules → findings
    3. Merge findings → save JSON → generate red report PDF

    Args:
        target_url: Target URL to scan (e.g., "http://localhost")
        scan_id: Optional identifier. Auto-generated if not provided.

    Returns:
        {
            "scan_id": "abc123",
            "target_url": "http://...",
            "findings": [...],          # list of Finding dicts
            "findings_count": 5,
            "report_path": "outputs/red_report_abc123.pdf",
            "duration_seconds": 45.2
        }

    Raises:
        Exception: Re-raises after updating status to "error"
    """
    if not scan_id:
        scan_id = str(uuid.uuid4())[:8]

    start_time = time.time()
    all_findings: list[Finding] = []

    try:
        # Phase 1: Crawl
        _update_status(scan_id, "crawling", current_module="Crawler")
        print(f"\n[Scan {scan_id}] ── Phase 1: Crawling {target_url}...")
        sitemap = _crawl(target_url)
        endpoints = sitemap.endpoints
        print(f"[Scan {scan_id}]    Found {len(endpoints)} endpoints")

        # Phase 2: Vulnerability scanning — all four modules
        modules = [
            ("SQLi",       "testing_sqli",  _scan_sqli),
            ("XSS",        "testing_xss",   _scan_xss),
            ("IDOR",       "testing_idor",  _scan_idor),
            ("BrokenAuth", "testing_auth",  _scan_auth),
        ]

        for module_name, status_key, scan_func in modules:
            _update_status(scan_id, status_key, current_module=module_name)
            print(f"[Scan {scan_id}] ── Phase 2: Running {module_name}...")
            try:
                findings = scan_func(endpoints)
                all_findings.extend(findings)
                print(f"[Scan {scan_id}]    {module_name}: {len(findings)} finding(s)")
            except Exception as module_err:
                # Module failure is non-fatal — log and continue
                print(f"[Scan {scan_id}] ⚠️  {module_name} error (skipped): {module_err}")

        # Phase 3: Save findings JSON + generate report
        _update_status(scan_id, "generating_report", findings_count=len(all_findings))
        print(f"[Scan {scan_id}] ── Phase 3: Generating red team report ({len(all_findings)} findings)...")

        findings_dicts = [f.to_dict() if hasattr(f, 'to_dict') else f for f in all_findings]

        # Save findings JSON (used by app.py /scan/<id>/findings endpoint)
        findings_path = Path("outputs") / f"findings_{scan_id}.json"
        findings_path.parent.mkdir(exist_ok=True)
        with open(findings_path, 'w') as fh:
            json.dump(findings_dicts, fh, indent=2)

        report_path = generate_red_report(findings_dicts, scan_id=scan_id)
        duration = time.time() - start_time

        _update_status(scan_id, "done",
                       findings_count=len(all_findings),
                       report_path=report_path)

        print(f"[Scan {scan_id}] Complete in {round(duration, 1)}s — {report_path}")

        return {
            "scan_id": scan_id,
            "target_url": target_url,
            "findings": findings_dicts,
            "findings_count": len(all_findings),
            "report_path": report_path,
            "duration_seconds": round(duration, 1)
        }

    except Exception as e:
        _update_status(scan_id, "error", error=str(e))
        print(f"[Scan {scan_id}] Fatal error: {e}")
        raise


# ── Blue Team Pipeline ─────────────────────────────────
def run_blue_analysis(log_file_path: str, report_id: str = None) -> dict:
    """
    Execute the complete blue team pipeline:
    1. Ingest SIEM log file → events
    2. Generate defensive report → PDF

    Args:
        log_file_path: Path to Wazuh/Splunk JSON export file

    Returns:
        {
            "report_id": "xyz789",
            "event_count": 12,
            "events": [...],            # list of Event dicts
            "report_path": "outputs/blue_report_xyz789.pdf"
        }
    """
    if not report_id:
        report_id = str(uuid.uuid4())[:8]

    print(f"\n[Blue {report_id}] ── Step 1: Ingesting logs from {log_file_path}...")
    events = _ingest_log_file(log_file_path)
    print(f"[Blue {report_id}]    Parsed {len(events)} events")

    events_dicts = [e.to_dict() if hasattr(e, 'to_dict') else e for e in events]

    print(f"[Blue {report_id}] ── Step 2: Generating blue team report...")
    report_path = generate_blue_report(events_dicts, report_id=report_id)

    print(f"[Blue {report_id}] Complete — {report_path}")

    return {
        "report_id": report_id,
        "event_count": len(events_dicts),
        "events": events_dicts,
        "report_path": report_path
    }


# ── CLI Test ────────────────────────────────────────────
if __name__ == "__main__":
    # Load .env before anything reads config — no need to `source .env` first;
    # real exported env vars still win (load_env uses override=False).
    from engine.env import load_env
    load_env()

    print("=" * 60)
    print("RedSee — Integration Pipeline Test")
    print("=" * 60)

    print("\n[TEST] Red team pipeline (stub modules)...")
    red_result = run_full_scan("http://localhost", scan_id="integration_test_red")
    print(f"Red result: {red_result['findings_count']} findings → {red_result['report_path']}")

    print("\n[TEST] Blue team pipeline (raw Wazuh file)...")
    blue_result = run_blue_analysis("sample_data/sample_wazuh_alerts.json",
                                     report_id="integration_test_blue")
    print(f"Blue result: {blue_result['event_count']} events → {blue_result['report_path']}")

    print("\nIntegration test complete!")
    print(f"  Status tracker: {get_scan_status('integration_test_red')}")