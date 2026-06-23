"""
RedSee Standalone Scanner — Member 3
=====================================
Runs SQLi + XSS vulnerability scans against any target.
Can auto-discover endpoints or use a sitemap file.

Usage:
    python scanner.py                                    # Auto-discover + scan
    python scanner.py --target http://redsees.com:6696   # Specific target
    python scanner.py --sitemap sample_data/mock_sitemap.json
    python scanner.py --quick                            # Targeted endpoints only
"""

import sys, os, argparse, json, time
from datetime import datetime, timezone
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from schemas import Endpoint, Finding, Sitemap
from modules.sqli import scan_sqli
from modules.xss import scan_xss


def discover_endpoints(target_url: str) -> list:
    """
    Auto-discover injectable endpoints on target.
    Probes common paths for forms, search endpoints, APIs, and login pages.
    Returns list[Endpoint].
    """
    import requests as _req

    endpoints = []
    discovered = set()

    print(f"\n[🔍] Discovering endpoints on {target_url}...")

    # Common search/injection paths
    probes = [
        # REST API patterns
        ("GET", "/rest/products/search", ["q"]),
        ("GET", "/api/Search", ["q"]),
        ("GET", "/api/search", ["q"]),
        ("GET", "/search", ["q", "query", "s"]),
        ("GET", "/api/products", []),
        ("GET", "/rest/user/login", []),
        # Traditional form patterns
        ("POST", "/login", ["username", "password", "email"]),
        ("POST", "/login.php", ["username", "password"]),
        ("POST", "/signin", ["username", "password", "email"]),
        ("POST", "/auth/login", ["username", "password"]),
        ("GET", "/vulnerabilities/sqli/", ["id", "Submit"]),
        ("GET", "/vulnerabilities/sqli_blind/", ["id", "Submit"]),
        ("GET", "/vulnerabilities/xss_r/", ["name", "Submit"]),
        ("POST", "/vulnerabilities/xss_s/", ["txtName", "mtxMessage", "btnSign"]),
        # Feedback/comment forms (XSS targets)
        ("POST", "/api/Feedbacks", ["comment", "rating"]),
        ("POST", "/rest/user/register", ["email", "password"]),
        ("POST", "/api/contact", ["name", "message", "email"]),
        # Admin
        ("GET", "/rest/admin/application-version", []),
    ]

    for method, path, inputs in probes:
        full_url = target_url.rstrip("/") + path
        if full_url in discovered:
            continue
        discovered.add(full_url)

        try:
            if method == "GET":
                r = _req.get(full_url, timeout=5, allow_redirects=True)
            else:
                r = _req.options(full_url, timeout=5) if True else None
                r = _req.post(full_url, timeout=5, allow_redirects=True)

            status = r.status_code
            ct = r.headers.get("Content-Type", "")

            if status not in (404, 405, 501):
                # Auto-detect input params from GET params if none provided
                if not inputs and "?" in full_url:
                    import urllib.parse
                    parsed = urllib.parse.urlparse(full_url)
                    qp = urllib.parse.parse_qs(parsed.query)
                    inputs = list(qp.keys())

                ep_type = "api" if "json" in ct else ("form" if method == "POST" else "page")

                ep = Endpoint(
                    url=full_url,
                    method=method,
                    form_action=None,
                    inputs=inputs if inputs else _extract_inputs_from_body(r.text),
                    cookies_needed=[],
                    endpoint_type=ep_type,
                )
                endpoints.append(ep)
                input_count = len(ep.inputs)
                print(f"  [{status}] {method:4s} {full_url} ({input_count} inputs)")

        except Exception:
            pass

    # Also probe form actions from the homepage
    try:
        r = _req.get(target_url, timeout=10)
        if "html" in r.headers.get("Content-Type", ""):
            import re as _re
            # Extract form actions
            forms = _re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', r.text, _re.IGNORECASE)
            # Extract input names
            inputs_found = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', r.text, _re.IGNORECASE)

            for action in forms[:5]:
                full_url = action if action.startswith("http") else target_url.rstrip("/") + "/" + action.lstrip("/")
                if full_url not in discovered:
                    discovered.add(full_url)
                    ep = Endpoint(
                        url=full_url,
                        method="POST",
                        form_action=action,
                        inputs=inputs_found[:10],
                        cookies_needed=[],
                        endpoint_type="form",
                    )
                    endpoints.append(ep)
                    print(f"  [form] POST {full_url} ({len(ep.inputs)} inputs)")
    except Exception:
        pass

    print(f"  → Discovered {len(endpoints)} endpoints\n")
    return endpoints


def _extract_inputs_from_body(html_body: str) -> list:
    """Extract input field names from HTML."""
    import re as _re
    names = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html_body, _re.IGNORECASE)
    return list(set(names))[:15] if names else []


def run_scan(target_url: str, sitemap_path: Optional[str] = None, quick: bool = False):
    """Main scan entry point."""
    start_time = time.time()

    print("\n" + "=" * 65)
    print("  RedSee — Vulnerability Scanner (Member 3)")
    print(f"  Target: {target_url}")
    print(f"  Time:   {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print("=" * 65)

    # Load or discover endpoints
    if sitemap_path and os.path.exists(sitemap_path):
        print(f"\n[📂] Loading sitemap from {sitemap_path}")
        sitemap = Sitemap.from_json(sitemap_path)
        endpoints = sitemap.endpoints
    elif quick:
        # Quick mode: target only key injection points
        endpoints = discover_endpoints(target_url)
        # Filter to only endpoints with inputs
        endpoints = [e for e in endpoints if e.inputs]
    else:
        endpoints = discover_endpoints(target_url)

    if not endpoints:
        print("\n⚠️  No testable endpoints found. Try --sitemap with a sitemap file.")
        return

    print(f"[📋] {len(endpoints)} endpoints to scan")

    # Run SQLi scan
    print(f"\n{'─'*65}")
    sql_start = time.time()
    sqli_findings = scan_sqli(endpoints)
    sql_elapsed = time.time() - sql_start

    # Run XSS scan
    print(f"\n{'─'*65}")
    xss_start = time.time()
    xss_findings = scan_xss(endpoints)
    xss_elapsed = time.time() - xss_start

    total_elapsed = time.time() - start_time
    all_findings = sqli_findings + xss_findings

    # ── Results ──
    print(f"\n{'='*65}")
    print(f"  SCAN COMPLETE")
    print(f"  Duration: {total_elapsed:.1f}s (SQLi: {sql_elapsed:.1f}s, XSS: {xss_elapsed:.1f}s)")
    print(f"  Total vulnerabilities: {len(all_findings)}")
    print(f"  {'='*65}")

    if not all_findings:
        print("\n  ✅ No vulnerabilities detected on this target.")
        print("     Note: This may indicate the target is secure or unreachable")
        print("     with the current authentication level.\n")
        return

    # Group by severity
    by_severity = {}
    for f in all_findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in ("Critical", "High", "Medium", "Low"):
        items = by_severity.get(sev, [])
        if items:
            print(f"\n  [{sev}] — {len(items)} finding(s)")
            for f in items:
                print(f"    🔴 {f.type:5s} | {f.url}")
                print(f"       Parameter: {f.parameter}")
                print(f"       Payload:   {f.payload[:80]}")
                print(f"       Evidence:  {f.evidence[:120]}")

    # Schema validation
    print(f"\n{'─'*65}")
    print("  Schema Validation:")
    errors = 0
    for f in all_findings:
        assert isinstance(f, Finding), f"Not a Finding: {type(f)}"
        d = f.to_dict()
        assert d["type"] in ("SQLi", "XSS"), f"Bad type: {d['type']}"
        assert d["severity"] in ("Critical", "High", "Medium", "Low"), f"Bad severity: {d['severity']}"
        assert d["timestamp"].endswith("Z"), f"Bad timestamp: {d['timestamp']}"
        required = {"type", "url", "parameter", "payload", "evidence", "severity", "timestamp"}
        missing = required - set(d.keys())
        assert not missing, f"Missing keys: {missing}"
    print(f"  ✅ All {len(all_findings)} findings pass schema validation")

    # Integration contract check
    print(f"\n{'─'*65}")
    print("  Integration Contract (Member 1):")
    print(f"    from modules.sqli import scan_sqli  → {len(sqli_findings)} findings")
    print(f"    from modules.xss import scan_xss    → {len(xss_findings)} findings")
    print(f"    all_findings = sqli_findings + xss_findings  → {len(all_findings)} total")
    print(f"  {'='*65}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RedSee Vulnerability Scanner")
    parser.add_argument("--target", default=os.getenv("TARGET_URL", "http://localhost"),
                        help="Target URL to scan")
    parser.add_argument("--sitemap", help="Path to sitemap JSON file")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan (only targeted injection points)")
    parser.add_argument("--sqli-only", action="store_true", help="SQLi scan only")
    parser.add_argument("--xss-only", action="store_true", help="XSS scan only")

    args = parser.parse_args()

    if args.sqli_only:
        endpoints = discover_endpoints(args.target)
        sqli_findings = scan_sqli(endpoints)
        print(f"\n📋 {len(sqli_findings)} SQLi finding(s)")
        for f in sqli_findings:
            print(f"  🔴 [{f.severity}] {f.url} → '{f.parameter}': {f.evidence[:100]}")
    elif args.xss_only:
        endpoints = discover_endpoints(args.target)
        xss_findings = scan_xss(endpoints)
        print(f"\n📋 {len(xss_findings)} XSS finding(s)")
        for f in xss_findings:
            print(f"  🟠 [{f.severity}] {f.url} → '{f.parameter}': {f.evidence[:100]}")
    else:
        run_scan(args.target, args.sitemap, args.quick)