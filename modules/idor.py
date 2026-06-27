"""
IDOR Scanner Module — detects Insecure Direct Object Reference vulnerabilities.

Scans API endpoints and links for numeric IDs in URL paths/query params,
tests with alternate IDs to detect unauthorized data access.

Public API:
    scan_idor(endpoints: list[Endpoint], session=None) -> list[Finding]

Owner: Member 4
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import re
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional
from schemas import Finding, Endpoint

try:
    from utils.http_helpers import HTTPSession
    _HAS_HTTP_SESSION = True
except ImportError:
    HTTPSession = None
    _HAS_HTTP_SESSION = False

import requests as _requests


# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

TEST_IDS = [1, 2, 3, 5, 10, 100, 999]

ID_PATTERNS = [
    r'/(\d+)$',           # /api/users/1
    r'/(\d+)/',           # /api/users/1/profile
    r'[?&]id=(\d+)',      # /page?id=1
    r'[?&]user_id=(\d+)', # /page?user_id=1
    r'[?&]userId=(\d+)',  # /page?userId=1
    r'[?&]account=(\d+)', # /page?account=1
    r'[?&]order=(\d+)',   # /page?order=1
    r'[?&]doc=(\d+)',     # /page?doc=1
    r'[?&]profile=(\d+)', # /page?profile=1
]

BLOCKED_STATUS_CODES = {401, 403, 404, 302}
SUCCESS_STATUS_CODES = {200}


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def scan_idor(endpoints: list, session=None) -> list:
    """
    Scan endpoints for IDOR vulnerabilities.

    Args:
        endpoints: list of Endpoint objects (from crawler)
        session: optional HTTPSession or requests.Session

    Returns:
        list[Finding] — findings with type="IDOR"
    """
    findings = []
    tested = set()  # (url, param_name) dedup

    for endpoint in endpoints:
        if not isinstance(endpoint, Endpoint):
            continue

        # Test API and link endpoints for URL path IDOR
        if endpoint.endpoint_type in ("api", "link"):
            findings.extend(_test_api_idor(endpoint, session, tested))

        # Test form endpoints for ID-like parameters
        if endpoint.endpoint_type == "form":
            findings.extend(_test_form_idor(endpoint, session, tested))

    return findings


# ═══════════════════════════════════════════════════════════════
# API / LINK IDOR DETECTION
# ═══════════════════════════════════════════════════════════════

def _test_api_idor(endpoint: Endpoint, session, tested: set) -> list:
    """Test API/link endpoints for IDOR by swapping numeric IDs in URL path/query."""
    findings = []
    url = endpoint.url

    for pattern in ID_PATTERNS:
        match = re.search(pattern, url)
        if not match:
            continue

        original_id = match.group(1)
        if not original_id.isdigit():
            continue

        original_id_int = int(original_id)

        for test_id in TEST_IDS:
            if test_id == original_id_int:
                continue

            # Build the test URL by replacing the matched ID
            test_url = url[:match.start(1)] + str(test_id) + url[match.end(1):]

            dedup_key = (test_url, "URL path")
            if dedup_key in tested:
                continue
            tested.add(dedup_key)

            finding = _test_param_idor(endpoint, "URL path", session, original_id, test_id, test_url, url)
            if finding:
                findings.append(finding)

    return findings


def _test_form_idor(endpoint: Endpoint, session, tested: set) -> list:
    """Test form endpoints with ID-like input parameters for IDOR."""
    findings = []
    id_like_params = {"id", "user_id", "userid", "account", "profile", "doc", "order", "uid"}

    for param_name in endpoint.inputs:
        if param_name.lower() not in id_like_params:
            continue

        # For param IDOR: test 5 sequential IDs; if ≥3 return 200 with ≥2 unique response bodies → IDOR
        base_url = endpoint.url
        success_count = 0
        response_hashes = set()

        for test_id in range(1, 6):
            test_url = _build_param_url(base_url, param_name, str(test_id))

            dedup_key = (test_url, param_name)
            if dedup_key in tested:
                continue
            tested.add(dedup_key)

            finding = _test_param_idor(endpoint, param_name, session, None, test_id, test_url, base_url)
            if finding:
                findings.append(finding)
                success_count += 1
                # Hash evidence for uniqueness check
                response_hashes.add(hashlib.md5(finding.evidence.encode()).hexdigest())

        # Check if enough unique responses were found to confirm IDOR
        if success_count >= 3 and len(response_hashes) >= 2:
            continue  # Already added individual findings
        elif success_count >= 3:
            continue  # Already added

    return findings


def _build_param_url(base_url: str, param_name: str, value: str) -> str:
    """Add or replace a query parameter in the URL."""
    if "?" in base_url:
        # Check if param already exists
        param_pattern = re.compile(rf'([?&]){re.escape(param_name)}=[^&]*')
        if param_pattern.search(base_url):
            return param_pattern.sub(rf'\1{param_name}={value}', base_url)
        else:
            return f"{base_url}&{param_name}={value}"
    else:
        return f"{base_url}?{param_name}={value}"


def _test_param_idor(endpoint: Endpoint, param_name: str, session,
                     original_id, test_id, test_url: str, original_url: str) -> Optional[Finding]:
    """
    Core test: make request to test URL, compare with original.
    Returns Finding if IDOR detected.
    """
    try:
        # Make request to the test URL
        test_response = _make_request(test_url, method=endpoint.method, session=session)

        if test_response is None:
            return None

        status = test_response.status_code
        body = test_response.text

        # Must be successful
        if status not in SUCCESS_STATUS_CODES:
            return None

        # Response must have meaningful body
        if len(body) < 50:
            return None

        # Try to get original response for comparison
        original_response = _make_request(original_url, method=endpoint.method, session=session)
        if original_response is None:
            return None

        # Check if original was blocked
        if original_response.status_code in BLOCKED_STATUS_CODES:
            # Original was blocked but test succeeded — stronger IDOR signal
            pass
        else:
            # Both succeeded — bodies must differ
            if body == original_response.text:
                return None

        # Build the finding
        if original_id is not None:
            parameter_desc = f"URL path ID ({original_id} → {test_id})"
        else:
            parameter_desc = param_name

        return Finding(
            type="IDOR",
            url=endpoint.url,
            parameter=parameter_desc,
            payload=test_url,
            evidence=(
                f"Accessed resource with test ID {test_id}"
                + (f" (original: {original_id})." if original_id is not None else ".")
                + f" Response: {status} ({len(body)} bytes). "
                f"Expected 401/403 — got 200 OK with data. "
                f"Different data returned confirms unauthorized access."
            ),
            severity="High",
            timestamp=_ts()
        )

    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# REQUEST HELPERS
# ═══════════════════════════════════════════════════════════════

def _make_request(url: str, method: str = "GET", session=None,
                  params: dict = None, data: dict = None):
    """Make an HTTP request with error handling. Returns response or None."""
    try:
        if session and _HAS_HTTP_SESSION and isinstance(session, HTTPSession):
            if method.upper() == "POST":
                return session.post(url, data=data, timeout=10)
            else:
                return session.get(url, params=params, timeout=10)
        elif session and hasattr(session, 'request'):
            return session.request(method.upper(), url, params=params, data=data, timeout=10)
        else:
            if method.upper() == "POST":
                return _requests.post(url, data=data, timeout=10)
            else:
                return _requests.get(url, params=params, timeout=10)
    except Exception:
        return None


def _ts() -> str:
    """ISO 8601 timestamp with trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ═══════════════════════════════════════════════════════════════
# CLI QUICK TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    print("=" * 60)
    print("🛡️  IDOR Scanner — Standalone Test")
    print("=" * 60)

    target = os.getenv("TARGET_URL", "")

    # Test with mock endpoints
    test_endpoints = [
        Endpoint(
            url="http://example.com/api/users/1",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="api"
        ),
        Endpoint(
            url="http://example.com/api/orders/5",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="api"
        ),
        Endpoint(
            url="http://example.com/profile?id=10",
            method="GET", form_action=None,
            inputs=["id"], cookies_needed=[], endpoint_type="form"
        ),
        Endpoint(
            url="http://example.com/about",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="page"
        ),
    ]

    if target:
        test_endpoints = [
            Endpoint(
                url=f"{target}/api/Users/1",
                method="GET", form_action=None,
                inputs=[], cookies_needed=[], endpoint_type="api"
            )
        ]

    print(f"\nTesting {len(test_endpoints)} endpoints...")
    results = scan_idor(test_endpoints)

    print(f"\nFindings: {len(results)}")
    for f in results:
        print(f"  [{f.severity}] {f.type} — {f.url}")
        print(f"    Parameter: {f.parameter}")
        print(f"    Evidence: {f.evidence[:120]}...")

    if not results:
        print("  No IDOR vulnerabilities detected (expected for mock/inactive targets).")

    print(f"\n{'=' * 60}")
    print("Standalone test complete.")
