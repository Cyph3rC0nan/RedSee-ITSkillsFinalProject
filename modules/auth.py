"""
Broken Authentication Scanner Module — detects auth weaknesses.

Tests for:
  1. Default credentials on login forms
  2. Missing rate limiting on login endpoints
  3. Missing authentication on API endpoints
  4. JWT weaknesses (alg:none, weak signing)

Public API:
    scan_auth(endpoints: list[Endpoint], session=None) -> list[Finding]

Owner: Member 4
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import re
import base64
import json
import time
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

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("root", "root"), ("root", "toor"),
    ("test", "test"), ("user", "user"), ("admin", ""), ("guest", "guest"),
]

RATE_LIMIT_TEST_COUNT = 50
RATE_LIMIT_THRESHOLD = 0.95  # if >95% of rapid requests succeed → no rate limiting

FAILURE_INDICATORS = ["failed", "invalid", "error", "incorrect"]
SUCCESS_INDICATORS = ["welcome", "dashboard", "logout", "admin", "success"]


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def scan_auth(endpoints: list, session=None) -> list:
    """
    Scan endpoints for broken authentication vulnerabilities.

    Args:
        endpoints: list of Endpoint objects
        session: optional HTTPSession or requests.Session

    Returns:
        list[Finding] — findings with type="BrokenAuth"
    """
    findings = []

    for endpoint in endpoints:
        if not isinstance(endpoint, Endpoint):
            continue

        # 1. Test default credentials on login endpoints
        if _is_login_endpoint(endpoint):
            finding = _test_default_credentials(endpoint, session)
            if finding:
                findings.append(finding)

            finding = _test_rate_limiting(endpoint, session)
            if finding:
                findings.append(finding)

        # 2. Test missing auth on API endpoints
        if endpoint.endpoint_type == "api":
            finding = _test_missing_auth(endpoint, session)
            if finding:
                findings.append(finding)

    # 3. Test JWT weaknesses across all API endpoints
    jwt_finding = _test_jwt_weaknesses(endpoints, session)
    if jwt_finding:
        findings.append(jwt_finding)

    return findings


# ═══════════════════════════════════════════════════════════════
# LOGIN ENDPOINT DETECTION
# ═══════════════════════════════════════════════════════════════

def _is_login_endpoint(endpoint: Endpoint) -> bool:
    """Detect if an endpoint is a login form."""
    url_lower = endpoint.url.lower()
    input_names = [i.lower() for i in endpoint.inputs]
    return (
        ("login" in url_lower or "auth" in url_lower or "signin" in url_lower)
        and ("username" in input_names or "email" in input_names
             or "password" in input_names or "pass" in input_names)
    )


# ═══════════════════════════════════════════════════════════════
# TEST 1: DEFAULT CREDENTIALS
# ═══════════════════════════════════════════════════════════════

def _test_default_credentials(endpoint: Endpoint, session) -> Optional[Finding]:
    """Test login endpoint with default credentials."""
    # Find username and password field names
    username_field = None
    password_field = None

    for inp in endpoint.inputs:
        inp_lower = inp.lower()
        if inp_lower in ("username", "user", "email", "login", "uname"):
            username_field = inp
        elif inp_lower in ("password", "pass", "pwd", "passwd"):
            password_field = inp

    if not username_field or not password_field:
        return None

    form_action = endpoint.form_action or endpoint.url

    for username, password in DEFAULT_CREDENTIALS:
        try:
            data = {username_field: username, password_field: password}

            # Add any cookies needed
            cookies = {}
            if endpoint.cookies_needed:
                for c in endpoint.cookies_needed:
                    cookies[c] = "1"  # placeholder

            resp = _make_request(
                form_action,
                method="POST",
                session=session,
                data=data,
                cookies=cookies if cookies else None
            )

            if resp is None:
                continue

            body_lower = resp.text.lower()

            # Success indicators
            has_success = any(indicator in body_lower for indicator in SUCCESS_INDICATORS)
            has_failure = any(indicator in body_lower for indicator in FAILURE_INDICATORS)
            is_redirect = resp.status_code in (301, 302, 303, 307, 308)

            if (has_success or is_redirect) and not has_failure:
                return Finding(
                    type="BrokenAuth",
                    url=endpoint.url,
                    parameter=f"{username_field}/{password_field}",
                    payload=f"{username}:{password}",
                    evidence=(
                        f"Default credentials accepted: {username}:{password}. "
                        f"Response: {resp.status_code}"
                        + (" (redirect)" if is_redirect else "")
                        + f". {'Welcome/dashboard indicators found.' if has_success else ''}"
                    ),
                    severity="Critical",
                    timestamp=_ts()
                )

        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
# TEST 2: RATE LIMITING
# ═══════════════════════════════════════════════════════════════

def _test_rate_limiting(endpoint: Endpoint, session) -> Optional[Finding]:
    """Test if login endpoint has rate limiting by sending rapid requests."""
    # Find password field
    password_field = None
    username_field = None
    for inp in endpoint.inputs:
        inp_lower = inp.lower()
        if inp_lower in ("username", "user", "email", "login", "uname"):
            username_field = inp
        elif inp_lower in ("password", "pass", "pwd", "passwd"):
            password_field = inp

    if not username_field or not password_field:
        username_field = "username"
        password_field = "password"

    form_action = endpoint.form_action or endpoint.url
    success_count = 0
    attempt_count = 0

    for i in range(RATE_LIMIT_TEST_COUNT):
        try:
            data = {username_field: f"test_user_{i}", password_field: f"wrong_pass_{i}"}
            resp = _make_request(form_action, method="POST", session=session, data=data)

            if resp is None:
                continue

            attempt_count += 1
            if resp.status_code not in (429, 403):
                success_count += 1

        except Exception:
            continue

    if attempt_count == 0:
        return None

    success_rate = success_count / attempt_count if attempt_count > 0 else 0

    if success_rate > RATE_LIMIT_THRESHOLD:
        return Finding(
            type="BrokenAuth",
            url=endpoint.url,
            parameter="Rate limiting",
            payload=f"{RATE_LIMIT_TEST_COUNT} rapid login attempts",
            evidence=(
                f"No rate limiting detected. Sent {RATE_LIMIT_TEST_COUNT} rapid POST requests "
                f"with wrong credentials: {success_count}/{attempt_count} succeeded without 429. "
                f"Success rate: {success_rate:.1%} (threshold: {RATE_LIMIT_THRESHOLD:.0%}). "
                f"Brute force attacks are feasible."
            ),
            severity="Medium",
            timestamp=_ts()
        )

    return None


# ═══════════════════════════════════════════════════════════════
# TEST 3: MISSING AUTH ON API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

def _test_missing_auth(endpoint: Endpoint, session) -> Optional[Finding]:
    """Test if API endpoint is accessible without authentication."""
    try:
        resp = _make_request(endpoint.url, method="GET", session=session)

        if resp is None:
            return None

        body_lower = resp.text.lower()
        body_len = len(resp.text)

        # Check: 200 OK, meaningful body, no auth-related rejection
        if resp.status_code == 200 and body_len > 50:
            if "unauthorized" not in body_lower and "login" not in body_lower:
                return Finding(
                    type="BrokenAuth",
                    url=endpoint.url,
                    parameter="No authentication",
                    payload="GET without credentials",
                    evidence=(
                        f"API endpoint accessible without authentication. "
                        f"Response: 200 OK, {body_len} bytes. "
                        f"No authorization required — sensitive data may be exposed."
                    ),
                    severity="High",
                    timestamp=_ts()
                )

    except Exception:
        pass

    return None


# ═══════════════════════════════════════════════════════════════
# TEST 4: JWT WEAKNESSES
# ═══════════════════════════════════════════════════════════════

def _test_jwt_weaknesses(endpoints: list, session) -> Optional[Finding]:
    """Scan API responses for JWT tokens and check for weaknesses."""
    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

    for endpoint in endpoints:
        if not isinstance(endpoint, Endpoint):
            continue
        if endpoint.endpoint_type != "api":
            continue

        try:
            resp = _make_request(endpoint.url, method="GET", session=session)
            if resp is None:
                continue

            # Search response headers and body for JWT
            search_text = resp.text
            for header_val in resp.headers.values():
                search_text += " " + str(header_val)

            match = jwt_pattern.search(search_text)
            if not match:
                continue

            token = match.group(0)
            parts = token.split(".")

            if len(parts) != 3:
                continue

            # Decode header (base64 URL-safe)
            header_b64 = parts[0]
            # Fix padding
            header_b64 += "=" * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ""

            try:
                header_bytes = base64.urlsafe_b64decode(header_b64)
                header = json.loads(header_bytes)
            except Exception:
                continue

            alg = header.get("alg", "").upper()

            if alg == "NONE":
                return Finding(
                    type="BrokenAuth",
                    url=endpoint.url,
                    parameter="JWT algorithm",
                    payload=f"alg:none (token: {token[:50]}...)",
                    evidence=(
                        f"JWT token found with algorithm 'none'. "
                        f"This allows bypassing signature verification entirely. "
                        f"Token header: {header}"
                    ),
                    severity="Critical",
                    timestamp=_ts()
                )

            if alg == "HS256":
                return Finding(
                    type="BrokenAuth",
                    url=endpoint.url,
                    parameter="JWT algorithm",
                    payload=f"alg:HS256 (token: {token[:50]}...)",
                    evidence=(
                        f"JWT token uses HS256 (symmetric HMAC with SHA-256). "
                        f"If the secret is weak or shared, tokens can be forged. "
                        f"Consider RS256 or ES256 for distributed systems."
                    ),
                    severity="Medium",
                    timestamp=_ts()
                )

        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
# REQUEST HELPERS
# ═══════════════════════════════════════════════════════════════

def _make_request(url: str, method: str = "GET", session=None,
                  params: dict = None, data: dict = None, cookies: dict = None):
    """Make an HTTP request with error handling. Returns response or None."""
    try:
        kwargs = {"timeout": 10}
        if cookies:
            kwargs["cookies"] = cookies

        if session and _HAS_HTTP_SESSION and isinstance(session, HTTPSession):
            if method.upper() == "POST":
                return session.post(url, data=data, **kwargs)
            else:
                return session.get(url, params=params, **kwargs)
        elif session and hasattr(session, 'request'):
            return session.request(method.upper(), url, params=params, data=data, **kwargs)
        else:
            if method.upper() == "POST":
                return _requests.post(url, data=data, **kwargs)
            else:
                return _requests.get(url, params=params, **kwargs)
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
    print("🛡️  Broken Auth Scanner — Standalone Test")
    print("=" * 60)

    target = os.getenv("TARGET_URL", "")

    test_endpoints = [
        Endpoint(
            url="http://example.com/login.php",
            method="POST",
            form_action="http://example.com/login.php",
            inputs=["username", "password", "Login", "user_token"],
            cookies_needed=["PHPSESSID"],
            endpoint_type="form"
        ),
        Endpoint(
            url="http://example.com/api/data",
            method="GET",
            form_action=None,
            inputs=[],
            cookies_needed=[],
            endpoint_type="api"
        ),
        Endpoint(
            url="http://example.com/about",
            method="GET",
            form_action=None,
            inputs=[],
            cookies_needed=[],
            endpoint_type="page"
        ),
    ]

    if target:
        test_endpoints = [
            Endpoint(
                url=f"{target}/login.php",
                method="POST",
                form_action=f"{target}/login.php",
                inputs=["username", "password", "Login", "user_token"],
                cookies_needed=["PHPSESSID"],
                endpoint_type="form"
            )
        ]

    print(f"\nTesting {len(test_endpoints)} endpoints...")
    print(f"  Login detection: {[e.url for e in test_endpoints if _is_login_endpoint(e)]}")

    results = scan_auth(test_endpoints)

    print(f"\nFindings: {len(results)}")
    for f in results:
        print(f"  [{f.severity}] {f.type} — {f.url}")
        print(f"    Parameter: {f.parameter}")
        print(f"    Evidence: {f.evidence[:120]}...")

    if not results:
        print("  No auth vulnerabilities detected (expected for mock/inactive targets).")

    print(f"\n{'=' * 60}")
    print("Standalone test complete.")
