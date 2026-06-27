"""
Unit tests for modules/auth.py

Run: python -m pytest tests/test_auth.py -v
"""
import pytest
from schemas import Endpoint, Finding
from modules.auth import scan_auth, _is_login_endpoint


def test_scan_auth_returns_list():
    assert isinstance(scan_auth([]), list)


def test_scan_auth_empty():
    assert scan_auth([]) == []


def test_is_login_endpoint_detection():
    login_ep = Endpoint(
        url="http://localhost/login.php", method="POST",
        form_action="login.php",
        inputs=["username", "password", "Login"],
        cookies_needed=["PHPSESSID"], endpoint_type="form"
    )
    assert _is_login_endpoint(login_ep) is True


def test_non_login_endpoint_not_detected():
    about_ep = Endpoint(
        url="http://localhost/about", method="GET",
        form_action=None, inputs=[],
        cookies_needed=[], endpoint_type="page"
    )
    assert _is_login_endpoint(about_ep) is False


def test_login_detection_with_auth_url():
    auth_ep = Endpoint(
        url="http://localhost/auth/login", method="POST",
        form_action="/auth/login",
        inputs=["email", "password", "remember"],
        cookies_needed=[], endpoint_type="form"
    )
    assert _is_login_endpoint(auth_ep) is True


def test_login_detection_signin():
    signin_ep = Endpoint(
        url="http://localhost/signin", method="POST",
        form_action="/signin",
        inputs=["username", "pass"],
        cookies_needed=[], endpoint_type="form"
    )
    assert _is_login_endpoint(signin_ep) is True


def test_all_findings_have_correct_type():
    results = scan_auth([])
    for r in results:
        t = r.type if isinstance(r, Finding) else r["type"]
        assert t == "BrokenAuth", f"Expected BrokenAuth, got: {t}"


def test_severity_values_valid():
    """All severity values must be from approved set."""
    # Use a login endpoint that might trigger findings
    endpoints = [
        Endpoint(
            url="http://localhost/login.php", method="POST",
            form_action="login.php",
            inputs=["username", "password", "Login"],
            cookies_needed=["PHPSESSID"], endpoint_type="form"
        )
    ]
    results = scan_auth(endpoints)
    valid = {"Critical", "High", "Medium", "Low"}
    for r in results:
        sev = r.severity if isinstance(r, Finding) else r["severity"]
        assert sev in valid, f"Invalid severity: {sev}"


def test_api_endpoint_tested():
    """API endpoints should be checked for missing auth."""
    api_ep = Endpoint(
        url="http://localhost/api/data",
        method="GET", form_action=None,
        inputs=[], cookies_needed=[],
        endpoint_type="api"
    )
    results = scan_auth([api_ep])
    # May or may not find findings (depends on whether endpoint responds)
    for r in results:
        assert r.severity in ("Critical", "High", "Medium", "Low")


# ── Live tests (require TARGET_URL) ────────────────────────

def test_live_default_credentials():
    import os
    from dotenv import load_dotenv
    load_dotenv()
    target = os.getenv("TARGET_URL", "")
    if not target:
        pytest.skip("TARGET_URL not set")

    endpoints = [
        Endpoint(
            url=f"{target}/login.php", method="POST",
            form_action="login.php",
            inputs=["username", "password", "Login", "user_token"],
            cookies_needed=["PHPSESSID"], endpoint_type="form"
        )
    ]
    results = scan_auth(endpoints)
    print(f"\nAuth findings against {target}: {len(results)}")
    for r in results:
        sev = r.severity if isinstance(r, Finding) else r["severity"]
        url = r.url if isinstance(r, Finding) else r["url"]
        print(f"  [{sev}] {url}")
