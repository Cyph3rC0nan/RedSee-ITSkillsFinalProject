"""
Unit tests for modules/idor.py
Tests run against mock Endpoint objects — no network required for structural tests.
For live tests, set TARGET_URL in .env to point at your test server.

Run: python -m pytest tests/test_idor.py -v
"""
import pytest
from schemas import Endpoint, Finding
from modules.idor import scan_idor

# ── Structural tests (no network) ──────────────────────────

def test_scan_idor_returns_list():
    """scan_idor must always return a list."""
    result = scan_idor([])
    assert isinstance(result, list)


def test_scan_idor_empty_endpoints():
    """Empty endpoint list returns empty findings list."""
    assert scan_idor([]) == []


def test_all_findings_are_finding_objects():
    """Every returned item must be a Finding or a dict with correct keys."""
    endpoints = [
        Endpoint(
            url="http://localhost/api/users/1",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="api"
        )
    ]
    # May or may not find findings depending on target availability
    results = scan_idor(endpoints)
    for r in results:
        if isinstance(r, Finding):
            assert r.type == "IDOR"
            assert r.severity in ("Critical", "High", "Medium", "Low")
            assert r.timestamp.endswith("Z")
        elif isinstance(r, dict):
            assert r["type"] == "IDOR"


def test_no_false_positive_on_non_id_endpoint():
    """Endpoints without numeric IDs should not trigger IDOR."""
    endpoints = [
        Endpoint(
            url="http://localhost/about",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="page"
        )
    ]
    results = scan_idor(endpoints)
    assert results == [], f"Expected no IDOR on /about, got: {results}"


def test_idor_type_always_correct():
    """All findings from scan_idor must have type='IDOR'."""
    endpoints = [
        Endpoint(
            url="http://localhost/api/users/1",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="api"
        ),
        Endpoint(
            url="http://localhost/api/orders/5",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="api"
        ),
    ]
    results = scan_idor(endpoints)
    for r in results:
        t = r.type if isinstance(r, Finding) else r["type"]
        assert t == "IDOR", f"Expected type='IDOR', got '{t}'"


def test_severity_values_are_valid():
    """All severity values must be from the approved set."""
    endpoints = [
        Endpoint(
            url="http://localhost/api/users/1",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="api"
        )
    ]
    results = scan_idor(endpoints)
    valid = {"Critical", "High", "Medium", "Low"}
    for r in results:
        sev = r.severity if isinstance(r, Finding) else r["severity"]
        assert sev in valid, f"Invalid severity: {sev}"


# ── Live tests (require TARGET_URL) ────────────────────────

def test_live_idor_on_target():
    """Live test against configured target."""
    import os
    from dotenv import load_dotenv
    load_dotenv()
    target = os.getenv("TARGET_URL", "")
    if not target:
        pytest.skip("TARGET_URL not set — skipping live test")

    endpoints = [
        Endpoint(
            url=f"{target}/api/Users/1",
            method="GET", form_action=None,
            inputs=[], cookies_needed=[], endpoint_type="api"
        )
    ]
    results = scan_idor(endpoints)
    print(f"\nLive IDOR results against {target}: {len(results)} findings")
    for r in results:
        sev = r.severity if isinstance(r, Finding) else r["severity"]
        url = r.url if isinstance(r, Finding) else r["url"]
        print(f"  [{sev}] {url}")
