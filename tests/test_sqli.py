"""
SQLi Scanner Test Suite — RedSee Member 3

Tests the scan_sqli() function against the configured DVWA target.

Prerequisites:
    - Target reachable (public server or local Docker DVWA on port 80)
    - DVWA security level set to 'Low'
    - .env configured with TARGET_URL, TARGET_AUTH_USER, TARGET_AUTH_PASS

Run from project root:
    python tests/test_sqli.py
"""

import sys, os
sys.path.insert(0, ".")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from schemas import Endpoint, Finding
from modules.sqli import scan_sqli


TARGET = os.getenv("TARGET_URL", "http://localhost")

PASS_COUNT = 0
FAIL_COUNT = 0


def _ok(msg):
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  ✅ PASS: {msg}")


def _fail(msg):
    global FAIL_COUNT
    FAIL_COUNT += 1
    print(f"  ❌ FAIL: {msg}")


def _header(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# ──────────────────────────────────────────────────────────────
# TEST 1: SQLi scanner detects known vulnerable DVWA endpoint
# ──────────────────────────────────────────────────────────────

def test_sqli_finds_dvwa_injection():
    _header("TEST 1: SQLi detection on DVWA /vulnerabilities/sqli/")

    endpoint = Endpoint(
        url=f"{TARGET}/vulnerabilities/sqli/",
        method="GET",
        form_action="#",
        inputs=["id", "Submit"],
        cookies_needed=["PHPSESSID", "security"],
        endpoint_type="form",
    )

    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(TARGET)
        session.authenticate_dvwa()
        findings = scan_sqli([endpoint], session=session)
    except ImportError:
        findings = scan_sqli([endpoint])

    if len(findings) >= 1:
        _ok(f"Found {len(findings)} SQLi finding(s)")
    else:
        _fail("Expected ≥1 SQLi finding — found 0")
        return

    f = findings[0]
    if f.type == "SQLi":
        _ok(f"Finding.type == 'SQLi'")
    else:
        _fail(f"Expected type 'SQLi', got '{f.type}'")

    if f.severity in ("Critical", "High"):
        _ok(f"Severity is '{f.severity}' (Critical or High)")
    else:
        _fail(f"Expected Critical/High severity, got '{f.severity}'")

    if f.parameter == "id":
        _ok(f"Vulnerable parameter correctly identified as 'id'")
    else:
        _fail(f"Expected parameter 'id', got '{f.parameter}'")

    print(f"\n  📌 Evidence: {f.evidence[:100]}")
    print(f"  📌 Payload:  {f.payload}")


# ──────────────────────────────────────────────────────────────
# TEST 2: No false positives on a benign endpoint
# ──────────────────────────────────────────────────────────────

def test_sqli_no_false_positive():
    _header("TEST 2: No false positives on safe endpoint")

    endpoint = Endpoint(
        url=f"{TARGET}/index.php",
        method="GET",
        form_action=None,
        inputs=[],
        cookies_needed=["PHPSESSID"],
        endpoint_type="page",
    )

    findings = scan_sqli([endpoint])

    if len(findings) == 0:
        _ok("No findings on endpoint with no inputs — correct")
    else:
        _fail(f"Expected 0 findings, got {len(findings)}")


# ──────────────────────────────────────────────────────────────
# TEST 3: All Finding objects match schema contract exactly
# ──────────────────────────────────────────────────────────────

def test_schema_compliance():
    _header("TEST 3: Finding schema compliance")

    endpoint = Endpoint(
        url=f"{TARGET}/vulnerabilities/sqli/",
        method="GET",
        form_action="#",
        inputs=["id", "Submit"],
        cookies_needed=["PHPSESSID", "security"],
        endpoint_type="form",
    )

    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(TARGET)
        session.authenticate_dvwa()
        findings = scan_sqli([endpoint], session=session)
    except ImportError:
        findings = scan_sqli([endpoint])

    if not findings:
        print("  ⚠️  No findings to validate schema — skipping (re-run with live target)")
        return

    required_keys = {"type", "url", "parameter", "payload", "evidence", "severity", "timestamp"}
    valid_severities = {"Critical", "High", "Medium", "Low"}

    for i, f in enumerate(findings):
        if isinstance(f, Finding):
            _ok(f"Finding {i} is a Finding instance")
        else:
            _fail(f"Finding {i} is type {type(f)}, expected Finding")
            continue

        d = f.to_dict()

        missing = required_keys - set(d.keys())
        if not missing:
            _ok(f"Finding {i} has all required keys")
        else:
            _fail(f"Finding {i} missing keys: {missing}")

        if d["type"] == "SQLi":
            _ok(f"Finding {i} type == 'SQLi'")
        else:
            _fail(f"Finding {i} type == '{d['type']}' (expected 'SQLi')")

        if d["severity"] in valid_severities:
            _ok(f"Finding {i} severity '{d['severity']}' is valid")
        else:
            _fail(f"Finding {i} severity '{d['severity']}' not in {valid_severities}")

        if d["timestamp"].endswith("Z"):
            _ok(f"Finding {i} timestamp is ISO 8601 with Z suffix")
        else:
            _fail(f"Finding {i} timestamp '{d['timestamp']}' missing 'Z' suffix")


# ──────────────────────────────────────────────────────────────
# TEST 4: Blind SQLi endpoint (sqli_blind)
# ──────────────────────────────────────────────────────────────

def test_sqli_blind_detection():
    _header("TEST 4: Blind SQLi on DVWA /vulnerabilities/sqli_blind/")

    endpoint = Endpoint(
        url=f"{TARGET}/vulnerabilities/sqli_blind/",
        method="GET",
        form_action="#",
        inputs=["id", "Submit"],
        cookies_needed=["PHPSESSID", "security"],
        endpoint_type="form",
    )

    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(TARGET)
        session.authenticate_dvwa()
        findings = scan_sqli([endpoint], session=session)
    except ImportError:
        findings = scan_sqli([endpoint])

    if len(findings) >= 1:
        _ok(f"Blind SQLi detected — {len(findings)} finding(s)")
        print(f"  📌 Technique: {findings[0].evidence[:80]}")
    else:
        _fail("Expected ≥1 blind SQLi finding — found 0 (time-based or boolean may need live target)")


# ──────────────────────────────────────────────────────────────
# RUNNER
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "🔴" * 20)
    print("RedSee — SQLi Scanner Test Suite")
    print(f"Target: {TARGET}")
    print("🔴" * 20)

    test_sqli_finds_dvwa_injection()
    test_sqli_no_false_positive()
    test_schema_compliance()
    test_sqli_blind_detection()

    print(f"\n{'='*55}")
    print(f"  RESULTS: {PASS_COUNT} passed / {FAIL_COUNT} failed")
    if FAIL_COUNT == 0:
        print("  🎉 All tests passed — sqli.py is ready for integration")
    else:
        print("  ⚠️  Fix failures before merging to main")
    print(f"{'='*55}\n")