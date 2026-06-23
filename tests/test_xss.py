"""
XSS Scanner Test Suite — RedSee Member 3

Tests the scan_xss() function against the configured DVWA target.

Prerequisites:
    - Target reachable (public server or local Docker DVWA on port 80)
    - DVWA security level set to 'Low'
    - .env configured with TARGET_URL

Run from project root:
    python tests/test_xss.py
"""

import sys, os
sys.path.insert(0, ".")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from schemas import Endpoint, Finding
from modules.xss import scan_xss


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
# TEST 1: Reflected XSS on DVWA xss_r
# ──────────────────────────────────────────────────────────────

def test_reflected_xss():
    _header("TEST 1: Reflected XSS on /vulnerabilities/xss_r/")

    endpoint = Endpoint(
        url=f"{TARGET}/vulnerabilities/xss_r/",
        method="GET",
        form_action="#",
        inputs=["name", "Submit"],
        cookies_needed=["PHPSESSID", "security"],
        endpoint_type="form",
    )

    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(TARGET)
        session.authenticate_dvwa()
        findings = scan_xss([endpoint], session=session)
    except ImportError:
        findings = scan_xss([endpoint])

    if len(findings) >= 1:
        _ok(f"Reflected XSS detected — {len(findings)} finding(s)")
    else:
        _fail("Expected ≥1 XSS finding on xss_r — found 0")
        return

    f = findings[0]
    if f.type == "XSS":
        _ok("Finding.type == 'XSS'")
    else:
        _fail(f"Expected type 'XSS', got '{f.type}'")

    if f.parameter == "name":
        _ok("Vulnerable parameter correctly identified as 'name'")
    else:
        _fail(f"Expected parameter 'name', got '{f.parameter}'")

    if f.severity in ("High", "Critical"):
        _ok(f"Severity is '{f.severity}' (High or Critical)")
    else:
        _fail(f"Expected High/Critical severity for reflected XSS, got '{f.severity}'")

    print(f"\n  📌 Payload:  {f.payload}")
    print(f"  📌 Evidence: {f.evidence[:100]}")


# ──────────────────────────────────────────────────────────────
# TEST 2: Stored XSS on DVWA xss_s
# ──────────────────────────────────────────────────────────────

def test_stored_xss():
    _header("TEST 2: Stored XSS on /vulnerabilities/xss_s/")

    endpoint = Endpoint(
        url=f"{TARGET}/vulnerabilities/xss_s/",
        method="POST",
        form_action="#",
        inputs=["txtName", "mtxMessage", "btnSign"],
        cookies_needed=["PHPSESSID", "security"],
        endpoint_type="form",
    )

    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(TARGET)
        session.authenticate_dvwa()
        findings = scan_xss([endpoint], session=session)
    except ImportError:
        findings = scan_xss([endpoint])

    if len(findings) >= 1:
        _ok(f"XSS detected on stored endpoint — {len(findings)} finding(s)")
    else:
        _fail("Expected ≥1 XSS finding on xss_s — found 0")
        return

    stored = [f for f in findings if "Stored" in f.evidence or "stored" in f.evidence]
    if stored:
        if stored[0].severity == "Critical":
            _ok("Stored XSS rated Critical — correct")
        else:
            _fail(f"Stored XSS should be Critical, got '{stored[0].severity}'")
    else:
        _ok(f"XSS finding detected (evidence: {findings[0].evidence[:60]})")


# ──────────────────────────────────────────────────────────────
# TEST 3: Schema compliance for all XSS findings
# ──────────────────────────────────────────────────────────────

def test_xss_schema_compliance():
    _header("TEST 3: Finding schema compliance for XSS")

    endpoint = Endpoint(
        url=f"{TARGET}/vulnerabilities/xss_r/",
        method="GET",
        form_action="#",
        inputs=["name", "Submit"],
        cookies_needed=["PHPSESSID", "security"],
        endpoint_type="form",
    )

    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(TARGET)
        session.authenticate_dvwa()
        findings = scan_xss([endpoint], session=session)
    except ImportError:
        findings = scan_xss([endpoint])

    if not findings:
        print("  ⚠️  No findings to validate (re-run with live target)")
        return

    required_keys = {"type", "url", "parameter", "payload", "evidence", "severity", "timestamp"}
    valid_severities = {"Critical", "High", "Medium", "Low"}

    for i, f in enumerate(findings):
        if isinstance(f, Finding):
            _ok(f"Finding {i} is a Finding instance")
        else:
            _fail(f"Finding {i} is {type(f)}, not Finding")
            continue

        d = f.to_dict()
        missing = required_keys - set(d.keys())
        if not missing:
            _ok(f"Finding {i} has all required keys")
        else:
            _fail(f"Finding {i} missing: {missing}")

        if d["type"] == "XSS":
            _ok(f"Finding {i} type == 'XSS'")
        else:
            _fail(f"Finding {i} type == '{d['type']}' (expected 'XSS')")

        if d["severity"] in valid_severities:
            _ok(f"Finding {i} severity '{d['severity']}' is valid")
        else:
            _fail(f"Finding {i} severity '{d['severity']}' is invalid")

        if d["timestamp"].endswith("Z"):
            _ok(f"Finding {i} timestamp is valid ISO 8601")
        else:
            _fail(f"Finding {i} timestamp '{d['timestamp']}' missing 'Z' suffix")


# ──────────────────────────────────────────────────────────────
# TEST 4: No false positives
# ──────────────────────────────────────────────────────────────

def test_xss_no_false_positive():
    _header("TEST 4: No false positives on endpoint with no inputs")

    endpoint = Endpoint(
        url=f"{TARGET}/index.php",
        method="GET",
        form_action=None,
        inputs=[],
        cookies_needed=["PHPSESSID"],
        endpoint_type="page",
    )

    findings = scan_xss([endpoint])

    if len(findings) == 0:
        _ok("No false positive on endpoint with no inputs")
    else:
        _fail(f"Got {len(findings)} false positive(s) on empty endpoint")


# ──────────────────────────────────────────────────────────────
# RUNNER
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "🟠" * 20)
    print("RedSee — XSS Scanner Test Suite")
    print(f"Target: {TARGET}")
    print("🟠" * 20)

    test_reflected_xss()
    test_stored_xss()
    test_xss_schema_compliance()
    test_xss_no_false_positive()

    print(f"\n{'='*55}")
    print(f"  RESULTS: {PASS_COUNT} passed / {FAIL_COUNT} failed")
    if FAIL_COUNT == 0:
        print("  🎉 All tests passed — xss.py is ready for integration")
    else:
        print("  ⚠️  Fix failures before merging to main")
    print(f"{'='*55}\n")