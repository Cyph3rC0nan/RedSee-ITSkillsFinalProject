"""
XSS Scanner Test Suite — RedSee Member 3

Tests 1-4 below exercise the legacy direct-HTTP scanner (_legacy_scan_xss)
against the configured DVWA target — that target (TARGET_URL, typically
localhost) is a different host than the agent engine's REDSEE_ALLOWED_HOSTS
scope, so they call _legacy_scan_xss directly rather than the top-level
scan_xss (which is now agent-backed-first and would scope-refuse a
non-allow-listed host, returning 0 findings instead of exercising this code).
The agent-backed path and its stub-fallback are covered separately below by
fully offline, mocked tests — see the "Agent-backed scan_xss" section.

Prerequisites (tests 1-4 only):
    - Target reachable (public server or local Docker DVWA on port 80)
    - DVWA security level set to 'Low'
    - .env configured with TARGET_URL

Run from project root:
    python tests/test_xss.py
    PYTHONPATH=. python -m pytest tests/test_xss.py -v
"""

import sys, os
sys.path.insert(0, ".")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import pytest

import modules.xss as xss_module
from schemas import Endpoint, Finding
from modules.xss import scan_xss, _legacy_scan_xss
from engine.xss_agent import XssCandidate, XssAgentResult
from engine.llm import Usage


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
        findings = _legacy_scan_xss([endpoint], session=session)
    except ImportError:
        findings = _legacy_scan_xss([endpoint])

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
        findings = _legacy_scan_xss([endpoint], session=session)
    except ImportError:
        findings = _legacy_scan_xss([endpoint])

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
        findings = _legacy_scan_xss([endpoint], session=session)
    except ImportError:
        findings = _legacy_scan_xss([endpoint])

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

    findings = _legacy_scan_xss([endpoint])

    if len(findings) == 0:
        _ok("No false positive on endpoint with no inputs")
    else:
        _fail(f"Got {len(findings)} false positive(s) on empty endpoint")


# ──────────────────────────────────────────────────────────────
# Agent-backed scan_xss (fully offline — mocked run_xss_agent, no
# Docker/LLM/network). Covers: injectable -> Finding, clean -> [], the
# import-failure stub-fallback to the legacy scanner, REDSEE_XSS_COOKIE
# threading, and that the public signature scan_xss(endpoints, session=None)
# is unchanged.
# ──────────────────────────────────────────────────────────────

def _cand(status, **overrides):
    base = dict(
        endpoint_url="http://redsees.com:8080/vulnerabilities/xss_r/?name=test",
        parameter="name" if status == "injectable" else None,
        injectable=status == "injectable",
        context="inHTML-none(1)" if status == "injectable" else None,
        payload="<svg/onload=alert(1)>" if status == "injectable" else None,
        evidence="[POC][V][GET][inHTML-none(1)] http://.../xss_r/?name=<svg/onload=alert(1)>"
                 if status == "injectable" else "",
        dalfox_argv=["dalfox", "url", "http://redsees.com:8080/..."],
        status=status, error=None,
    )
    base.update(overrides)
    return XssCandidate(**base)


def _result(candidates, stopped_reason="done"):
    return XssAgentResult(
        candidates=candidates,
        usage=Usage(input_tokens=10, output_tokens=5, cost_usd=0.0, calls=1),
        iterations=1,
        transcript=[],
        stopped_reason=stopped_reason,
    )


def _endpoint():
    return Endpoint(url="http://redsees.com:8080/vulnerabilities/xss_r/?name=test",
                    method="GET", form_action=None, inputs=["name"],
                    cookies_needed=[], endpoint_type="page")


def test_scan_xss_signature_unchanged():
    import inspect
    params = list(inspect.signature(scan_xss).parameters)
    assert params == ["endpoints", "session"]
    assert inspect.signature(scan_xss).parameters["session"].default is None


def test_agent_backed_injectable_candidate_yields_finding(monkeypatch):
    monkeypatch.setattr(xss_module, "_HAS_AGENT", True)
    monkeypatch.setattr(xss_module, "_run_xss_agent_real",
                        lambda endpoints, **kw: _result([_cand("injectable")]))
    monkeypatch.setattr(xss_module, "_write_outputs_real", lambda *a, **kw: None)

    findings = scan_xss([_endpoint()])
    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].type == "XSS"
    assert findings[0].severity in {"Critical", "High", "Medium", "Low"}


def test_agent_backed_clean_candidate_yields_empty_list(monkeypatch):
    monkeypatch.setattr(xss_module, "_HAS_AGENT", True)
    monkeypatch.setattr(xss_module, "_run_xss_agent_real",
                        lambda endpoints, **kw: _result([_cand("clean")]))
    monkeypatch.setattr(xss_module, "_write_outputs_real", lambda *a, **kw: None)

    findings = scan_xss([_endpoint()])
    assert findings == []


def test_agent_backed_error_candidate_yields_empty_list_not_a_finding(monkeypatch):
    # A scan error (e.g. target unreachable) must never be reported as a
    # finding OR silently treated as "clean" — it simply yields no Finding.
    monkeypatch.setattr(xss_module, "_HAS_AGENT", True)
    monkeypatch.setattr(xss_module, "_run_xss_agent_real",
                        lambda endpoints, **kw: _result([_cand("error")], stopped_reason="max_iterations"))
    monkeypatch.setattr(xss_module, "_write_outputs_real", lambda *a, **kw: None)

    findings = scan_xss([_endpoint()])
    assert findings == []


def test_stub_fallback_used_when_agent_import_unavailable(monkeypatch):
    # Force the "engine/xss_agent import failed" state and confirm scan_xss
    # still returns a valid list via the legacy scanner (no exception, no None).
    monkeypatch.setattr(xss_module, "_HAS_AGENT", False)
    endpoint = Endpoint(url="http://127.0.0.1:1/no-such-service", method="GET",
                        form_action=None, inputs=["name"], cookies_needed=[],
                        endpoint_type="page")

    findings = scan_xss([endpoint])
    assert isinstance(findings, list)   # never None, never raises


def test_runtime_agent_failure_falls_back_to_legacy_scanner(monkeypatch):
    # Agent import succeeds but the call itself raises (e.g. LLM/scope not
    # configured, sandbox unavailable) — scan_xss must still return a list.
    def _boom(endpoints, **kw):
        raise RuntimeError("LLM not configured")

    monkeypatch.setattr(xss_module, "_HAS_AGENT", True)
    monkeypatch.setattr(xss_module, "_run_xss_agent_real", _boom)
    endpoint = Endpoint(url="http://127.0.0.1:1/no-such-service", method="GET",
                        form_action=None, inputs=["name"], cookies_needed=[],
                        endpoint_type="page")

    findings = scan_xss([endpoint])
    assert isinstance(findings, list)


def test_redsee_xss_cookie_env_var_threaded_into_auth_cookie(monkeypatch):
    seen = {}

    def _fake_run_xss_agent(endpoints, **kw):
        seen["auth_cookie"] = kw.get("auth_cookie")
        return _result([_cand("clean")])

    monkeypatch.setattr(xss_module, "_HAS_AGENT", True)
    monkeypatch.setattr(xss_module, "_run_xss_agent_real", _fake_run_xss_agent)
    monkeypatch.setattr(xss_module, "_write_outputs_real", lambda *a, **kw: None)
    monkeypatch.setenv("REDSEE_XSS_COOKIE", "PHPSESSID=abc123; security=low")

    scan_xss([_endpoint()])
    assert seen["auth_cookie"] == "PHPSESSID=abc123; security=low"


def test_no_redsee_xss_cookie_means_none_auth_cookie(monkeypatch):
    seen = {}

    def _fake_run_xss_agent(endpoints, **kw):
        seen["auth_cookie"] = kw.get("auth_cookie")
        return _result([_cand("clean")])

    monkeypatch.setattr(xss_module, "_HAS_AGENT", True)
    monkeypatch.setattr(xss_module, "_run_xss_agent_real", _fake_run_xss_agent)
    monkeypatch.setattr(xss_module, "_write_outputs_real", lambda *a, **kw: None)
    monkeypatch.delenv("REDSEE_XSS_COOKIE", raising=False)

    scan_xss([_endpoint()])
    assert seen["auth_cookie"] is None


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

    # ── Agent-backed / stub-fallback tests (assert-based; need a monkeypatch shim) ──
    class _MP:
        def __init__(self):
            self._undo = []
            self._env_undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def setenv(self, name, value):
            self._env_undo.append((name, os.environ.get(name), True))
            os.environ[name] = value

        def delenv(self, name, raising=False):
            self._env_undo.append((name, os.environ.get(name), name in os.environ))
            os.environ.pop(name, None)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)
            for name, old, existed in reversed(self._env_undo):
                if existed and old is not None:
                    os.environ[name] = old
                else:
                    os.environ.pop(name, None)

    print("\n" + "=" * 55)
    print("  Agent-backed scan_xss — offline tests")
    print("=" * 55)
    for _fn in (
        test_scan_xss_signature_unchanged,
        test_agent_backed_injectable_candidate_yields_finding,
        test_agent_backed_clean_candidate_yields_empty_list,
        test_agent_backed_error_candidate_yields_empty_list_not_a_finding,
        test_stub_fallback_used_when_agent_import_unavailable,
        test_runtime_agent_failure_falls_back_to_legacy_scanner,
        test_redsee_xss_cookie_env_var_threaded_into_auth_cookie,
        test_no_redsee_xss_cookie_means_none_auth_cookie,
    ):
        needs_mp = "monkeypatch" in _fn.__code__.co_varnames[:_fn.__code__.co_argcount]
        mp = _MP()
        try:
            _fn(mp) if needs_mp else _fn()
            print(f"  ok  {_fn.__name__}")
        finally:
            mp.undo()
    print("All agent-backed scan_xss tests passed!")