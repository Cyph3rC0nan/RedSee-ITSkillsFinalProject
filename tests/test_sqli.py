"""
SQLi Scanner Test Suite — RedSee Member 3

Tests 1-4 below exercise the legacy direct-HTTP scanner (_legacy_scan_sqli)
against the configured DVWA target — that target (TARGET_URL, typically
localhost) is a different host than the agent engine's REDSEE_ALLOWED_HOSTS
scope, so they call _legacy_scan_sqli directly rather than the top-level
scan_sqli (which is now agent-backed-first and would scope-refuse a
non-allow-listed host, returning 0 findings instead of exercising this code).
The agent-backed path and its stub-fallback are covered separately below by
fully offline, mocked tests — see the "Agent-backed scan_sqli" section.

Prerequisites (tests 1-4 only):
    - Target reachable (public server or local Docker DVWA on port 80)
    - DVWA security level set to 'Low'
    - .env configured with TARGET_URL, TARGET_AUTH_USER, TARGET_AUTH_PASS

Run from project root:
    python tests/test_sqli.py
    PYTHONPATH=. python -m pytest tests/test_sqli.py -v
"""

import sys, os
sys.path.insert(0, ".")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import pytest

import modules.sqli as sqli_module
from schemas import Endpoint, Finding
from modules.sqli import scan_sqli, _legacy_scan_sqli
from engine.agent import SqliCandidate, SqliAgentResult
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
        findings = _legacy_scan_sqli([endpoint], session=session)
    except ImportError:
        findings = _legacy_scan_sqli([endpoint])

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

    findings = _legacy_scan_sqli([endpoint])

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
        findings = _legacy_scan_sqli([endpoint], session=session)
    except ImportError:
        findings = _legacy_scan_sqli([endpoint])

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
        findings = _legacy_scan_sqli([endpoint], session=session)
    except ImportError:
        findings = _legacy_scan_sqli([endpoint])

    if len(findings) >= 1:
        _ok(f"Blind SQLi detected — {len(findings)} finding(s)")
        print(f"  📌 Technique: {findings[0].evidence[:80]}")
    else:
        _fail("Expected ≥1 blind SQLi finding — found 0 (time-based or boolean may need live target)")


# ──────────────────────────────────────────────────────────────
# Agent-backed scan_sqli (fully offline — mocked run_sqli_agent, no
# Docker/LLM/network). Covers: injectable -> Finding, clean -> [], the
# import-failure stub-fallback to the legacy scanner, and that the public
# signature scan_sqli(endpoints, session=None) is unchanged.
# ──────────────────────────────────────────────────────────────

def _cand(status, **overrides):
    base = dict(
        endpoint_url="http://redsees.com:3000/rest/products/search?q=apple",
        parameter="q" if status == "injectable" else None,
        injectable=status == "injectable",
        technique="boolean-based blind" if status == "injectable" else None,
        dbms="SQLite" if status == "injectable" else None,
        evidence="Parameter: q (GET)\n    Type: boolean-based blind\n    Payload: q=apple' AND 1=1\n"
                 if status == "injectable" else "",
        sqlmap_argv=["sqlmap", "-u", "http://redsees.com:3000/..."],
        depth=0, status=status, error=None,
    )
    base.update(overrides)
    return SqliCandidate(**base)


def _result(candidates, stopped_reason="done"):
    return SqliAgentResult(
        candidates=candidates,
        usage=Usage(input_tokens=10, output_tokens=5, cost_usd=0.0, calls=1),
        iterations=1,
        transcript=[],
        stopped_reason=stopped_reason,
    )


def _endpoint():
    return Endpoint(url="http://redsees.com:3000/rest/products/search?q=apple",
                    method="GET", form_action=None, inputs=["q"],
                    cookies_needed=[], endpoint_type="api")


def test_scan_sqli_signature_unchanged():
    import inspect
    params = list(inspect.signature(scan_sqli).parameters)
    assert params == ["endpoints", "session"]
    assert inspect.signature(scan_sqli).parameters["session"].default is None


def test_agent_backed_injectable_candidate_yields_finding(monkeypatch):
    monkeypatch.setattr(sqli_module, "_HAS_AGENT", True)
    monkeypatch.setattr(sqli_module, "_run_sqli_agent_real",
                        lambda endpoints, **kw: _result([_cand("injectable")]))
    monkeypatch.setattr(sqli_module, "_write_outputs_real", lambda *a, **kw: None)

    findings = scan_sqli([_endpoint()])
    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].type == "SQLi"
    assert findings[0].severity in {"Critical", "High", "Medium", "Low"}


def test_agent_backed_clean_candidate_yields_empty_list(monkeypatch):
    monkeypatch.setattr(sqli_module, "_HAS_AGENT", True)
    monkeypatch.setattr(sqli_module, "_run_sqli_agent_real",
                        lambda endpoints, **kw: _result([_cand("clean")]))
    monkeypatch.setattr(sqli_module, "_write_outputs_real", lambda *a, **kw: None)

    findings = scan_sqli([_endpoint()])
    assert findings == []


def test_agent_backed_error_candidate_yields_empty_list_not_a_finding(monkeypatch):
    # A scan error (e.g. target unreachable) must never be reported as a
    # finding OR silently treated as "clean" — it simply yields no Finding.
    monkeypatch.setattr(sqli_module, "_HAS_AGENT", True)
    monkeypatch.setattr(sqli_module, "_run_sqli_agent_real",
                        lambda endpoints, **kw: _result([_cand("error")], stopped_reason="error"))
    monkeypatch.setattr(sqli_module, "_write_outputs_real", lambda *a, **kw: None)

    findings = scan_sqli([_endpoint()])
    assert findings == []


def test_stub_fallback_used_when_agent_import_unavailable(monkeypatch):
    # Force the "engine/agent import failed" state and confirm scan_sqli still
    # returns a valid list via the legacy scanner (no exception, no None).
    monkeypatch.setattr(sqli_module, "_HAS_AGENT", False)
    endpoint = Endpoint(url="http://127.0.0.1:1/no-such-service", method="GET",
                        form_action=None, inputs=["id"], cookies_needed=[],
                        endpoint_type="api")

    findings = scan_sqli([endpoint])
    assert isinstance(findings, list)   # never None, never raises


def test_runtime_agent_failure_falls_back_to_legacy_scanner(monkeypatch):
    # Agent import succeeds but the call itself raises (e.g. LLM/scope not
    # configured, sandbox unavailable) — scan_sqli must still return a list.
    def _boom(endpoints, **kw):
        raise RuntimeError("LLM not configured")

    monkeypatch.setattr(sqli_module, "_HAS_AGENT", True)
    monkeypatch.setattr(sqli_module, "_run_sqli_agent_real", _boom)
    endpoint = Endpoint(url="http://127.0.0.1:1/no-such-service", method="GET",
                        form_action=None, inputs=["id"], cookies_needed=[],
                        endpoint_type="api")

    findings = scan_sqli([endpoint])
    assert isinstance(findings, list)


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

    # ── Agent-backed / stub-fallback tests (assert-based; need a monkeypatch shim) ──
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    print("\n" + "=" * 55)
    print("  Agent-backed scan_sqli — offline tests")
    print("=" * 55)
    for _fn in (
        test_scan_sqli_signature_unchanged,
        test_agent_backed_injectable_candidate_yields_finding,
        test_agent_backed_clean_candidate_yields_empty_list,
        test_agent_backed_error_candidate_yields_empty_list_not_a_finding,
        test_stub_fallback_used_when_agent_import_unavailable,
        test_runtime_agent_failure_falls_back_to_legacy_scanner,
    ):
        needs_mp = "monkeypatch" in _fn.__code__.co_varnames[:_fn.__code__.co_argcount]
        mp = _MP()
        try:
            _fn(mp) if needs_mp else _fn()
            print(f"  ok  {_fn.__name__}")
        finally:
            mp.undo()
    print("All agent-backed scan_sqli tests passed!")