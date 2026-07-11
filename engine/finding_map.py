# engine/finding_map.py
"""
Maps agent-produced candidate objects (engine/agent.py's SqliCandidate,
engine/xss_agent.py's XssCandidate) into schema-valid Finding objects
(schemas.py — FROZEN, matched here exactly).

Only a candidate whose tool run actually CONFIRMED a vulnerability
(status == "injectable") may become a Finding. clean/error/out_of_scope
candidates are not verdicts of "no vulnerability" in the exploit sense — they
are the absence of a confirmed one — so they never produce a Finding.
"""

import re
from datetime import datetime, timezone

from schemas import Finding
from engine.agent import SqliCandidate
from engine.xss_agent import XssCandidate

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_PAYLOAD_LINE_RE = re.compile(r"Payload:\s*(.+)", re.I)

# Remediation guidance shared by every SQLi Finding (responsible-reporting
# requirement — every confirmed injection ships with the standard fix).
_REMEDIATION = (
    "Remediation: use parameterized queries / prepared statements — never "
    "concatenate user input into SQL. Apply server-side input validation, "
    "run the application DB account with least privilege, and add a WAF rule "
    "as defense-in-depth while the fix is deployed."
)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FMT)


def _first_payload_line(evidence: str) -> str | None:
    m = _PAYLOAD_LINE_RE.search(evidence or "")
    return m.group(1).strip() if m else None


def _severity_for(cand: SqliCandidate) -> str:
    """Small, explicit severity rule — no invented CVSS score (schemas.py has
    no such field).

    Default "High": any sqlmap-confirmed injection is a serious, real risk
    regardless of technique. Escalate to "Critical" only for UNION-based or
    error-based technique, which directly disclose/extract data (vs. a blind
    boolean/time-based signal, which is exploitable but needs more read
    amplification). This mirrors the exact High/Critical split modules/sqli.py
    already uses for its own direct-detection techniques.
    """
    technique = (cand.technique or "").lower()
    if "union" in technique or "error" in technique:
        return "Critical"
    return "High"


def candidate_to_finding(cand: SqliCandidate, *, target_url: str, scan_id: str) -> Finding:
    """Build a schema-valid Finding from a CONFIRMED injectable SqliCandidate.

    Raises ValueError if `cand` is not a confirmed injection — this is a
    caller-contract violation (only status=="injectable" candidates should
    ever be passed here), not a normal "no finding" outcome.
    """
    if cand.status != "injectable" or not cand.injectable:
        raise ValueError(
            f"candidate_to_finding requires a confirmed injectable candidate "
            f"(got status={cand.status!r}); clean/error/out_of_scope candidates "
            f"must never become a Finding"
        )

    parameter = cand.parameter or "unknown"
    technique = cand.technique or "unspecified technique"
    dbms = cand.dbms or "unknown DBMS"
    payload = _first_payload_line(cand.evidence) or (
        f"(no explicit payload captured — sqlmap argv: {' '.join(cand.sqlmap_argv)})"
    )

    evidence = (
        f"sqlmap confirmed SQL injection in parameter '{parameter}' "
        f"(technique: {technique}; DBMS: {dbms}). {_REMEDIATION}\n\n"
        f"--- sqlmap evidence (rung depth={cand.depth}) ---\n{cand.evidence.strip()}"
    )

    return Finding(
        type="SQLi",
        url=cand.endpoint_url or target_url,
        parameter=parameter,
        payload=payload,
        evidence=evidence,
        severity=_severity_for(cand),
        timestamp=_ts(),
    )


# ── XSS (engine/xss_agent.py) ────────────────────────────────────────────────

# Remediation guidance shared by every XSS Finding.
_XSS_REMEDIATION = (
    "Remediation: apply context-aware output encoding (HTML-entity encode for an "
    "HTML-body context, JS-string escape for a script context, URL-encode for a "
    "URL/attribute context) to every user-controlled value before it is reflected "
    "in a response. Prefer a templating engine with auto-escaping enabled, and "
    "deploy a Content-Security-Policy (CSP) header as defense-in-depth."
)


def _severity_for_xss(cand: XssCandidate) -> str:
    """Severity rule for a Dalfox-confirmed reflected XSS — no invented CVSS
    score (schemas.py has no such field).

    Always "High": a confirmed reflected XSS is a serious, real risk (arbitrary
    JS execution in the victim's session) regardless of injection context.
    Unlike SQLi's technique-based High/Critical split, Dalfox's `context` field
    (inHTML-none, inJS, inATTR, ...) is a syntactic classification, not a
    reliable signal of exploit severity — the agent only confirms REFLECTED
    XSS (no stored/persistence signal), so there is no honest basis to
    escalate any confirmed finding above High here.
    """
    return "High"


def xss_candidate_to_finding(cand: XssCandidate, *, target_url: str, scan_id: str) -> Finding:
    """Build a schema-valid Finding from a CONFIRMED injectable XssCandidate.

    Raises ValueError if `cand` is not a confirmed injection — this is a
    caller-contract violation (only status=="injectable" candidates should
    ever be passed here), not a normal "no finding" outcome.
    """
    if cand.status != "injectable" or not cand.injectable:
        raise ValueError(
            f"xss_candidate_to_finding requires a confirmed injectable candidate "
            f"(got status={cand.status!r}); clean/error/out_of_scope candidates "
            f"must never become a Finding"
        )

    parameter = cand.parameter or "unknown"
    context = cand.context or "unspecified context"
    payload = cand.payload or "(no explicit payload captured — see evidence)"

    evidence = (
        f"Dalfox confirmed reflected XSS in parameter '{parameter}' "
        f"(context: {context}). {_XSS_REMEDIATION}\n\n"
        f"--- dalfox evidence ---\n{cand.evidence.strip()}"
    )

    return Finding(
        type="XSS",
        url=cand.endpoint_url or target_url,
        parameter=parameter,
        payload=payload,
        evidence=evidence,
        severity=_severity_for_xss(cand),
        timestamp=_ts(),
    )
