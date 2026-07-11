# engine/report_io.py
"""
Audit-trail output writer for one agent run (SQLi's SqliAgentResult, XSS's
XssAgentResult, or any future agent result with the same
candidates/usage/iterations/transcript/stopped_reason shape): the same
findings_<id>.json shape integration.py/red_report.py already consume, a
minimal hand-built SARIF 2.1.0 report (stdlib only — no SARIF dependency), and
a run.json execution/audit trail (usage, cost, stopped_reason, per-endpoint
status).

run.json NEVER contains secrets: any caller-supplied llm_meta is defensively
stripped of key/token/secret/authorization-shaped fields before writing.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from schemas import Finding
from engine.agent import SqliAgentResult
from engine.xss_agent import XssAgentResult

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

_AgentResult = Union[SqliAgentResult, XssAgentResult]

# Severity -> SARIF result level, per the SARIF 2.1.0 spec's three severity
# levels (there is no fourth "critical" level in SARIF, so Critical maps to
# the same "error" level as High).
_SEVERITY_TO_SARIF_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}

# Finding.type -> descriptive SARIF rule name (schemas.py's exact type
# strings). Falls back to the type string itself for any future/unknown type.
_RULE_NAMES = {
    "SQLi": "SQLInjection",
    "XSS": "CrossSiteScripting",
    "IDOR": "InsecureDirectObjectReference",
    "BrokenAuth": "BrokenAuthentication",
}

# Defensive secret scrub for llm_meta: any key containing one of these
# substrings is dropped before it can reach run.json, regardless of what a
# caller passes in.
_SECRET_KEY_MARKERS = ("key", "token", "secret", "authorization", "password")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FMT)


def _scrub_secrets(meta: dict | None) -> dict | None:
    if not meta:
        return None
    return {
        k: v for k, v in meta.items()
        if not any(marker in k.lower() for marker in _SECRET_KEY_MARKERS)
    }


def _build_sarif(findings: list[Finding]) -> dict:
    # ruleId comes from each Finding's own `type` (schemas.py's exact enum:
    # SQLi/XSS/IDOR/BrokenAuth) — never hardcoded to one vuln class, so a
    # mixed or XSS-only findings list gets correctly-labeled SARIF results.
    results = [
        {
            "ruleId": f.type,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.evidence}\n\nPayload: {f.payload}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": f.url}},
            }],
        }
        for f in findings
    ]
    # Only declare rules for the vuln types actually present in this run.
    rule_ids = sorted({f.type for f in findings})
    rules = [{"id": rid, "name": _RULE_NAMES.get(rid, rid)} for rid in rule_ids]
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RedSee",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def _endpoint_status_summary(result: _AgentResult) -> dict:
    """One entry per endpoint URL actually attempted, listing every status
    seen (injectable/clean/error/out_of_scope) — the audit-trail answer to
    "what did we actually scan, and what happened". `max_depth` (the deepest
    SQLi ladder rung reached) is included only for candidates that carry a
    `depth` field (SqliCandidate); XssCandidate has no notion of depth, so it
    is simply omitted rather than fabricated.
    """
    summary: dict = {}
    for c in result.candidates:
        entry = summary.setdefault(c.endpoint_url, {"statuses": []})
        entry["statuses"].append(c.status)
        depth = getattr(c, "depth", None)
        if depth is not None:
            entry["max_depth"] = max(entry.get("max_depth", 0), depth)
    return summary


def _build_run_json(result: _AgentResult, *, scan_id: str, target_url: str,
                    llm_meta: dict | None = None) -> dict:
    usage = result.usage
    doc = {
        "scan_id": scan_id,
        "target_url": target_url,
        "timestamp": _ts(),
        "stopped_reason": result.stopped_reason,
        "iterations": result.iterations,
        "usage": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cost_usd": usage.cost_usd,
            "calls": usage.calls,
        },
        "endpoint_status_summary": _endpoint_status_summary(result),
        "transcript": result.transcript,
    }
    scrubbed = _scrub_secrets(llm_meta)
    if scrubbed:
        doc["llm"] = scrubbed
    return doc


def write_outputs(agent_result: _AgentResult, findings: list[Finding], *,
                  scan_id: str, target_url: str, out_dir: str = "outputs",
                  llm_meta: dict | None = None) -> dict:
    """Write findings_<scan_id>.json, findings_<scan_id>.sarif, and
    run_<scan_id>.json into out_dir (created if missing).

    `agent_result` may be a SqliAgentResult or an XssAgentResult (or any other
    agent result with the same candidates/usage/iterations/transcript/
    stopped_reason shape) — this writer is agent-type-agnostic.

    findings_<scan_id>.json is the exact shape integration.py already writes
    and red_report.py already reads: a plain JSON list of Finding.to_dict().

    Returns {"findings": path, "sarif": path, "run": path} (str paths).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    findings_path = out / f"findings_{scan_id}.json"
    findings_path.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")

    sarif_path = out / f"findings_{scan_id}.sarif"
    sarif_path.write_text(json.dumps(_build_sarif(findings), indent=2), encoding="utf-8")

    run_path = out / f"run_{scan_id}.json"
    run_path.write_text(
        json.dumps(_build_run_json(agent_result, scan_id=scan_id,
                                   target_url=target_url, llm_meta=llm_meta),
                   indent=2),
        encoding="utf-8")

    return {
        "findings": str(findings_path),
        "sarif": str(sarif_path),
        "run": str(run_path),
    }
