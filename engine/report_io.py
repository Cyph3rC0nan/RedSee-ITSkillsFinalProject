# engine/report_io.py
"""
Audit-trail output writer for one agent run (SQLi's SqliAgentResult, XSS's
XssAgentResult, nuclei's NucleiAgentResult, or any future agent result with the
same candidates/usage/iterations/transcript/stopped_reason shape): the same
findings_<id>.json shape integration.py/red_report.py already consume, a
minimal hand-built SARIF 2.1.0 report (stdlib only — no SARIF dependency), and
a run.json execution/audit trail (usage, cost, stopped_reason, per-endpoint
status).

nuclei results are BROADER than the frozen schemas.py Finding enum
(SQLi/XSS/IDOR/BrokenAuth), so they DELIBERATELY do NOT become typed Findings and
NEVER enter findings_<id>.json. When a caller passes `nuclei_candidates`, the
found ones are surfaced ADDITIVELY into the SARIF file (ruleId from template_id),
a dedicated nuclei_<id>.json, and a run.json summary block — leaving the typed
findings_<id>.json and the SQLi/XSS SARIF/run output byte-for-byte unchanged.
report_io does not import the nuclei types; it duck-types candidates via getattr.

engine.recon_tools's httpx/tlsx ReconObservations ride the SAME path (D-017):
when a caller passes `recon_observations`, the "observed" ones are surfaced
ADDITIVELY into the SARIF file (ruleId from category), a dedicated
recon_<id>.json, and a run.json summary block — likewise duck-typed via getattr,
likewise NEVER entering findings_<id>.json, likewise byte-for-byte unchanged
when omitted.

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

# nuclei emits lower-case severities (info/low/medium/high/critical/unknown),
# distinct from the frozen Finding severities above. Map them to the same three
# SARIF levels; info is informational -> "note", unknown -> "warning" default.
_NUCLEI_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
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


def _nuclei_level(severity) -> str:
    """SARIF level for a nuclei severity string (lower-cased; default warning)."""
    return _NUCLEI_SEVERITY_TO_SARIF_LEVEL.get(
        (severity or "").strip().lower(), "warning")


def _nuclei_sarif_result(cand) -> dict:
    """SARIF result for one found NucleiCandidate. Duck-typed via getattr so
    report_io stays decoupled from engine.nuclei_agent. ruleId is the nuclei
    template id (BROADER than the frozen Finding enum — that is exactly why these
    are surfaced here in SARIF rather than as typed Findings)."""
    template_id = getattr(cand, "template_id", None) or "nuclei"
    matched_at = getattr(cand, "matched_at", None) or getattr(cand, "target", None) or ""
    evidence = getattr(cand, "evidence", "") or ""
    name = getattr(cand, "name", None) or template_id
    severity = getattr(cand, "severity", None)
    text = evidence or f"{name} [{severity}] at {matched_at}"
    return {
        "ruleId": template_id,
        "level": _nuclei_level(severity),
        "message": {"text": text},
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": matched_at}},
        }],
    }


def _nuclei_sarif_rules(found: list) -> list[dict]:
    """rules[] entries for the distinct template_ids among found candidates,
    sorted for determinism; rule name is the template's human name."""
    tid_to_name: dict = {}
    for c in found:
        tid = getattr(c, "template_id", None)
        if tid and tid not in tid_to_name:
            tid_to_name[tid] = getattr(c, "name", None) or tid
    return [{"id": tid, "name": tid_to_name[tid]} for tid in sorted(tid_to_name)]


def _recon_sarif_result(obs) -> dict:
    """SARIF result for one observed ReconObservation (httpx/tlsx). Duck-typed
    via getattr so report_io stays decoupled from engine.recon_tools. ruleId is
    the recon category (e.g. "http-fingerprint", "tls-self-signed") — BROADER
    than the frozen Finding enum, same reasoning as nuclei (D-017). Severity is
    already title-case ("Low"/"Medium"), the same convention Finding uses, so
    the existing _SEVERITY_TO_SARIF_LEVEL map is reused directly."""
    category = getattr(obs, "category", None) or "recon"
    target = getattr(obs, "target", None) or ""
    evidence = getattr(obs, "evidence", "") or ""
    title = getattr(obs, "title", None) or category
    severity = getattr(obs, "severity", None)
    text = evidence or title
    return {
        "ruleId": category,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
        "message": {"text": text},
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": target}},
        }],
    }


def _recon_sarif_rules(observed: list) -> list[dict]:
    """rules[] entries for the distinct categories among observed observations,
    sorted for determinism; rule name is the tool + category."""
    cat_to_name: dict = {}
    for o in observed:
        cat = getattr(o, "category", None)
        if cat and cat not in cat_to_name:
            tool = getattr(o, "tool", None) or "recon"
            cat_to_name[cat] = f"{tool}:{cat}"
    return [{"id": cat, "name": cat_to_name[cat]} for cat in sorted(cat_to_name)]


def _build_sarif(findings: list[Finding], nuclei_candidates=None,
                 recon_observations=None) -> dict:
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

    # Additively surface found nuclei candidates (broader than the Finding enum,
    # so SARIF-only — never typed Findings). Appended AFTER the Finding results/
    # rules so that with no nuclei input the output is byte-for-byte unchanged.
    found = [c for c in (nuclei_candidates or [])
             if getattr(c, "status", None) == "found"]
    if found:
        results += [_nuclei_sarif_result(c) for c in found]
        rules += _nuclei_sarif_rules(found)

    # Additively surface observed recon (httpx/tlsx) observations — same
    # broader-than-Finding-enum reasoning (D-017), appended AFTER nuclei so with
    # no recon input the output (including the nuclei-augmented case) is
    # byte-for-byte unchanged.
    observed = [o for o in (recon_observations or [])
                if getattr(o, "status", None) == "observed"]
    if observed:
        results += [_recon_sarif_result(o) for o in observed]
        rules += _recon_sarif_rules(observed)

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
    seen (injectable/clean/error/out_of_scope, or found/clean/error for nuclei) —
    the audit-trail answer to "what did we actually scan, and what happened".
    The scanned URL is read as `endpoint_url` (SQLi/XSS candidates) falling back
    to `target` (NucleiCandidate) via getattr, so this stays agent-type-agnostic
    and SQLi/XSS output is unchanged. `max_depth` (the deepest SQLi ladder rung
    reached) is included only for candidates that carry a `depth` field
    (SqliCandidate); XSS/nuclei have no notion of depth, so it is omitted.
    """
    summary: dict = {}
    for c in result.candidates:
        url = getattr(c, "endpoint_url", None) or getattr(c, "target", None) or ""
        entry = summary.setdefault(url, {"statuses": []})
        entry["statuses"].append(c.status)
        depth = getattr(c, "depth", None)
        if depth is not None:
            entry["max_depth"] = max(entry.get("max_depth", 0), depth)
    return summary


def _nuclei_candidate_dict(cand) -> dict:
    """Serialize one NucleiCandidate to the raw audit shape for nuclei_<id>.json.
    Duck-typed via getattr so report_io does not depend on engine.nuclei_agent."""
    return {
        "target": getattr(cand, "target", None),
        "template_id": getattr(cand, "template_id", None),
        "name": getattr(cand, "name", None),
        "severity": getattr(cand, "severity", None),
        "matched_at": getattr(cand, "matched_at", None),
        "evidence": getattr(cand, "evidence", "") or "",
        "status": getattr(cand, "status", None),
    }


def _nuclei_summary(candidates: list) -> dict:
    """run.json summary block for a nuclei run: counts by status
    (found/clean/error/...) and, for the found ones, counts by nuclei severity."""
    by_status: dict = {}
    by_severity: dict = {}
    for c in candidates:
        status = getattr(c, "status", None)
        by_status[status] = by_status.get(status, 0) + 1
        if status == "found":
            sev = (getattr(c, "severity", None) or "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "total": len(candidates),
        "found": by_status.get("found", 0),
        "clean": by_status.get("clean", 0),
        "error": by_status.get("error", 0),
        "count_by_status": by_status,
        "count_by_severity": by_severity,   # found candidates only
    }


def _recon_observation_dict(obs) -> dict:
    """Serialize one ReconObservation to the raw audit shape for recon_<id>.json.
    Duck-typed via getattr so report_io does not depend on engine.recon_tools."""
    return {
        "tool": getattr(obs, "tool", None),
        "target": getattr(obs, "target", None),
        "category": getattr(obs, "category", None),
        "title": getattr(obs, "title", None),
        "severity": getattr(obs, "severity", None),
        "evidence": getattr(obs, "evidence", "") or "",
        "status": getattr(obs, "status", None),
        "error": getattr(obs, "error", None),
    }


def _recon_summary(observations: list) -> dict:
    """run.json summary block for a recon (httpx/tlsx) run: counts BY TOOL and,
    for the observed ones, counts by severity."""
    by_tool: dict = {}
    by_status: dict = {}
    by_severity: dict = {}
    for o in observations:
        tool = getattr(o, "tool", None) or "unknown"
        status = getattr(o, "status", None)
        by_tool[tool] = by_tool.get(tool, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        if status == "observed":
            sev = (getattr(o, "severity", None) or "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "total": len(observations),
        "observed": by_status.get("observed", 0),
        "error": by_status.get("error", 0),
        "out_of_scope": by_status.get("out_of_scope", 0),
        "count_by_tool": by_tool,
        "count_by_severity": by_severity,   # observed only
    }


def _build_run_json(result: _AgentResult, *, scan_id: str, target_url: str,
                    llm_meta: dict | None = None,
                    nuclei_candidates=None, recon_observations=None) -> dict:
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
    # nuclei/recon summaries are added ONLY when that input was passed, so a
    # plain SQLi/XSS run.json is byte-for-byte unchanged.
    if nuclei_candidates is not None:
        doc["nuclei"] = _nuclei_summary(nuclei_candidates)
    if recon_observations is not None:
        doc["recon"] = _recon_summary(recon_observations)
    return doc


def write_outputs(agent_result: _AgentResult, findings: list[Finding], *,
                  scan_id: str, target_url: str, out_dir: str = "outputs",
                  llm_meta: dict | None = None,
                  nuclei_candidates=None, recon_observations=None) -> dict:
    """Write findings_<scan_id>.json, findings_<scan_id>.sarif, and
    run_<scan_id>.json into out_dir (created if missing).

    `agent_result` may be a SqliAgentResult, an XssAgentResult, a
    NucleiAgentResult, or any other agent result with the same candidates/usage/
    iterations/transcript/stopped_reason shape — this writer is agent-type-agnostic.

    findings_<scan_id>.json is the exact shape integration.py already writes
    and red_report.py already reads: a plain JSON list of Finding.to_dict().
    nuclei/recon results NEVER enter it (both are broader than the frozen
    Finding enum — see DECISIONS.md D-017).

    `nuclei_candidates` (optional): a list of NucleiCandidate-shaped objects. When
    provided (even if empty), the found ones are added to the SARIF report, the
    full raw list is written to nuclei_<scan_id>.json, and a nuclei summary block
    is added to run_<scan_id>.json.

    `recon_observations` (optional): a list of ReconObservation-shaped objects
    (engine.recon_tools's httpx/tlsx output). When provided (even if empty), the
    "observed" ones are added to the SAME SARIF report (ruleId from category),
    the full raw list is written to recon_<scan_id>.json, and a recon summary
    block (counts by tool + by severity) is added to run_<scan_id>.json.

    When BOTH nuclei_candidates and recon_observations are omitted (None), the
    SARIF, findings, and run outputs are byte-for-byte identical to a plain
    SQLi/XSS run.

    Returns {"findings": path, "sarif": path, "run": path} — plus "nuclei": path
    when nuclei_candidates was provided, and "recon": path when
    recon_observations was provided.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    findings_path = out / f"findings_{scan_id}.json"
    findings_path.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")

    sarif_path = out / f"findings_{scan_id}.sarif"
    sarif_path.write_text(
        json.dumps(_build_sarif(findings, nuclei_candidates, recon_observations),
                   indent=2),
        encoding="utf-8")

    run_path = out / f"run_{scan_id}.json"
    run_path.write_text(
        json.dumps(_build_run_json(agent_result, scan_id=scan_id,
                                   target_url=target_url, llm_meta=llm_meta,
                                   nuclei_candidates=nuclei_candidates,
                                   recon_observations=recon_observations),
                   indent=2),
        encoding="utf-8")

    paths = {
        "findings": str(findings_path),
        "sarif": str(sarif_path),
        "run": str(run_path),
    }

    # Dedicated nuclei JSON — the raw candidate list. Written ONLY when nuclei
    # input was passed, so a plain SQLi/XSS run produces no extra file.
    if nuclei_candidates is not None:
        nuclei_path = out / f"nuclei_{scan_id}.json"
        nuclei_path.write_text(
            json.dumps([_nuclei_candidate_dict(c) for c in nuclei_candidates],
                       indent=2),
            encoding="utf-8")
        paths["nuclei"] = str(nuclei_path)

    # Dedicated recon JSON — the raw observation list. Written ONLY when recon
    # input was passed, so a plain SQLi/XSS/nuclei run produces no extra file.
    if recon_observations is not None:
        recon_path = out / f"recon_{scan_id}.json"
        recon_path.write_text(
            json.dumps([_recon_observation_dict(o) for o in recon_observations],
                       indent=2),
            encoding="utf-8")
        paths["recon"] = str(recon_path)

    return paths
