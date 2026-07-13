# modules/scan.py
"""
Unified scan orchestrator — the aggregation spine.

`run_scan(target_url)` runs ONE authorized target end-to-end:

    crawl -> vuln agents (sqli, xss) -> recon (nuclei, httpx, tlsx, ffuf) -> aggregate

and writes ONE new `outputs/scan_<id>.json` that unifies everything, ALONGSIDE (never
instead of) the existing per-tool outputs from `engine.report_io.write_outputs`
(`findings_<id>.json` / `.sarif` / `run_<id>.json` / `nuclei_<id>.json` /
`recon_<id>.json`). All artifacts from ONE run share ONE bare scan_id — directly
addressing the "two differently-named findings files" known-limitation in AGENTS.md:
the unified view is keyed by a single id, `scan_<id>.json`.

Why modules/scan.py and NOT engine/orchestrator.py:
  This spine imports BOTH the modules layer (`modules.sqli.scan_sqli`,
  `modules.xss.scan_xss`) AND the engine layer (`engine.recon_tools`,
  `engine.nuclei_agent`). The repo's dependency direction is modules -> engine —
  nothing in `engine/` imports `modules/` (verified). Putting the spine in `engine/`
  would invert that layering (engine importing modules). `modules/recon.py` already
  establishes the "run several things + write outputs" runner pattern at the modules
  layer; this spine is a strict superset of it (adds crawl + the two vuln agents), so
  it belongs beside it. Live entry point is therefore `python -m modules.scan`.

Discipline (mirrors modules/recon.py + the recon_tools status="error" contract):
  * Authorization + scope gate FIRST — an unauthorized/out-of-scope target is refused
    (ScopeError) before ANY artifact is written. No partial run.
  * Every tool is wrapped: a single tool's failure is recorded as an "error" entry and
    the scan CONTINUES — one tool never aborts the whole scan, and a failed tool never
    fabricates results (its section stays empty, exactly like status="error").
  * schemas.py is FROZEN: the unified record is a NEW json artifact, not a schema type.
  * report_io is reused untouched (write_outputs + its secret scrubber + its per-tool
    serializers), so the existing per-tool outputs stay byte-for-byte as they are today.

NOT wired into integration.py's resolver or app.py — that is a later task.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from crawler import crawl
from modules.sqli import scan_sqli
from modules.xss import scan_xss
from engine.nuclei_agent import run_nuclei_agent, _target_url
from engine.recon_tools import run_httpx, run_tlsx, run_ffuf
from engine.report_io import (
    write_outputs, _scrub_secrets,
    _nuclei_candidate_dict, _recon_observation_dict,
)
from engine.scope import load_scope_config, require_authorization, assert_in_scope
from engine.llm import Usage

try:
    from engine.llm import load_llm_config as _load_llm_config, LLMError as _LLMError
    _HAS_LLM = True
except ImportError:                                   # pragma: no cover - defensive
    _HAS_LLM = False

# Canonical Finding severities (schemas.py: exactly these four). The rollup always
# reports all four (0 when absent) so the dashboard gets a stable shape.
_SEVERITIES = ("Critical", "High", "Medium", "Low")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Per-tool wrapper: a failure is an error entry, never a scan abort ────────

# Sentinel distinguishing "the tool raised" from "the tool returned None/[]".
_FAILED = object()


def _safe(fn):
    """Run fn(); return (result, None) on success or (_FAILED, reason) on ANY
    exception. NEVER re-raises — a single tool's failure must not abort the scan,
    and its caller records an error entry instead of fabricating a result."""
    try:
        return fn(), None
    except Exception as exc:                          # noqa: BLE001 - deliberate catch-all
        return _FAILED, f"{type(exc).__name__}: {exc}"


def _record(tools_run: list, name: str, status: str, count: int, detail: str) -> None:
    tools_run.append({"name": name, "status": status,
                      "count": int(count), "detail": detail})


def _classify_results(items: list, positive: str) -> tuple:
    """(status, count, detail) for a tools_run entry from a list of
    status-bearing results (recon ReconObservations or nuclei NucleiCandidates).

    `positive` is the status that counts as a real result ("observed" or
    "found"). The recon/nuclei tools do NOT raise on a sandbox/isolation failure
    — they return a status="error" result instead — so this classifier surfaces
    that honestly rather than reporting a misleading "ran, 0":
      * any positives          -> "ran"    (count = number of positives)
      * results, ALL errored   -> "error"  (e.g. sandbox unreachable — the real
                                             per-result error reason is the detail)
      * results, ALL out-of-scope -> "skipped"
      * ran but nothing positive (e.g. nuclei clean) -> "ran", count 0
      * no results at all       -> "ran", count 0 ("no results")
    """
    n = len(items)
    if n == 0:
        return "ran", 0, "no results"
    statuses = [getattr(i, "status", None) for i in items]
    pos = sum(1 for s in statuses if s == positive)
    err = sum(1 for s in statuses if s == "error")
    oos = sum(1 for s in statuses if s == "out_of_scope")
    if pos == 0 and err == n:
        reason = next((getattr(i, "error", None) for i in items
                       if getattr(i, "status", None) == "error"), None)
        return "error", 0, (reason or "all targets errored")[:300]
    if pos == 0 and oos == n:
        return "skipped", 0, "out of scope"
    detail = f"{pos} {positive}"
    if err:
        detail += f", {err} errored"
    if oos:
        detail += f", {oos} out-of-scope"
    return "ran", pos, detail


# ── Small helpers ───────────────────────────────────────────────────────────

def _live_urls_from_httpx(httpx_observations: list, seed_targets: list) -> list:
    """ffuf targets: the DISTINCT base URLs httpx actually confirmed live
    (status="observed"), first-seen order; falls back to the seed targets when
    httpx found nothing live. Reimplemented locally (not imported from
    modules.recon) to keep this spine self-contained — same rationale the recon
    layer uses for reimplementing trivial helpers rather than cross-coupling."""
    live: list = []
    seen = set()
    for o in httpx_observations:
        if getattr(o, "status", None) != "observed":
            continue
        target = getattr(o, "target", None)
        if target and target not in seen:
            seen.add(target)
            live.append(target)
    if live:
        return live
    return [_target_url(t) for t in seed_targets if _target_url(t)]


def _severity_rollup(findings: list) -> dict:
    """Counts by Finding severity — all four canonical levels always present."""
    roll = {sev: 0 for sev in _SEVERITIES}
    for f in findings:
        sev = getattr(f, "severity", None)
        roll[sev] = roll.get(sev, 0) + 1
    return roll


def _build_llm_meta():
    """Non-secret LLM run metadata (provider/model/spend-cap), mirroring
    modules/sqli.py's block. A module-level function so tests can override it to
    prove the secret scrub is wired. The result is ALWAYS run through
    report_io._scrub_secrets before it reaches any artifact."""
    if not _HAS_LLM:
        return None
    try:
        cfg = _load_llm_config()
    except Exception:                                 # noqa: BLE001 - LLM optional
        return None
    return {"provider": cfg.base_url, "model": cfg.model, "max_usd": cfg.max_usd}


def _redsee_version():
    """Installed RedSee package version if it happens to be installed, else None
    (this repo ships no version metadata today)."""
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("redsee")
        except PackageNotFoundError:
            return None
    except Exception:                                 # noqa: BLE001 - defensive
        return None


class _EmptyAgentResult:
    """Stand-in agent_result for write_outputs when the nuclei agent itself
    failed (so run_<id>.json is still produced). Carries the same
    candidates/usage/iterations/transcript/stopped_reason shape write_outputs
    reads, all empty — never fabricated scan data."""

    def __init__(self, stopped_reason: str = "error"):
        self.candidates: list = []
        self.usage = Usage(input_tokens=0, output_tokens=0, cost_usd=0.0, calls=0)
        self.iterations = 0
        self.transcript: list = []
        self.stopped_reason = stopped_reason


# ── Orchestrator ────────────────────────────────────────────────────────────

def run_scan(target_url: str, *, scope_config=None, scan_id: str | None = None,
             out_dir: str = "outputs") -> dict:
    """Run a full end-to-end scan of ONE authorized target and write the unified
    outputs/scan_<id>.json (plus the existing per-tool artifacts, all sharing the
    one scan_id).

    Gating (engine.scope, reused — never reimplemented) runs FIRST:
    require_authorization + assert_in_scope. An unauthorized or out-of-scope
    target raises ScopeError and NOTHING is written (no partial run).

    Each stage (crawl, sqli, xss, nuclei, httpx, tlsx, ffuf) is wrapped so a
    single stage's failure is recorded as a tools_run "error" entry and the scan
    continues; a failed stage contributes no findings/observations (never
    fabricated). ffuf is chained off httpx's live URLs (mirrors modules/recon.py).

    Returns the unified record dict (also written to outputs/scan_<id>.json).
    """
    # 1. GATE FIRST — refuse before writing anything.
    if scope_config is None:
        scope_config = load_scope_config()
    require_authorization(scope_config)
    assert_in_scope(target_url, scope_config)

    # 2. ONE bare scan_id for EVERY artifact this run (unified file is scan_<id>.json;
    #    per-tool files are findings_<id>.json / run_<id>.json / nuclei_<id>.json /
    #    recon_<id>.json — same id).
    scan_id = scan_id or uuid.uuid4().hex[:8]
    started_at = _ts()
    tools_run: list = []

    # 3. Crawl -> endpoints.
    res, err = _safe(lambda: crawl(target_url))
    if err is not None:
        endpoints: list = []
        _record(tools_run, "crawl", "error", 0, err)
    else:
        endpoints = list(res.endpoints)
        _record(tools_run, "crawl", "ran", len(endpoints), f"{len(endpoints)} endpoints")

    # 4. Vuln agents (typed Findings). Skipped cleanly when crawl found nothing to
    #    test — a skip is NOT an error and NOT a fabricated empty result.
    if endpoints:
        res, err = _safe(lambda: scan_sqli(endpoints))
        if err is not None:
            sqli_findings: list = []
            _record(tools_run, "sqli", "error", 0, err)
        else:
            sqli_findings = list(res or [])
            _record(tools_run, "sqli", "ran", len(sqli_findings),
                    f"{len(sqli_findings)} finding(s)")

        res, err = _safe(lambda: scan_xss(endpoints))
        if err is not None:
            xss_findings: list = []
            _record(tools_run, "xss", "error", 0, err)
        else:
            xss_findings = list(res or [])
            _record(tools_run, "xss", "ran", len(xss_findings),
                    f"{len(xss_findings)} finding(s)")
    else:
        sqli_findings = []
        xss_findings = []
        _record(tools_run, "sqli", "skipped", 0, "no endpoints from crawl")
        _record(tools_run, "xss", "skipped", 0, "no endpoints from crawl")

    findings = sqli_findings + xss_findings

    # 5. Recon. nuclei (LLM-driven) + httpx/tlsx (deterministic) run against the
    #    target directly; ffuf is chained off httpx's live URLs.
    res, err = _safe(lambda: run_nuclei_agent([target_url], scope_config=scope_config))
    if err is not None:
        nuclei_result = None
        nuclei_candidates: list = []
        _record(tools_run, "nuclei", "error", 0, err)
    else:
        nuclei_result = res
        nuclei_candidates = list(res.candidates)
        _record(tools_run, "nuclei", *_classify_results(nuclei_candidates, "found"))

    res, err = _safe(lambda: run_httpx([target_url], scope_config=scope_config))
    if err is not None:
        httpx_obs: list = []
        _record(tools_run, "httpx", "error", 0, err)
    else:
        httpx_obs = list(res or [])
        _record(tools_run, "httpx", *_classify_results(httpx_obs, "observed"))

    res, err = _safe(lambda: run_tlsx([target_url], scope_config=scope_config))
    if err is not None:
        tlsx_obs: list = []
        _record(tools_run, "tlsx", "error", 0, err)
    else:
        tlsx_obs = list(res or [])
        _record(tools_run, "tlsx", *_classify_results(tlsx_obs, "observed"))

    ffuf_targets = _live_urls_from_httpx(httpx_obs, [target_url])
    res, err = _safe(lambda: run_ffuf(ffuf_targets, scope_config=scope_config))
    if err is not None:
        ffuf_obs: list = []
        _record(tools_run, "ffuf", "error", 0, err)
    else:
        ffuf_obs = list(res or [])
        _record(tools_run, "ffuf", *_classify_results(ffuf_obs, "observed"))

    recon_observations = httpx_obs + tlsx_obs + ffuf_obs
    finished_at = _ts()

    # 6. Existing per-tool outputs, UNCHANGED — reuse write_outputs as-is, under the
    #    ONE shared scan_id. Empty lists (not None) are passed so nuclei_<id>.json and
    #    recon_<id>.json are always produced even if that tool errored (empty, not
    #    fabricated). llm_meta is passed raw; write_outputs scrubs it for run.json.
    llm_meta_raw = _build_llm_meta()
    agent_result = nuclei_result if nuclei_result is not None else _EmptyAgentResult()
    paths = write_outputs(
        agent_result, findings,
        scan_id=scan_id, target_url=target_url, out_dir=out_dir,
        llm_meta=llm_meta_raw,
        nuclei_candidates=nuclei_candidates,
        recon_observations=recon_observations,
    )

    # 7. Unified record. Tool sections reuse report_io's OWN serializers, so the
    #    shapes match nuclei_<id>.json / recon_<id>.json exactly. Secret-scrubbed
    #    with report_io's scrubber, same as run_<id>.json.
    observed = sum(1 for o in recon_observations if getattr(o, "status", None) == "observed")
    record = {
        "scan_id": scan_id,
        "target": target_url,
        "started_at": started_at,
        "finished_at": finished_at,
        "redsee_version": _redsee_version(),
        "tools_run": tools_run,
        "findings": [f.to_dict() for f in findings],
        "recon": {
            "nuclei": [_nuclei_candidate_dict(c) for c in nuclei_candidates],
            "observations": [_recon_observation_dict(o) for o in recon_observations],
        },
        "summary": {
            "findings_total": len(findings),
            "findings_by_severity": _severity_rollup(findings),
            "recon_observations": observed,
            "tools_ok": sum(1 for t in tools_run if t["status"] == "ran"),
            "tools_error": sum(1 for t in tools_run if t["status"] == "error"),
            "tools_skipped": sum(1 for t in tools_run if t["status"] == "skipped"),
            "tools_total": len(tools_run),
        },
        "outputs": {**paths, "scan": None},   # "scan" filled in just below
    }
    scrubbed_meta = _scrub_secrets(llm_meta_raw)
    if scrubbed_meta:
        record["llm"] = scrubbed_meta

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    scan_path = out / f"scan_{scan_id}.json"
    record["outputs"]["scan"] = str(scan_path)
    scan_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    return record


# ── Opt-in live entry point ─────────────────────────────────────────────────
if __name__ == "__main__":
    # Requires: .env configured (scope + LLM), sandbox image built
    # (bash docker/sandbox/build.sh), a running Ollama, and a reachable in-scope
    # target. .env is loaded automatically (override=False, so real env wins).
    #
    #   REDSEE_AUTHORIZED=true REDSEE_ALLOWED_HOSTS=redsees.com \
    #   REDSEE_TARGET_URL=http://redsees.com:3000/ \
    #   REDSEE_LLM_BASE_URL=http://localhost:11434/v1 REDSEE_LLM_MODEL=llama3.2 \
    #   REDSEE_LLM_MAX_USD=0.50 PYTHONPATH=. python -m modules.scan
    import os

    from engine.env import load_env
    load_env()

    target = os.environ.get("REDSEE_TARGET_URL") or "http://localhost:8080/"

    record = run_scan(target)
    print(f"scan_id={record['scan_id']} target={record['target']}")
    print(f"started={record['started_at']} finished={record['finished_at']}")
    print("tools_run:")
    for t in record["tools_run"]:
        print(f"  {t['name']:<7} {t['status']:<8} count={t['count']:<3} {t['detail']}")
    s = record["summary"]
    print(f"findings: {s['findings_total']} {s['findings_by_severity']}")
    print(f"recon observations: {s['recon_observations']}")
    print(f"tools ok/err/skip: {s['tools_ok']}/{s['tools_error']}/{s['tools_skipped']}")
    print("outputs:")
    for kind, path in record["outputs"].items():
        print(f"  {kind}: {path}")
