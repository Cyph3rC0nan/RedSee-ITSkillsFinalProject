# modules/scan.py
"""
Unified scan orchestrator — the aggregation spine.

`run_scan(target_url, *, mode=...)` runs ONE authorized target end-to-end:

    crawl -> extract injectable params -> vuln agents (sqli, xss) on PARAM-BEARING
    targets only -> recon (scoped nuclei, httpx, tlsx, ffuf) -> aggregate

Independent tools run CONCURRENTLY under a conservative sandbox-parallelism bound,
and a scan MODE (fast / standard / deep) tunes how many endpoints are injected, how
deep the injection goes, and which recon runs. The orchestrator drives the engine
agents (run_sqli_agent / run_xss_agent / run_nuclei_agent) DIRECTLY so it can set
per-mode depth/timeout — it does not go through modules/sqli.py's fixed-signature
scan_sqli (which cannot carry mode/depth). Injection targets come from
engine.params (query-string + form/body params); a param-less endpoint is never
handed to sqlmap/Dalfox (wasted sandbox time, only ever an empty result).

It writes ONE new `outputs/scan_<id>.json` that unifies everything, ALONGSIDE (never
instead of) the existing per-tool outputs from `engine.report_io.write_outputs`
(`findings_<id>.json` / `.sarif` / `run_<id>.json` / `nuclei_<id>.json` /
`recon_<id>.json`). All artifacts from ONE run share ONE bare scan_id — directly
addressing the "two differently-named findings files" known-limitation in AGENTS.md:
the unified view is keyed by a single id, `scan_<id>.json`.

Why modules/scan.py (not engine/orchestrator.py):
  storage/scan_store.py imports this module, so the dependency direction is
  storage -> modules -> engine; nothing in engine/ imports modules/. This spine is
  a COMPOSITION over the engine layer (crawl + agents + recon + aggregation) — a
  higher-level concern than any single engine module — and `modules/recon.py`
  already establishes the "run several tools + write outputs" runner pattern here.
  Live entry point is `python -m modules.scan`.

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
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from crawler import crawl
from engine.params import select_injection_targets
from engine.agent import run_sqli_agent
from engine.xss_agent import run_xss_agent
from engine.finding_map import candidate_to_finding, xss_candidate_to_finding
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

# The full, fixed order tools_run is reported in — INDEPENDENT of the order the
# concurrent stages actually finish, so the record shape is deterministic and a
# deep-mode scan is byte-stable vs. the serial version.
_TOOL_ORDER = ("crawl", "sqli", "xss", "nuclei", "httpx", "tlsx", "ffuf")


# ── Scan modes ───────────────────────────────────────────────────────────────
# A scan MODE tunes breadth (how many endpoints are injected), depth (how hard the
# injection agents push), and which recon runs. It is a RUNTIME profile, never a
# schemas.py field. Deep == the pre-mode behavior (all param-bearing endpoints, the
# agents' own default caps, every recon tool).

@dataclass(frozen=True)
class ScanProfile:
    name: str
    # None = no cap (inject every param-bearing endpoint); an int caps how many of
    # the deterministically-ranked injection targets get the sqlmap/Dalfox treatment.
    max_injection_targets: int | None
    sqli_max_level: int
    sqli_max_risk: int
    sqli_max_iterations: int
    xss_max_iterations: int
    # Per-sandbox-run wall-clock for the injection agents; None = the agents' default.
    injection_timeout_sec: int | None
    run_httpx: bool
    run_tlsx: bool
    run_ffuf: bool
    run_nuclei: bool
    # Scoped template tags for nuclei's deterministic pass; None = its default profile.
    nuclei_tags: tuple[str, ...] | None
    # Per-scan wall-clock bound for nuclei; None = the nuclei agent's default.
    nuclei_timeout_sec: int | None


_PROFILES = {
    # ~2 min: only the top few param-bearing endpoints, a shallow single-rung
    # injection (level/risk 1, tight timeout, few iterations), and the two cheap
    # deterministic recon probes only (no nuclei template scan, no ffuf brute-force).
    "fast": ScanProfile(
        name="fast", max_injection_targets=5,
        sqli_max_level=1, sqli_max_risk=1, sqli_max_iterations=2, xss_max_iterations=2,
        injection_timeout_sec=60,
        run_httpx=True, run_tlsx=True, run_ffuf=False, run_nuclei=False,
        nuclei_tags=None, nuclei_timeout_sec=None,
    ),
    # ~5-8 min: ~10 endpoints, medium injection depth, and the full recon set with a
    # SCOPED, wall-clock-bounded nuclei scan. The template set is memory-bounded by
    # engine.nuclei_agent (exposures + misconfiguration dirs — the whole corpus OOMs
    # the 256 MB sandbox); these tags scope within it.
    "standard": ScanProfile(
        name="standard", max_injection_targets=10,
        sqli_max_level=3, sqli_max_risk=2, sqli_max_iterations=4, xss_max_iterations=3,
        injection_timeout_sec=120,
        run_httpx=True, run_tlsx=True, run_ffuf=True, run_nuclei=True,
        nuclei_tags=("exposure", "misconfig"), nuclei_timeout_sec=300,
    ),
    # The pre-mode behavior: every param-bearing endpoint, the agents' own default
    # caps, the full recon set with nuclei's default profile. "deep unchanged."
    "deep": ScanProfile(
        name="deep", max_injection_targets=None,
        sqli_max_level=3, sqli_max_risk=2, sqli_max_iterations=6, xss_max_iterations=6,
        injection_timeout_sec=None,
        run_httpx=True, run_tlsx=True, run_ffuf=True, run_nuclei=True,
        nuclei_tags=None, nuclei_timeout_sec=None,
    ),
}

DEFAULT_MODE = "standard"


def resolve_profile(mode) -> ScanProfile:
    """The ScanProfile for `mode`; an unknown/empty mode falls back to the default
    (never raises — a bad mode string should degrade to a sane scan, not abort)."""
    key = (mode or "").strip().lower()
    return _PROFILES.get(key, _PROFILES[DEFAULT_MODE])


def _max_parallel_sandboxes() -> int:
    """Conservative bound on how many stages (and therefore sandboxes) run at once.

    Default 2 — verified safe live; each concurrent stage spawns at most one sandbox
    at a time, so at most this many isolated containers/networks coexist. Kept small
    on purpose: run_in_sandbox sets up per-run iptables egress rules, and stray rules
    from a KILLED run have collided before, so we do not fan out aggressively.
    REDSEE_MAX_PARALLEL_SANDBOXES overrides it; 1 = fully serial (the safest)."""
    try:
        return max(1, int(os.environ.get("REDSEE_MAX_PARALLEL_SANDBOXES", "2")))
    except (ValueError, TypeError):
        return 2


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


# ── Injection drivers (agents -> Findings) ──────────────────────────────────
# The orchestrator drives run_sqli_agent / run_xss_agent DIRECTLY (not via
# modules/sqli.py) so it can set per-mode depth/iterations/timeout. injectable is
# still derived SOLELY from the agents' parsed tool output: only status=="injectable"
# candidates become Findings (engine.finding_map enforces this), so the evidence
# gate is intact.

def _scan_sqli_targets(targets: list, *, scope_config, profile: ScanProfile,
                       scan_id: str) -> list:
    """Run the SQLi agent over param-bearing injection targets, map confirmed
    injections to Findings. Empty target list -> no run, no findings."""
    if not targets:
        return []
    result = run_sqli_agent(
        list(targets), scope_config=scope_config,
        max_iterations=profile.sqli_max_iterations,
        max_level=profile.sqli_max_level, max_risk=profile.sqli_max_risk,
        timeout_sec=profile.injection_timeout_sec)
    target_url = getattr(targets[0], "url", "") or ""
    return [candidate_to_finding(c, target_url=target_url, scan_id=scan_id)
            for c in result.candidates if c.status == "injectable"]


def _scan_xss_targets(targets: list, *, scope_config, profile: ScanProfile,
                      scan_id: str) -> list:
    """Run the XSS agent over param-bearing injection targets, map confirmed
    reflected XSS to Findings. REDSEE_XSS_COOKIE (if set) is threaded through for
    authenticated targets, mirroring modules/xss.py."""
    if not targets:
        return []
    auth_cookie = os.environ.get("REDSEE_XSS_COOKIE") or None
    result = run_xss_agent(
        list(targets), scope_config=scope_config,
        max_iterations=profile.xss_max_iterations,
        auth_cookie=auth_cookie, timeout_sec=profile.injection_timeout_sec)
    target_url = getattr(targets[0], "url", "") or ""
    return [xss_candidate_to_finding(c, target_url=target_url, scan_id=scan_id)
            for c in result.candidates if c.status == "injectable"]


# ── Orchestrator ────────────────────────────────────────────────────────────

def _run_stages(stages: dict, max_parallel: int) -> dict:
    """Run each stage callable in `stages` (name -> zero-arg fn) concurrently under
    a ThreadPoolExecutor bounded to `max_parallel` workers, each wrapped in _safe.

    Returns name -> (result_or__FAILED, error_reason). A stage that raises never
    aborts the others — its failure becomes an error entry (mirrors _safe). Bounded
    on purpose: at most `max_parallel` stages (hence isolated sandboxes) coexist."""
    if not stages:
        return {}
    workers = max(1, min(max_parallel, len(stages)))
    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="redsee-scan-stage") as ex:
        futures = {name: ex.submit(_safe, fn) for name, fn in stages.items()}
        return {name: fut.result() for name, fut in futures.items()}


def run_scan(target_url: str, *, scope_config=None, scan_id: str | None = None,
             out_dir: str = "outputs", mode: str = DEFAULT_MODE) -> dict:
    """Run a full end-to-end scan of ONE authorized target and write the unified
    outputs/scan_<id>.json (plus the existing per-tool artifacts, all sharing the
    one scan_id).

    `mode` (fast / standard / deep) tunes breadth (how many param-bearing endpoints
    are injected), depth (injection level/risk/iterations/timeout), and which recon
    runs — see the ScanProfile table above. An unknown mode degrades to the default.

    Gating (engine.scope, reused — never reimplemented) runs FIRST:
    require_authorization + assert_in_scope. An unauthorized or out-of-scope
    target raises ScopeError and NOTHING is written (no partial run).

    Injection runs ONLY on param-bearing endpoints (engine.params) — a param-less
    endpoint is never handed to sqlmap/Dalfox. Independent tools (sqli, xss, nuclei,
    httpx, tlsx) run CONCURRENTLY under a conservative sandbox-parallelism bound;
    ffuf runs after httpx (it is chained off httpx's live URLs). Each stage is
    wrapped so a single stage's failure is an "error" tools_run entry and the scan
    continues; a failed stage contributes no findings/observations (never fabricated).

    Returns the unified record dict (also written to outputs/scan_<id>.json).
    """
    # 1. GATE FIRST — refuse before writing anything.
    if scope_config is None:
        scope_config = load_scope_config()
    require_authorization(scope_config)
    assert_in_scope(target_url, scope_config)

    profile = resolve_profile(mode)
    max_parallel = _max_parallel_sandboxes()

    # 2. ONE bare scan_id for EVERY artifact this run (unified file is scan_<id>.json;
    #    per-tool files are findings_<id>.json / run_<id>.json / nuclei_<id>.json /
    #    recon_<id>.json — same id).
    scan_id = scan_id or uuid.uuid4().hex[:8]
    started_at = _ts()
    tool_status: dict = {}          # name -> (status, count, detail), assembled in
                                    # _TOOL_ORDER at the end regardless of finish order

    # 3. Crawl -> endpoints (serial: injection-target selection depends on it).
    res, err = _safe(lambda: crawl(target_url))
    if err is not None:
        endpoints: list = []
        tool_status["crawl"] = ("error", 0, err)
    else:
        endpoints = list(res.endpoints)
        tool_status["crawl"] = ("ran", len(endpoints), f"{len(endpoints)} endpoints")

    # 4. Injection targets: param-bearing endpoints only, deterministically ranked
    #    and capped to the mode's breadth. Param-less endpoints are excluded here
    #    (they can't be injected — wasted sandbox time), so sqlmap/Dalfox only ever
    #    see real parameters.
    injection_targets = select_injection_targets(
        endpoints, limit=profile.max_injection_targets)

    # 5. Assemble the independent stages for this mode. Each is a zero-arg callable
    #    executed concurrently (bounded). ffuf is NOT here — it is chained off httpx.
    stages: dict = {}
    if injection_targets:
        stages["sqli"] = lambda: _scan_sqli_targets(
            injection_targets, scope_config=scope_config, profile=profile, scan_id=scan_id)
        stages["xss"] = lambda: _scan_xss_targets(
            injection_targets, scope_config=scope_config, profile=profile, scan_id=scan_id)
    if profile.run_nuclei:
        _nuclei_cookie = os.environ.get("REDSEE_NUCLEI_COOKIE") or None
        _nuclei_tags = list(profile.nuclei_tags) if profile.nuclei_tags else None
        stages["nuclei"] = lambda: run_nuclei_agent(
            [target_url], scope_config=scope_config, default_tags=_nuclei_tags,
            timeout_sec=profile.nuclei_timeout_sec, auth_cookie=_nuclei_cookie)
    if profile.run_httpx:
        stages["httpx"] = lambda: run_httpx([target_url], scope_config=scope_config)
    if profile.run_tlsx:
        stages["tlsx"] = lambda: run_tlsx([target_url], scope_config=scope_config)

    results = _run_stages(stages, max_parallel)

    # 6. Classify each stage into tool_status + collect its output.
    #    Injection (sqli/xss): skipped cleanly when there is nothing param-bearing to
    #    test — distinguishing "crawl found nothing" from "nothing had a parameter".
    inj_skip = "no endpoints from crawl" if not endpoints else "no param-bearing endpoints"

    sqli_findings: list = []
    xss_findings: list = []
    for name in ("sqli", "xss"):
        if name not in stages:
            tool_status[name] = ("skipped", 0, inj_skip)
            continue
        res, err = results[name]
        if err is not None:
            tool_status[name] = ("error", 0, err)
        else:
            found = list(res or [])
            tool_status[name] = ("ran", len(found), f"{len(found)} finding(s)")
            if name == "sqli":
                sqli_findings = found
            else:
                xss_findings = found

    # nuclei
    nuclei_result = None
    nuclei_candidates: list = []
    if "nuclei" not in stages:
        tool_status["nuclei"] = ("skipped", 0, f"disabled in {profile.name} profile")
    else:
        res, err = results["nuclei"]
        if err is not None:
            tool_status["nuclei"] = ("error", 0, err)
        else:
            nuclei_result = res
            nuclei_candidates = list(res.candidates)
            tool_status["nuclei"] = _classify_results(nuclei_candidates, "found")

    # httpx / tlsx
    httpx_obs: list = []
    tlsx_obs: list = []
    for name in ("httpx", "tlsx"):
        if name not in stages:
            tool_status[name] = ("skipped", 0, f"disabled in {profile.name} profile")
            continue
        res, err = results[name]
        if err is not None:
            tool_status[name] = ("error", 0, err)
        else:
            obs = list(res or [])
            tool_status[name] = _classify_results(obs, "observed")
            if name == "httpx":
                httpx_obs = obs
            else:
                tlsx_obs = obs

    # 7. ffuf — chained off httpx's LIVE URLs, so it runs after the concurrent pool.
    ffuf_obs: list = []
    if not profile.run_ffuf:
        tool_status["ffuf"] = ("skipped", 0, f"disabled in {profile.name} profile")
    else:
        ffuf_targets = _live_urls_from_httpx(httpx_obs, [target_url])
        res, err = _safe(lambda: run_ffuf(ffuf_targets, scope_config=scope_config))
        if err is not None:
            tool_status["ffuf"] = ("error", 0, err)
        else:
            ffuf_obs = list(res or [])
            tool_status["ffuf"] = _classify_results(ffuf_obs, "observed")

    findings = sqli_findings + xss_findings
    recon_observations = httpx_obs + tlsx_obs + ffuf_obs
    finished_at = _ts()

    # tools_run assembled in a FIXED order (independent of concurrent finish order).
    tools_run: list = []
    for name in _TOOL_ORDER:
        status, count, detail = tool_status[name]
        _record(tools_run, name, status, count, detail)

    # 8. Existing per-tool outputs, UNCHANGED — reuse write_outputs as-is, under the
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
        "mode": profile.name,
        "started_at": started_at,
        "finished_at": finished_at,
        "redsee_version": _redsee_version(),
        "tools_run": tools_run,
        "findings": [f.to_dict() for f in findings],
        "recon": {
            "nuclei": [_nuclei_candidate_dict(c) for c in nuclei_candidates],
            "observations": [_recon_observation_dict(o) for o in recon_observations],
        },
        # Effective caps this mode applied — so a reader can see exactly how the scan
        # was tuned (endpoints crawled vs. injected, injection depth, recon selection).
        "caps": {
            "mode": profile.name,
            "endpoints_crawled": len(endpoints),
            "injection_targets_selected": len(injection_targets),
            "max_injection_targets": profile.max_injection_targets,
            "sqli_max_level": profile.sqli_max_level,
            "sqli_max_risk": profile.sqli_max_risk,
            "sqli_max_iterations": profile.sqli_max_iterations,
            "xss_max_iterations": profile.xss_max_iterations,
            "injection_timeout_sec": profile.injection_timeout_sec,
            "recon": {"httpx": profile.run_httpx, "tlsx": profile.run_tlsx,
                      "ffuf": profile.run_ffuf, "nuclei": profile.run_nuclei},
            "nuclei_tags": list(profile.nuclei_tags) if profile.nuclei_tags else None,
            "max_parallel_sandboxes": max_parallel,
        },
        "summary": {
            "mode": profile.name,
            "findings_total": len(findings),
            "findings_by_severity": _severity_rollup(findings),
            "recon_observations": observed,
            "endpoints_crawled": len(endpoints),
            "injection_targets": len(injection_targets),
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
    mode = os.environ.get("REDSEE_SCAN_MODE") or DEFAULT_MODE

    record = run_scan(target, mode=mode)
    print(f"scan_id={record['scan_id']} target={record['target']} mode={record['mode']}")
    print(f"caps: {json.dumps(record['caps'])}")
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
