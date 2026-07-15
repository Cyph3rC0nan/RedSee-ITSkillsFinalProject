# modules/recon.py
"""
Standalone recon runner — chains the sandboxed nuclei agent
(engine.nuclei_agent.run_nuclei_agent) PLUS the deterministic httpx/tlsx/ffuf
recon runners (engine.recon_tools.run_httpx / run_tlsx / run_ffuf) into the
output layer (engine.report_io.write_outputs), surfacing found nuclei
candidates and observed httpx/tlsx/ffuf recon observations into ONE SARIF
report + nuclei_<id>.json + recon_<id>.json + the run.json summary.

The pipeline chains httpx -> ffuf: ffuf's content-discovery brute-force runs
against the LIVE base URLs httpx actually confirmed (status="observed"), not
blindly against every seed target — a target httpx couldn't reach is unlikely
to be reachable for ffuf either, so there is no point spending the (much
noisier) brute-force budget on it. Falls back to the raw seed targets when
httpx found nothing live (e.g. everything errored or was out of scope), so
content discovery still gets attempted rather than silently skipped.

DELIBERATELY separate from the typed-Finding pipeline:
  * nuclei/httpx/tlsx/ffuf results are ALL BROADER than the frozen schemas.py
    Finding enum (SQLi/XSS/IDOR/BrokenAuth), so none of them are typed Findings
    and NONE enter findings_<id>.json (which this run leaves as an empty list)
    — see DECISIONS.md D-017.
  * This module is NOT wired into integration.py's resolver and does NOT expose a
    scan_<vuln>(endpoints, session?) function — it is invoked on its own (see
    run_recon_scan / the __main__ block below), not by the red-team scan pipeline.

Everything active still runs ONLY inside engine.sandbox — nuclei via the agent
loop (run_nuclei_agent), httpx/tlsx/ffuf deterministically (run_httpx/run_tlsx/
run_ffuf, no LLM, no agent loop) — scope-gated, egress-locked, detection-only.
This module adds no execution of its own; it just wires the results into
write_outputs.
"""

import uuid

from engine.nuclei_agent import run_nuclei_agent, _target_url
from engine.recon_tools import run_httpx, run_tlsx, run_ffuf
from engine.report_io import write_outputs
from engine.scope import load_scope_config


def _live_urls_from_httpx(httpx_observations: list, seed_targets: list) -> list[str]:
    """The base URLs to feed into run_ffuf: every DISTINCT target httpx
    actually got a live JSON result for (status="observed"), in first-seen
    order. Falls back to the raw seed target list when httpx found nothing
    live, so content discovery still gets SOME target rather than silently
    running against nothing."""
    live: list[str] = []
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


def run_recon_scan(targets: list, *, scan_id: str | None = None,
                   out_dir: str = "outputs", auth_cookie: str | None = None,
                   max_iterations: int = 6, scope_config=None, llm_config=None,
                   llm_client=None, llm_meta: dict | None = None) -> dict:
    """Run a sandboxed nuclei + httpx + tlsx + ffuf recon pass over `targets`
    and write the combined outputs.

    Chains run_nuclei_agent(...) + run_httpx(...) + run_tlsx(...) +
    run_ffuf(...) -> write_outputs(..., nuclei_candidates=...,
    recon_observations=...). ffuf runs against the LIVE base URLs httpx
    confirmed (falling back to the seed targets when httpx found none — see
    _live_urls_from_httpx), NOT against the raw seed list directly. Writes
    findings_<id>.json (an empty list — none of these four are typed Findings),
    findings_<id>.sarif (nuclei's found results + httpx/tlsx/ffuf's observed
    rows), nuclei_<id>.json (the raw nuclei candidate list), recon_<id>.json
    (the raw httpx/tlsx/ffuf observation list), and run_<id>.json (usage +
    nuclei summary + recon summary). Returns:
    {"result": NucleiAgentResult, "recon_observations": [...], "paths": {...},
     "scan_id": str}.

    `targets` may be bare URL strings or Endpoint-like objects exposing `.url`.
    scope_config / llm_config / llm_client are forwarded to the nuclei agent
    (inject fakes for tests); the SAME resolved scope_config is also used for
    the httpx/tlsx/ffuf runs, so all four tools see identical scope. This
    function performs NO active execution itself — all of that is inside
    run_nuclei_agent / run_httpx / run_tlsx / run_ffuf's sandboxed calls.
    """
    scan_id = scan_id or f"recon_{uuid.uuid4().hex[:8]}"
    if scope_config is None:
        scope_config = load_scope_config()

    result = run_nuclei_agent(
        targets, max_iterations=max_iterations, scope_config=scope_config,
        llm_config=llm_config, llm_client=llm_client, auth_cookie=auth_cookie)

    httpx_observations = run_httpx(targets, scope_config=scope_config)
    tlsx_observations = run_tlsx(targets, scope_config=scope_config)
    ffuf_targets = _live_urls_from_httpx(httpx_observations, targets)
    ffuf_observations = run_ffuf(ffuf_targets, scope_config=scope_config)
    recon_observations = httpx_observations + tlsx_observations + ffuf_observations

    target_url = next((_target_url(t) for t in targets if _target_url(t)), "")

    paths = write_outputs(
        result, [],                      # NO typed Findings from a recon run
        scan_id=scan_id, target_url=target_url, out_dir=out_dir,
        llm_meta=llm_meta, nuclei_candidates=result.candidates,
        recon_observations=recon_observations)

    return {"result": result, "recon_observations": recon_observations,
            "paths": paths, "scan_id": scan_id}


# ── Opt-in live entry point ─────────────────────────────────────────────────
if __name__ == "__main__":
    # Requires: .env configured (scope + LLM), sandbox image built
    # (bash docker/sandbox/build.sh), a running Ollama, and a reachable in-scope
    # target. .env is loaded automatically (override=False, so real env wins).
    #
    #   REDSEE_AUTHORIZED=true REDSEE_ALLOWED_HOSTS=localhost \
    #   REDSEE_TARGET_URL=http://localhost:8080/ \
    #   REDSEE_LLM_BASE_URL=http://localhost:11434/v1 REDSEE_LLM_MODEL=llama3.2 \
    #   REDSEE_LLM_MAX_USD=0.50 PYTHONPATH=. python -m modules.recon
    #
    # An optional auth cookie for authenticated targets: REDSEE_NUCLEI_COOKIE.
    import os

    from engine.env import load_env
    load_env()

    cookie = os.environ.get("REDSEE_NUCLEI_COOKIE") or None
    target = os.environ.get("REDSEE_TARGET_URL") or "http://localhost:8080/"

    out = run_recon_scan([target], auth_cookie=cookie)
    result, paths = out["result"], out["paths"]
    recon_obs = out["recon_observations"]
    print(f"scan_id={out['scan_id']} stopped_reason={result.stopped_reason} "
          f"calls={result.usage.calls} cost=${result.usage.cost_usd:.4f}")
    print("outputs:")
    for kind, path in paths.items():
        print(f"  {kind}: {path}")

    found = [c for c in result.candidates if c.status == "found"]
    print(f"nuclei found templates ({len(found)}):")
    for c in found:
        print(f"  [{(c.severity or '').upper()}] {c.template_id} @ {c.matched_at}")

    observed = [o for o in recon_obs if o.status == "observed"]
    errored = [o for o in recon_obs if o.status == "error"]
    print(f"httpx/tlsx/ffuf observations ({len(observed)} observed, {len(errored)} errored):")
    for o in observed:
        print(f"  [{o.tool}] [{(o.severity or '').upper()}] {o.category}: {o.title}")
    for o in errored:
        print(f"  [{o.tool}] [ERROR] {o.target}: {o.error}")
