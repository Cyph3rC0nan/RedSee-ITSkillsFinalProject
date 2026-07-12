# modules/recon.py
"""
Standalone nuclei recon runner — chains the sandboxed nuclei agent
(engine.nuclei_agent.run_nuclei_agent) into the output layer
(engine.report_io.write_outputs), surfacing found nuclei candidates into SARIF +
nuclei_<id>.json + the run.json summary.

DELIBERATELY separate from the typed-Finding pipeline:
  * nuclei results are BROADER than the frozen schemas.py Finding enum
    (SQLi/XSS/IDOR/BrokenAuth), so they are NOT typed Findings and NEVER enter
    findings_<id>.json (which this run leaves as an empty list).
  * This module is NOT wired into integration.py's resolver and does NOT expose a
    scan_<vuln>(endpoints, session?) function — it is invoked on its own (see
    run_recon_scan / the __main__ block below), not by the red-team scan pipeline.

Everything active still runs ONLY inside engine.sandbox via run_nuclei_agent —
scope-gated, egress-locked, detection-only. This module adds no execution of its
own; it just wires the agent result into write_outputs.
"""

import uuid

from engine.nuclei_agent import run_nuclei_agent, _target_url
from engine.report_io import write_outputs


def run_recon_scan(targets: list, *, scan_id: str | None = None,
                   out_dir: str = "outputs", auth_cookie: str | None = None,
                   max_iterations: int = 6, scope_config=None, llm_config=None,
                   llm_client=None, llm_meta: dict | None = None) -> dict:
    """Run a sandboxed nuclei scan over `targets` and write the outputs.

    Chains run_nuclei_agent(...) -> write_outputs(..., nuclei_candidates=...).
    Writes findings_<id>.json (an empty list — nuclei results are never typed
    Findings), findings_<id>.sarif (with the found nuclei results), a dedicated
    nuclei_<id>.json (the raw candidate list), and run_<id>.json (usage + a nuclei
    summary). Returns the write_outputs paths dict plus the NucleiAgentResult:
    {"result": NucleiAgentResult, "paths": {...}, "scan_id": str}.

    `targets` may be bare URL strings or Endpoint-like objects exposing `.url`.
    scope_config / llm_config / llm_client are forwarded to the agent (inject
    fakes for tests). This function performs NO active execution itself — all of
    that is inside run_nuclei_agent's sandbox.
    """
    scan_id = scan_id or f"recon_{uuid.uuid4().hex[:8]}"

    result = run_nuclei_agent(
        targets, max_iterations=max_iterations, scope_config=scope_config,
        llm_config=llm_config, llm_client=llm_client, auth_cookie=auth_cookie)

    target_url = next((_target_url(t) for t in targets if _target_url(t)), "")

    paths = write_outputs(
        result, [],                      # NO typed Findings from a nuclei run
        scan_id=scan_id, target_url=target_url, out_dir=out_dir,
        llm_meta=llm_meta, nuclei_candidates=result.candidates)

    return {"result": result, "paths": paths, "scan_id": scan_id}


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
    print(f"scan_id={out['scan_id']} stopped_reason={result.stopped_reason} "
          f"calls={result.usage.calls} cost=${result.usage.cost_usd:.4f}")
    print("outputs:")
    for kind, path in paths.items():
        print(f"  {kind}: {path}")
    found = [c for c in result.candidates if c.status == "found"]
    print(f"found templates ({len(found)}):")
    for c in found:
        print(f"  [{(c.severity or '').upper()}] {c.template_id} @ {c.matched_at}")
