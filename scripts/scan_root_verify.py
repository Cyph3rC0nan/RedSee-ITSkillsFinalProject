#!/usr/bin/env python3
"""
D-025/D-026 live verification script.

Runs a STANDARD-mode scan against the ROOT of the themed marketplace target
(http://redsees.com:3000/ — never /market, never /rest directly) and prints the
discovery->injection loop's transparency counters, every tool's status, any
confirmed findings, and every sqli candidate actually tested (including
clean/error ones) so a "0 findings" result is diagnosable instead of a black box.

Requires (see README/.env.example):
  - .env configured: REDSEE_LLM_BASE_URL/MODEL/API_KEY/MAX_USD (a reachable
    OpenAI-compatible endpoint — e.g. a local Ollama at localhost:11434/v1 with
    llama3.2 pulled) so the sqli/xss/nuclei agents can actually run. Without
    this, those stages report status="error" and nothing will be found — that
    is a missing-config issue, not a scan bug.
  - The sandbox image built: bash docker/sandbox/build.sh
  - redsees.com:3000 reachable from wherever this runs.

Usage:
    PYTHONPATH=. python3 scripts/scan_root_verify.py
"""
import json
import time

from engine.env import load_env
from engine.scope import ScopeConfig
from modules.scan import run_scan

load_env()

TARGET = "http://redsees.com:3000/"


def main() -> None:
    scope = ScopeConfig(target_url=TARGET, allowed_hosts=["redsees.com"], authorized=True)

    t0 = time.time()
    rec = run_scan(TARGET, scope_config=scope, mode="standard", out_dir="/tmp/redsee_out")
    wall = time.time() - t0

    print(f"\n=== STANDARD scan of ROOT — wall={wall:.0f}s ===")
    print("discovery:", json.dumps(rec["discovery"]))
    print("caps:", json.dumps({
        k: rec["caps"][k] for k in (
            "seed_paths", "seed_params", "max_discovered_paths",
            "max_total_injection_targets", "max_parallel_sandboxes",
        )
    }))

    # Full, UNTRUNCATED detail — a truncated error message is worse than useless
    # when diagnosing a sandbox/Docker-networking failure (the real cause is
    # often the tail end of the message).
    for tr in rec["tools_run"]:
        print(f"  {tr['name']:<7} {tr['status']:<8} count={tr['count']:<3} {tr['detail']}")

    summary = rec["summary"]
    print("findings_total:", summary["findings_total"], summary["findings_by_severity"])
    for f in rec["findings"]:
        print("  FINDING:", f["type"], f["severity"], f["url"], "param=%s" % f["parameter"])

    print("\n--- injection candidates tested (incl. clean/error, for diagnosis) ---")
    for c in rec["injection_candidates"]["sqli"]:
        print("  SQLI:", c["status"], c["url"], "param=%s" % c["parameter"],
              c.get("technique"), "error=%s" % c.get("error"))
    for c in rec["injection_candidates"]["xss"]:
        print("  XSS: ", c["status"], c["url"], "param=%s" % c["parameter"],
              c.get("context"), "error=%s" % c.get("error"))


if __name__ == "__main__":
    main()
