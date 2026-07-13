# RedSee — Session Handoff

**Last updated:** 2026-07-13T18:30:00Z
**Current milestone:** unified scan orchestrator (`modules/scan.py`'s `run_scan`) — crawl -> vuln agents (sqli, xss) -> recon (nuclei, httpx, tlsx, ffuf) -> aggregate into ONE `outputs/scan_<id>.json`, alongside the existing per-tool outputs, all sharing one scan_id. Branch `feat/nuclei`, uncommitted.

## Next step
Orchestrator is COMPLETE and live-proven — commit it (modules/scan.py + tests/test_orchestrator.py;
outputs are gitignored). The NEXT prompt wires modules.scan into integration.py/app.py
(deliberately NOT done here). Longer-standing: idor/auth agents; a full-findings live run
(agents actually driving sqlmap/dalfox) if ever needed — use a real REDSEE_LLM_MAX_USD and
expect 10-40 min.

## In progress
nothing

## Recently completed (last 5)
- Built `modules/scan.py` — the unified scan orchestrator (aggregation spine).
  `run_scan(target_url, *, scope_config=None, scan_id=None, out_dir="outputs")` gates FIRST
  (require_authorization + assert_in_scope; refuses before writing anything), then runs
  crawl -> scan_sqli + scan_xss (typed Findings) -> run_nuclei_agent + run_httpx/tlsx/ffuf
  (candidates/observations, ffuf chained off httpx live URLs) -> writes ONE
  `outputs/scan_<id>.json` unifying findings + recon + a tools_run table + severity/summary
  rollup, ALONGSIDE (never replacing) the existing per-tool outputs via the SAME reused
  `write_outputs` under ONE shared bare scan_id (fixes AGENTS.md's "two differently-named
  findings files" limitation). Each stage is wrapped: a tool that RAISES -> "error" tools_run
  entry, scan continues, nothing fabricated; a recon/nuclei tool that returns status="error"
  results (they don't raise) is honestly classified as "error" (not a misleading "ran, 0")
  via `_classify_results`. schemas.py NOT touched (unified record is a NEW json artifact, not
  a schema type); report_io reused untouched (write_outputs + its secret scrubber + its
  per-tool serializers). Chose modules/scan.py over engine/orchestrator.py because it imports
  BOTH modules (sqli/xss) and engine layers, and engine must not depend on modules. 9 offline
  tests in tests/test_orchestrator.py (happy path, tool-error isolation, all-errored-recon
  classification, crawl-fail-skips-vuln-agents, unauthorized/out-of-scope refusal + no
  outputs, per-tool byte-for-byte match vs a direct write_outputs, secret scrub); 124-test
  full regression green. LIVE-PROVEN: real Juice Shop run (scan_id 4caea79d, budget-0 fast
  path) — all 7 tools ran 0-error, httpx fingerprint + 9 ffuf paths in ONE scan_<id>.json
  alongside the shared-id per-tool files; llm block secret-scrubbed. NOT wired into
  integration.py — 2026-07-13
- Added `run_ffuf` to engine/recon_tools.py — deterministic sandboxed content discovery,
  mirroring run_httpx/run_tlsx's exact shape (scope-gate-first, sandbox-only, no LLM/agent
  loop/budget). **Found + fixed a real bug via the mandated live smoke test**: `-mc`
  status-code matching alone FLOODED 4741/4750 words as false hits against Juice Shop (an
  SPA whose client routing catch-all serves an identical 200 for every path). Added `-ac`
  (auto-calibration) — confirmed it drops the flood to 0 on the SPA while still surfacing
  genuine hits (.git/.env/admin) on a differentiated target, and Juice Shop's real static
  routes once re-run. Same "verify against a real target" lesson as D-019. Rate/thread-bounded
  (REDSEE_RATE_LIMIT honored as a req/sec cap, ceiling 50) with a `-maxtime` backstop so a
  bounded scan exits gracefully. GET-only, no recursion/proxy/write flags (`_FFUF_FORBIDDEN`).
  Severity Medium for a small sensitive-path marker list, Low otherwise — never fabricated.
- Chained httpx -> ffuf in modules/recon.py (`_live_urls_from_httpx`): ffuf targets are
  httpx's LIVE-confirmed URLs, falling back to seed targets. ffuf joins the SAME
  `recon_observations` list as httpx/tlsx -> zero report_io changes needed (already generic).
  23 new tests in tests/test_ffuf_recon.py vs a REAL captured fixture; 115-test full
  regression clean; schemas.py untouched — 2026-07-13
- Installed pinned ffuf v2.1.0 + bundled ONE pinned SecLists wordlist (common.txt, ~4750
  lines, commit-sha-pinned, sha256-verified) into docker/sandbox/Dockerfile — same
  reproducible-release pattern as every other sandbox tool. No XDG bake needed (ffuf writes
  nothing at startup, unlike the ProjectDiscovery tools). D-020 — 2026-07-13
- Built engine/recon_tools.py's run_httpx/run_tlsx — deterministic sandboxed HTTP
  fingerprint + TLS/cert inspection, no LLM/agent loop. `ReconObservation` (local, not
  schemas.py) has status={observed,error,out_of_scope}, no "clean" status. tlsx derives
  host/port via the SAME formula run_in_sandbox uses internally — 2026-07-13

## Key decisions
- The unified scan orchestrator lives at `modules/scan.py`, NOT `engine/orchestrator.py`
  (the task offered either). It imports BOTH the modules layer (sqli/xss) and the engine
  layer (recon/nuclei), and the repo's dependency direction is modules -> engine (nothing in
  engine/ imports modules/). Placing it in engine/ would invert that layering. Live entry is
  therefore `python -m modules.scan`. The unified file is `scan_<id>.json`; per-tool files are
  `findings_<id>.json`/`run_<id>.json`/`nuclei_<id>.json`/`recon_<id>.json` — ALL sharing ONE
  bare scan_id (hex, no prefix), which is the fix for the "two differently-named findings
  files" limitation. NOT wired into integration.py's resolver (next prompt).
- Fast live-proof technique for the orchestrator: set `REDSEE_LLM_MAX_USD=0` so the sqli/xss/
  nuclei AGENTS hit a budget stop immediately and suppress their completion pass (verified:
  all three guard it with `if entered_reason != "budget"`), meaning ZERO per-endpoint
  sandboxed sqlmap/dalfox/nuclei runs — while the deterministic httpx/tlsx/ffuf still probe
  the target live. Turns a 10-40 min full agent run into a ~3-4 min real recon-backed
  `scan_<id>.json`. A FULL live run (agents actually driving sqlmap/dalfox per endpoint) is
  inherently slow: ~21 Juice-Shop endpoints x 2 agents x (local-LLM latency + sandbox
  setup/self-test/teardown + tool runtime).
- D-017 (recon results -> SARIF + dedicated JSON + run.json, never typed Findings/
  schemas.py) now covers nuclei, httpx/tlsx, AND ffuf — `report_io` stays fully decoupled
  from every source module via getattr duck-typing, so adding ffuf required ZERO report_io
  changes. modules/recon.py is the standalone entry for all four tools, not in
  integration.py's resolver. The orchestrator reuses this same write_outputs call unchanged
  (proven byte-for-byte vs a direct call in tests/test_orchestrator.py).
- D-019/D-020 pattern ("pin/configure to avoid a problematic real-world behavior, verified
  against a BUILT image + a real target, not assumed") now has a THIRD instance: ffuf's fixed
  profile MUST include `-ac` (auto-calibration), not just `-mc` status-code matching — proven
  via the live Juice-Shop smoke (see above). A flag set that looks right in offline unit
  tests can still be wrong against real-world target behavior — always live-smoke-test new
  tool integrations before calling them done.
- REDSEE_RATE_LIMIT is honored DIRECTLY as ffuf's `-rate` (req/SECOND) rather than converted
  per-minute — the literal per-minute conversion would make the bundled wordlist take ~79min
  at the default 60. Ceiling-bounded at 50 req/s regardless of configured value. httpx/tlsx's
  own rate handling is unchanged.
- ffuf's targets chain from httpx's LIVE observations (`_live_urls_from_httpx`), not the raw
  seed list — a target httpx couldn't reach is unlikely reachable for ffuf's noisier
  brute-force either. Falls back to seed targets when httpx found nothing live.
- Prior decisions (Dalfox v2.13.0 pin, nuclei v3.11.0 + templates v10.4.5, httpx v1.9.0 not
  v1.10.0/phone-home, XDG under /tmp for nuclei/httpx/tlsx, tlsx host/port formula, recon_tools
  has no model in the loop) unchanged this session — see DECISIONS.md D-012 through D-020 for
  full detail; not re-summarized here to keep this file lean.

## Open issues / blockers
- **RESOLVED this session** (re-verified via a real live run, not assumed): the host-local
  BRIDGE-mode sandbox networking blocker affecting DVWA/Juice-Shop-style published-port
  targets is no longer reproducing — `modules.recon` ran cleanly end-to-end against
  `http://redsees.com:3000/` (scan_id `recon_d67b8366`), httpx AND ffuf both actually reaching
  the live target. Kept here as a note in case it regresses, not as an active blocker.
- nuclei_agent/recon_tools have NO Finding mapping — by design (D-017), not a gap.
- Not yet run: a live `scan_xss()` call through the full modules.xss public API.
- `_SENSITIVE_PATH_MARKERS` (ffuf severity) is a small, deliberately conservative hand-picked
  list — extend it if a real engagement surfaces another exposure pattern worth Medium.
- Env note (this session): the Juice Shop container got stuck DETACHED from all networks
  (empty `NetworkSettings.Networks`, no published port) after a `pkill` interrupted a
  `run_in_sandbox` teardown mid-op — a `docker restart` did NOT fix it. Recreated it clean:
  `docker rm -f redsee-juiceshop && docker run -d --name redsee-juiceshop --restart
  unless-stopped -p 3000:3000 bkimminich/juice-shop` (stateless demo, no volumes — safe). If
  the live target is unreachable, check `docker ps` shows a real `0.0.0.0:3000->3000/tcp`
  mapping (not an empty Ports column) before assuming a code/networking bug.
- Leaked host iptables rules exist from that killed run (`sudo iptables -S DOCKER-USER |
  grep 172.` shows appended ACCEPT/DROP for old sandbox subnets 172.18/172.19). They are
  HARMLESS to fresh sandbox runs (run_in_sandbox INSERTS its rules at the TOP, above these
  appended ones — proven: scan_id 4caea79d's self-test passed and httpx/tlsx/ffuf all
  reached the target). Not flushed autonomously (host-firewall change). Remove with targeted
  `iptables -D` if tidying is wanted; not required for correctness.
- To do a lightweight live orchestrator smoke WITHOUT the slow per-endpoint vuln agents, set
  `REDSEE_LLM_MAX_USD=0` (agents budget-stop instantly; httpx/tlsx/ffuf still run live).
- This dev sandbox lacks `markdown`/`weasyprint` — red_report.py/blue_report.py + their tests
  fail to import here (pre-existing, unrelated).
- Container lifecycle is volatile across turns: check `docker ps`/`curl` before assuming
  DVWA (:8080) or Juice Shop (:3000) is up.

## Changed files (this session — unified scan orchestrator)
- modules/scan.py (NEW) — `run_scan` orchestrator + helpers (`_safe` per-tool wrapper,
  `_classify_results` honest recon/nuclei status rollup, `_live_urls_from_httpx`,
  `_severity_rollup`, `_build_llm_meta`, `_redsee_version`, `_EmptyAgentResult`). Opt-in
  `__main__` (`python -m modules.scan`). NOT wired into integration.py.
- tests/test_orchestrator.py (NEW, 9 tests) — fully mocked (crawl + every tool doubled at the
  modules.scan boundary; a guard proves run_in_sandbox is never reached).
- schemas.py, integration.py, engine/*, engine/report_io.py, modules/sqli.py, modules/xss.py,
  modules/recon.py, docker/sandbox/* — UNTOUCHED (verified via `git status`/`git diff --stat`;
  schemas.py + integration.py diffs empty). The ffuf work from earlier this session is already
  committed (70d964e, 8bdeac8).

## Invariants to preserve
- schemas.py contract frozen · severity strings exact · sandbox + scope gating · auth gating first
- run_in_sandbox public API + hardening flags frozen (--cap-drop=ALL, no-new-privileges,
  --read-only, non-root, NEVER --privileged/NET_ADMIN) · fail-closed self-test never softened
- Egress allows ONLY the single connect_ip:port actually contacted — never broadened ·
  public internet + host SSH(22) stay blocked & self-tested
- Host-local targets route via the bridge gateway, never hairpin via the public IP
- injectable/found derives SOLELY from parsed tool positive output (sqlmap for SQLi; Dalfox
  [POC]/[V] for XSS; nuclei -jsonl result lines; ffuf JSON hit lines) · never from the model ·
  agents never let the model supply raw flags; harness-owned profile only · no interactsh/OOB,
  no exploit/intrusive/dos/fuzz/brute, no auto-update, ever
- All tool execution via engine.sandbox.run_in_sandbox; every URL scope-checked first;
  detection-only (no exploit/blind-callback flags, ever)
- load_env() only at true entry points · override=False always
- See AGENTS.md for the full contract.
