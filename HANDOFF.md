# RedSee — Session Handoff

**Last updated:** 2026-07-13T17:00:00Z
**Current milestone:** deterministic sandboxed ffuf content-discovery (engine/recon_tools.py's run_ffuf), chained off httpx's live URLs, surfaced into the SAME recon channel as httpx/tlsx. Branch `feat/nuclei`, all uncommitted.

## Next step
Deterministic recon trio (httpx/tlsx/ffuf) is done, chained through `modules/recon.py`.
Options next: (a) idor/auth agents (long-outstanding, not started); (b) a live `scan_xss()`
smoke through the full modules.xss public API (long-outstanding). Everything this session is
UNCOMMITTED — commit when ready (engine/recon_tools.py's run_ffuf + modules/recon.py's
httpx->ffuf chaining + tests/test_ffuf_recon.py + tests/fixtures/ffuf_localhost_real.jsonl).

## In progress
nothing

## Recently completed (last 5)
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
- Surfaced nuclei candidates into report_io WITHOUT touching schemas.py or
  findings_<id>.json (D-017). `write_outputs` gained optional `nuclei_candidates=` — SARIF +
  nuclei_<id>.json + run.json summary. New standalone modules/recon.py — 2026-07-12

## Key decisions
- D-017 (recon results -> SARIF + dedicated JSON + run.json, never typed Findings/
  schemas.py) now covers nuclei, httpx/tlsx, AND ffuf — `report_io` stays fully decoupled
  from every source module via getattr duck-typing, so adding ffuf required ZERO report_io
  changes. modules/recon.py is the standalone entry for all four tools, not in
  integration.py's resolver.
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
- outputs/*.sarif from ad-hoc live smoke runs got swept into a prior commit by a broad
  `git add -A` (`.gitignore` covers `outputs/*.json` but NOT `.sarif`); this session deleted
  the stale ones from disk as cleanup but did NOT commit that deletion — review `git status`
  before your next commit.
- This dev sandbox lacks `markdown`/`weasyprint` — red_report.py/blue_report.py + their tests
  fail to import here (pre-existing, unrelated).
- Container lifecycle is volatile across turns: check `docker ps`/`curl` before assuming
  DVWA (:8080) or Juice Shop (:3000) is up.

## Changed files (this session — ffuf content-discovery runner + httpx->ffuf chaining)
- engine/recon_tools.py — added `run_ffuf` + argv builder (`_build_ffuf_argv`,
  `_build_ffuf_target_url`, `_ffuf_rate`), `_FFUF_FORBIDDEN`, sensitive-path classifier
  (`_is_sensitive_path`/`_SENSITIVE_PATH_MARKERS`), `_ffuf_observation_for`. `ReconObservation`
  gained "ffuf" as a third `tool` value (just a string, no schema change).
- modules/recon.py — added `_live_urls_from_httpx`, wired httpx -> ffuf into
  `run_recon_scan`.
- engine/report_io.py — UNTOUCHED (already fully generic for the recon channel).
- tests/test_ffuf_recon.py (NEW, 23 tests) + tests/fixtures/ffuf_localhost_real.jsonl (NEW,
  real captured JSON).
- schemas.py, engine/sandbox.py, engine/nuclei_agent.py, engine/agent.py, engine/xss_agent.py,
  modules/sqli.py, modules/xss.py, modules/idor.py, integration.py, docker/sandbox/Dockerfile,
  build.sh — UNTOUCHED (verified via `git status`/`git diff --stat`).

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
