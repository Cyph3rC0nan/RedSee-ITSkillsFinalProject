# RedSee — Session Handoff

**Last updated:** 2026-07-13T19:30:00Z
**Current milestone:** persistent scan store (`storage/scan_store.py`) — SQLite-backed queue + status lifecycle + history over `modules.scan.run_scan`, surviving process restart. Branch `feat/nuclei`, uncommitted (orchestrator itself already committed at 490180e).

## Next step
Scan store is COMPLETE — commit it (storage/scan_store.py + storage/__init__.py +
tests/test_scan_store.py + the .gitignore `outputs/*.db*` line; outputs/redsee.db is
gitignored, never commit it). The NEXT prompt wires the store into app.py's Flask routes
(enqueue/list/get endpoints + the dashboard tab) — deliberately NOT done here. Longer-standing:
idor/auth agents.

## In progress
nothing

## Recently completed (last 5)
- Built `storage/scan_store.py` — persistent scan store (queue + lifecycle + history) over
  run_scan. `enqueue_scan(target, *, scope_config=None)` gates UP FRONT (require_authorization
  + assert_in_scope; refuses with ScopeError BEFORE any row is created), inserts a `queued`
  row, hands the id to a bounded background worker pool, returns the id. Worker flips
  queued->running->done (persisting the summary rollup + the PATH to scan_<id>.json, never
  the full record — the JSON file stays the source of truth) or ->error with the message on
  any exception (a scan is NEVER left stuck in running; a store re-opened after a crash
  reconciles orphaned `running` rows to `error` on init). SQLite at outputs/redsee.db
  (gitignored via a new `outputs/*.db*` line), stdlib sqlite3 only, per-op connections
  serialized by one RLock (no "database is locked"). Concurrency bounded + configurable
  (`REDSEE_SCAN_CONCURRENCY` / `ScanStore(concurrency=)`, default 1). list_scans(newest-first,
  status filter, limit/offset) + get_scan (row + loads scan_<id>.json when present). Chose a
  NEW top-level `storage/` package over engine/scan_store.py: it imports modules.scan (which
  imports engine.*), so storage->modules->engine keeps the dependency direction clean and
  makes an import cycle impossible. 10 offline tests (tests/test_scan_store.py, run_scan
  faked); 87-test regression green; schemas.py/modules/scan.py/app.py/integration.py untouched.
  Live-proven against Juice Shop via the module-level API. NOT wired into Flask — 2026-07-13
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

## Key decisions
- The persistent scan store lives at `storage/scan_store.py` (a NEW top-level package), NOT
  `engine/scan_store.py` (the task offered either). Same layering logic as the orchestrator,
  one level up: it imports `modules.scan` (which imports `engine.*`), so `storage -> modules
  -> engine` keeps the dependency direction clean and makes an import cycle impossible
  (nothing in modules/ or engine/ imports storage/). Live entry: `import storage.scan_store`.
  SQLite at `outputs/redsee.db` (gitignored via `outputs/*.db*`); the DB holds a SUMMARY row +
  a PATH to scan_<id>.json, never the full record (the JSON file is the source of truth).
  Worker pool bounded + configurable (`REDSEE_SCAN_CONCURRENCY`, default 1). Gating is UP
  FRONT in enqueue AND again inside run_scan. Orphaned `running` rows are reconciled to
  `error` on store init so a crash never leaves a scan stuck. NOT wired into Flask (next).
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
- Leaked host iptables rules from that killed run were CLEANED this session (user-authorized,
  done by hand): 20 orphaned `-s 172.18/172.19` sandbox rules removed from DOCKER-USER/INPUT
  (filter) + PREROUTING (nat); DOCKER-USER is back to its empty default; live 172.17 bridge
  rules (juice shop/DVWA) untouched; juice shop still 200. If they recur after a future killed
  run, inspect with `sudo iptables -S | grep -E '172\.(1[8-9]|2[0-9])\.'` and delete only the
  stale-subnet ones (re-issue each `-A` as `-D`); never touch 172.17 (the live docker0 bridge).
- To do a lightweight live orchestrator smoke WITHOUT the slow per-endpoint vuln agents, set
  `REDSEE_LLM_MAX_USD=0` (agents budget-stop instantly; httpx/tlsx/ffuf still run live).
- This dev sandbox lacks `markdown`/`weasyprint` — red_report.py/blue_report.py + their tests
  fail to import here (pre-existing, unrelated).
- Container lifecycle is volatile across turns: check `docker ps`/`curl` before assuming
  DVWA (:8080) or Juice Shop (:3000) is up.

## Changed files (uncommitted — persistent scan store)
- storage/scan_store.py (NEW) — `ScanStore` class (sqlite queue + worker pool + history) +
  module-level `enqueue_scan`/`list_scans`/`get_scan` delegating to a lazy default store.
- storage/__init__.py (NEW, empty) — makes storage/ a package.
- tests/test_scan_store.py (NEW, 10 tests) — run_scan faked at the storage.scan_store boundary.
- .gitignore — added `outputs/*.db*` so outputs/redsee.db is never committed.
- schemas.py, modules/scan.py, app.py, integration.py, engine/*, docker/sandbox/* — UNTOUCHED
  (verified: `git diff --stat schemas.py modules/scan.py app.py integration.py` empty).
- Already committed earlier this session: the orchestrator (490180e), ffuf (70d964e, 8bdeac8).

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
