# RedSee — Session Handoff

**Last updated:** 2026-07-15T13:10:00Z
**Current milestone:** D-025/D-026 discovery→injection loop + param seeding — code is merged
to `main` (via `feat/nuclei`), live-verified against the real target on the user's WSL2
machine; a seed-path ranking bug found live has been fixed+pushed. One more live re-run
needed to get a clean (non-resource-starved) confirmation on the `q` SQLi param.

## Next step
Have the user re-run `scripts/scan_root_verify.py` now that (a) the seed-ranking fix is
pulled and (b) this server's memory pressure has been reduced (stale sessions killed — see
"In progress"). Confirm the `q`/`search` params on `/rest/products/search` come back
`injectable`, and that `/market` XSS is still reachable via discovery. If clean, D-025/D-026
are fully done; if the sandbox self-test still intermittently fails, the box may need a
bigger tier or Wazuh should be stopped during test windows.

## In progress
Killing stale processes on THIS server (vmi3362886) to relieve memory pressure (was 289MB
free / load avg ~8, causing intermittent sandbox self-test failures + read-timeouts during
the user's live scan — confirmed via `free -h`/`ps aux --sort=-%mem`: Wazuh indexer (~1.6GB)
+ 4-5 concurrent Claude Code sessions were the load, NOT the RedSee scan itself). User
confirmed all extra sessions were theirs and safe to close. Killed (or attempted — the
in-session safety classifier was intermittently unavailable mid-task, retry if still alive):
PIDs 1740662 (pts/3 `claude -c`), 2006772 (pts/5 `claude -c`), 2007576/2007587 (bg job
`ff9ff7a9`), 1526275 (orphaned `mem_monitor.log` bash loop, ~16h old, harmless but stale).
**Next session: verify these are actually gone (`ps -p <pids>`) and re-check `free -h`
before the next live scan attempt.**

## Recently completed (last 5)
- Fixed live-evidenced seed-path ranking bug (commit `69d31d7`, pushed to `feat/nuclei`):
  `_QUERY_PATH_MARKERS` in `engine/params.py` mixed strong query-verb markers (search/query/
  find/lookup/filter) with weak collection-noun markers (products/users/orders/list/fetch/
  get) in one flat tier, so `/api/Products` and `/rest/products/search` tied and the
  alphabetical fallback ("api" < "rest") picked the WRONG path under `seed_paths=1` — the
  real target never got tested. Split into `_QUERY_PATH_MARKERS_STRONG`/`_WEAK` two-tier
  ranking; added regression test reproducing the exact two-URL scenario. Live re-verified:
  the user's next scan run correctly seeded `/rest/products/search` (not `/api/Products`).
  Also fixed `scan_root_verify.py` to pretty-print (indent=2) instead of one long line —
  the user's terminal had mangled a long single-line JSON dump on copy/paste.
- Merged all of `feat/nuclei` into `main` and pushed (merge commit `61740b3`): D-025/D-026
  discovery+seeding work, the Wazuh JSONL blue-team ingestion, live-verify script, README
  rewrite. Clean merge, zero conflicts, frozen files (`schemas.py`/`engine/sandbox.py`)
  verified untouched via `git diff --stat`.
- README.md full rewrite reflecting real current state (agentic architecture, security
  model, scan modes, blue team/SIEM ingestion, dual LLM/deterministic report pattern) —
  replaced the old stale static-pipeline description.
- Helped user stand up native Docker Engine inside WSL2 Ubuntu (their local test box) after
  discovering Docker Desktop's split-VM architecture broke RedSee's host-iptables sandbox
  isolation model (`DOCKER-USER` chain missing) — root cause, not just a symptom fix.
- Wazuh alerts.json → Blue Ops (ingest + feed + threat levels + deterministic blue report,
  now on `main`). See DECISIONS.md / git log for detail — this entry is intentionally
  compressed to keep this file under the line budget.

## Key decisions
- Blue: MITRE has no home in the frozen 8-field Event, so it rides in `raw_payload` as a
  parseable `[MITRE: T1190]` marker appended after the attack payload/full_log. blue_report
  regexes it back out for the "MITRE techniques seen" section. Web-attack highlight keys off
  rule_id 31xxx (derivable from Event.rule_id — `groups` isn't a schema field).
- Blue report reuses `red_report._render_report` (not its own weasyprint import) so the
  deterministic PDF/HTML fallback path is shared. `/generate-blue-report` now calls the
  deterministic generator; old LLM `generate_blue_report` left as an optional path, not deleted.
- `/analyze-logs` reads a server-side `path` (default Wazuh alerts.json) with a `last_n`=500
  cap so a 1000s-line JSONL never floods the UI; JSONL detection is "first non-empty line
  parses as JSON → parse line-by-line, skip malformed", with JSON-array/object fallbacks.
- Report route calls a NEW deterministic generator, not "fix weasyprint + keep the LLM path
  primary": even with weasyprint installed the LLM call would still fail (`OPENROUTER_API_KEY`
  empty). A report button must not depend on a paid API key/network/model.
- Skip reasons are computed from data ALREADY collected in the same scan (crawl count +
  httpx reachability) — zero new calls. The skip CONDITION in modules/scan.py is
  byte-identical to before; only the `detail` string changed (tools_run isn't in schemas.py).
- storage/scan_store.py is a NEW top-level package (not engine/scan_store.py) — it imports
  modules.scan (which imports engine.*), so storage->modules->engine avoids an import cycle.
- modules/scan.py (not engine/orchestrator.py) — imports BOTH modules (sqli/xss) and engine
  (recon/nuclei); engine must never import modules/. Unified file `scan_<id>.json`; per-tool
  files share the SAME bare scan_id.
- D-024: nuclei's real failure was a 256 MB OOM (not a slow scan) — only found by running
  THROUGH the real sandbox (a raw `--network host` run looked fine and hid it).
- Seed-path rank markers must be tiered (strong verb vs. weak noun), not one flat set — a
  flat set lets a low-value path (`/api/Products`) tie a high-value one
  (`/rest/products/search`) and lose only to alphabetical luck under a tight `seed_paths` cap.
  Found via a LIVE run, not a test (all unit tests passed with the bug present).
- Full decision history + rationale: DECISIONS.md D-012 through D-026.

## Open issues / blockers
- This dev sandbox's .venv HAS `markdown` but NOT `weasyprint` (confirmed via gunicorn's own
  interpreter). System libs (pango/cairo/gdk-pixbuf) ARE present, so `pip install weasyprint`
  would likely work if ever wanted — but the report button no longer needs it. blue_report.py
  is UNCHANGED/still weasyprint-only (not verified/fixed this session).
- `OPENROUTER_API_KEY` is empty, `LLM_PROVIDER` unset (defaults openrouter) — the OLD
  LLM-authored report path fails regardless of weasyprint. Ollama IS reachable (`:11434`) if
  a future session wants a free LLM-authored path (`LLM_PROVIDER=ollama`).
- `outputs/*.html` IS now in `.gitignore` (the earlier gap is closed) — report HTML fallbacks
  won't be swept by `git add -A`.
- The console runs as ROOT on port 80 (not 5000) via `redsee-console` gunicorn; root can read
  the 640 `wazuh:wazuh` alerts.json. Basic auth is ON — creds in `.env`
  (`REDSEE_DASH_USER`/`REDSEE_DASH_PASS`). If the console ever runs as non-root, add it to the
  `wazuh` group or it'll get 403 on `/analyze-logs` (route already returns a clear 403/404).
- nuclei's `-t` paths are memory-bounded (D-024) — if widened, re-verify under
  `docker run --memory 256m` first; `technologies`/`cve` OOM.
- Concurrency bounded to `REDSEE_MAX_PARALLEL_SANDBOXES=2` on purpose. Even a CLEAN (non-
  killed) scan can leak a sandbox network + its iptables rules on teardown — inspect with
  `sudo iptables -S | grep -E '172\.(1[89]|2[0-9])\.'` + `docker network ls --filter
  name=redsee-sbx-net`, delete only those subnets (both filter AND nat), never touch 172.17.
- DEPLOY LESSON: gunicorn/systemd caches Python AND Jinja templates — edits need
  `sudo systemctl restart redsee-console` to take effect. A "frontend looks broken" report is
  often the service running stale code, not a JS bug.
- The themed Juice Shop (:3001, behind the gateway on :3000) is FRAGILE under scanning —
  crashed under nuclei load this session. Restart: `cd /root/juice-shop && NODE_CONFIG_ENV=
  redsees nohup node build/app.js >/tmp/redsees-juiceshop.log 2>&1 &`. It also surfaces 0
  param-bearing endpoints to the crawler — use `/market/*` (search?q=, greeting?name=,
  notfound?path=) to exercise injection.
- Container lifecycle is volatile across turns: check `docker ps`/`curl` before assuming a
  target is up.
- THIS server (vmi3362886, 8GB) runs the target's Docker sinks container, a native Juice
  Shop Node process, the FULL Wazuh SIEM stack, AND whatever Claude Code sessions happen to
  be open — free memory can drop to <300MB just from that idle baseline. Before a live scan,
  check `free -h`/`ps aux --sort=-%mem` and close stale sessions first; a low-memory scan
  failure (`isolation self-test FAILED`, `target_unreachable`) may be host contention, not a
  RedSee bug — rule this out before chasing a code fix.

## Changed files (this session)
- engine/params.py — `_QUERY_PATH_MARKERS` split into `_STRONG`/`_WEAK` two-tier ranking
  (see Key decisions). Committed+pushed `69d31d7` on `feat/nuclei`.
- tests/test_param_seeding.py — regression test for the strong-vs-weak tie-break, same commit.
- scripts/scan_root_verify.py — pretty-printed (indent=2) discovery/caps output + prints the
  scan_<id>.json path up front, same commit.
- HANDOFF.md — this update.
- (Earlier this session, already committed to `main` via the `feat/nuclei` merge `61740b3`:
  Wazuh alerts.json → Blue Ops, README rewrite, D-025/D-026 discovery+seeding — see git log,
  not repeated here to stay within this file's line budget.)

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
