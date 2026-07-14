# RedSee — Session Handoff

**Last updated:** 2026-07-14T14:50:00Z
**Current milestone:** skip legibility (D-025 territory, not yet numbered/committed) + Red
Report export fix — deterministic (no-LLM) report generator, always produces a real file.
UNCOMMITTED. Live-deployed (service restarted) and proven against the real console.

## Next step
Diagnose-and-fix task is COMPLETE and live-proven — commit it (see "Changed files" below).
Flag to the user before/at commit time: `outputs/*.html` is NOT in `.gitignore` (only
`.pdf`/`.json`/`.sarif`/`.db*` are) — the new deterministic report's HTML fallback output
would get swept up by a `git add -A`; add an `outputs/*.html` line before committing, or
`git add` the specific source files rather than the whole `outputs/` tree. Two proof
artifacts already sitting there uncommitted: `outputs/red_report_7a4b9a45.html`,
`outputs/red_report_90bc384c.html` — fine to leave or delete, not deliverables. After that:
idor/auth agents (the last two static modules to convert to the agent-driven pattern).

## In progress
nothing

## Recently completed (last 5)
- Skip legibility + Red Report export fix. DIAGNOSIS (confirmed against a real record,
  `outputs/scan_0975e0a2.json`, before changing anything): sqli/xss "skipped" on a 502'd
  target was CORRECT D-024 behavior (0 param-bearing endpoints -> nothing to inject), not a
  bug — `session.get()` doesn't raise on an HTTP error status, so crawl silently drops an
  unreachable root and returns 0 endpoints with no exception. The reason already existed in
  `tools_run[].detail` but the UI only showed it as a hover tooltip. Fix (skip CONDITION
  untouched): modules/scan.py builds a 3-way reason (no-params / target-unreachable /
  target-responded-but-crawl-empty, using httpx's already-collected reachability signal,
  zero new network calls); script.js shows `.detail` as a visible sub-line, not just a
  tooltip. SEPARATE bug: `/scan/<id>/report` 400'd on 0-finding scans AND weasyprint was
  confirmed missing in gunicorn's own venv AND `OPENROUTER_API_KEY` is empty — installing
  weasyprint alone would NOT have fixed the button. Fix: red_report.py gained
  `generate_deterministic_report()` — builds the same structured report from the scan record
  via string templates (no LLM call), renders PDF if weasyprint is importable else
  self-contained HTML (needs only the already-installed `markdown` pkg). app.py's route
  prefers `scan_<id>.json`, never 400s on 0 findings, only 404s on a truly unknown id. Live-
  proven end-to-end (unreachable-port scan -> legible skip reason; /market/* standard scan ->
  6 real XSS + a real downloadable report; 0-finding scan -> real report, not 400; unknown id
  -> clear 404). 11 new offline tests; schemas.py/engine/sandbox.py untouched — 2026-07-14
- Param-targeted injection + scan modes + nuclei OOM fix (D-024, COMMITTED+PUSHED as 0b28c9e).
  NEW `engine/params.py` extracts injectable params, ranks targets (forms>links>api), caps
  per mode. `run_scan(mode=fast|standard|deep)` drives the engine agents DIRECTLY (scan_sqli's
  sig is frozen) with per-mode depth/timeout. Independent tools run concurrently
  (ThreadPoolExecutor, `REDSEE_MAX_PARALLEL_SANDBOXES`, default 2). **nuclei "timeout" was a
  256 MB sandbox OOM** loading the full template corpus — fixed by scoping `-t` to
  memory-safe dirs (exposures+misconfiguration). mode threaded store->app->UI. Full detail:
  DECISIONS.md D-024 — 2026-07-14
- Built `storage/scan_store.py` (COMMITTED) — SQLite queue/status/history over run_scan;
  `enqueue_scan` gates up front, bounded worker pool, orphaned `running` rows reconcile to
  `error` on restart. DB holds a summary + a path to scan_<id>.json, never the full record.
  See DECISIONS.md D-023 — 2026-07-13
- Built `modules/scan.py` (COMMITTED) — the unified scan orchestrator: crawl -> sqli/xss ->
  recon -> ONE `scan_<id>.json` alongside the existing per-tool outputs, all sharing one
  scan_id. Every stage wrapped so a failure is an "error" tools_run entry, never fabricated.
  See DECISIONS.md D-022 — 2026-07-13

## Key decisions
- Report route calls a NEW deterministic generator, not "fix weasyprint + keep the LLM path
  primary": even with weasyprint installed (system pango/cairo ARE present), the LLM call
  would still fail (`OPENROUTER_API_KEY` empty). A report button must not depend on a paid
  API key/network/model. Old `generate_red_report` (LLM prose) is left as an optional future
  path, not deleted.
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
- Full decision history + rationale: DECISIONS.md D-012 through D-024.

## Open issues / blockers
- This dev sandbox's .venv HAS `markdown` but NOT `weasyprint` (confirmed via gunicorn's own
  interpreter). System libs (pango/cairo/gdk-pixbuf) ARE present, so `pip install weasyprint`
  would likely work if ever wanted — but the report button no longer needs it. blue_report.py
  is UNCHANGED/still weasyprint-only (not verified/fixed this session).
- `OPENROUTER_API_KEY` is empty, `LLM_PROVIDER` unset (defaults openrouter) — the OLD
  LLM-authored report path fails regardless of weasyprint. Ollama IS reachable (`:11434`) if
  a future session wants a free LLM-authored path (`LLM_PROVIDER=ollama`).
- GAP: `outputs/*.html` is NOT in `.gitignore` (only `.pdf`/`.json`/`.sarif`/`.db*` are) — the
  new HTML report fallback would get swept by `git add -A`. Add before/at next commit.
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

## Changed files (uncommitted — skip legibility + report fix)
- modules/scan.py — httpx/tlsx classified before sqli/xss (reorder only); 3-way skip reason
  for sqli/xss's `tools_run[].detail` (skip CONDITION untouched).
- red_report.py — graceful `weasyprint` import (`_HAS_WEASYPRINT`); NEW
  `generate_deterministic_report()` / `_build_deterministic_markdown()` / `_render_report()`
  / `_tools_table()` / `_recon_summary()` / `_finding_section()` / `_fmt_ts()`. OLD
  `generate_red_report`/`markdown_to_pdf`/`call_llm` UNTOUCHED.
- app.py — `/scan/<id>/report` rewritten: prefers `scan_<id>.json` over legacy
  `findings_<id>.json`, calls the deterministic generator, 404 (not 400) only when there's
  truly no scan data, returns `{"report_url","format"}`.
- static/script.js — `renderTools()` shows `.detail` as a visible sub-line for skipped/error
  chips; report button visible whenever `status==="done"`; `downloadRedReport()` surfaces the
  real server error via a new `#reportNote`.
- templates/index.html — added `#reportNote`. static/style.css — `.treason` sub-line style.
- tests/test_red_report_deterministic.py (NEW, 11 tests — exercises both pdf/html render
  branches via a stubbed weasyprint, so it's environment-independent).
- FROZEN, verified empty diff: `git diff --stat schemas.py engine/sandbox.py`.
- D-024 (prior session) is committed/pushed (0b28c9e, 268f7ed) — not part of this diff.

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
