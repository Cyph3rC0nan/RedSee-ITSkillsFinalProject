# RedSee — Session Handoff

**Last updated:** 2026-07-15T11:35:00Z
**Current milestone:** Blue Ops wired to REAL Wazuh alerts.json (JSONL) — ingest → events
feed + threat levels → deterministic (no-LLM) blue incident report. UNCOMMITTED. Live-
deployed (service restarted, port 80) and proven end-to-end against the real console.

## Next step
Blue Ops / Wazuh-ingest task is COMPLETE and live-proven — commit it (see "Changed files").
`.gitignore` already covers `outputs/*.html` (the earlier gap is closed), so `git add -A` is
safe now w.r.t. report artifacts. After that: idor/auth agents (the last two static modules
to convert to the agent-driven pattern).

## In progress
nothing

## Recently completed (last 5)
- Wazuh alerts.json → Blue Ops (ingest + feed + threat levels + deterministic blue report).
  log_ingestor.py: `ingest_log_file(filepath, last_n=None, since_minutes=None)` — NEW
  `_read_records()` handles JSONL (Wazuh's real shape, one alert/line, malformed lines
  skipped) AND the old JSON-array/object fixtures; `last_n` tails the file (newest last),
  `since_minutes` best-effort time-window. Enriched `_parse_wazuh_alerts`: rule.level→
  severity_level (raw int), rule.description→description, data.srcip→src_ip (`::ffff:`
  stripped), data.url OR request parsed from full_log→target_url, query-string/full_log +
  `[MITRE: T…]` marker→raw_payload (frozen Event has no context field, so MITRE rides in the
  free-form detail field). NEW helpers `severity_bucket()` (≥12 Crit/7–11 High/4–6 Med/<4
  Low), `is_web_attack()` (31xxx or attack/web group). app.py `/analyze-logs`: accepts a
  server-side `path` (default `/var/ossec/logs/alerts/alerts.json`) + `last_n`(500 default)/
  `minutes`, OR an upload, OR inline events; `/generate-blue-report` now calls the
  deterministic generator (always downloads a file). blue_report.py: NEW
  `generate_deterministic_blue_report(events)` (incident summary, events-by-severity, MITRE
  seen, top source IPs, web-attack section, all-events table) → reuses red_report._render_
  report (weasyprint PDF if present, else self-contained HTML; no LLM). Frontend: "Load
  alerts.json" button + web-attack row highlight (rule 31xxx) + WEB badge. 22 new offline
  tests (real captured alert lines); schemas.py/engine untouched. LIVE proven: /analyze-logs
  → 300 events, 10 web-attack, the /rest/products/search?q=<script>alert(1)</script> XSS
  (rule 31106) present; blue report downloads a real 23KB file listing it — 2026-07-15
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
  `engine/params.py` ranks/caps injectable targets; `run_scan(mode=fast|standard|deep)` drives
  agents directly with per-mode depth; independent tools run concurrently. **nuclei "timeout"
  was a 256 MB sandbox OOM** — fixed by scoping `-t` to memory-safe dirs. DECISIONS.md D-024.
- Built `storage/scan_store.py` (COMMITTED) — SQLite queue/status/history over run_scan; gates
  up front, bounded worker pool, orphaned rows reconcile to `error`. DECISIONS.md D-023 — 07-13

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
- Full decision history + rationale: DECISIONS.md D-012 through D-024.

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

## Changed files (this session — Wazuh alerts.json → Blue Ops; UNCOMMITTED)
- log_ingestor.py — `ingest_log_file(filepath, last_n=None, since_minutes=None)`; NEW
  `_read_records()` (JSONL + JSON-array/object), `_record_timestamp()`/`_filter_since()`,
  `severity_bucket()`, `is_web_attack()`, `_clean_ip()`, `_url_from_full_log()`,
  `_mitre_ids()`, `_compose_detail()`; `_parse_wazuh_alerts` enriched (full_log/mitre/IP).
  `WAZUH_ALERTS_DEFAULT_PATH` const. Backward-compatible: old sample fixtures still parse.
- blue_report.py — NEW `generate_deterministic_blue_report()` + section builders
  (`_severity_table`/`_mitre_section`/`_top_source_ips`/`_events_table`/…); imports
  `_render_report` from red_report. OLD LLM `generate_blue_report` UNTOUCHED.
- app.py — `/analyze-logs` accepts server-side `path`(default Wazuh alerts.json)+`last_n`/
  `minutes` OR upload OR inline events; `/generate-blue-report` → deterministic generator,
  returns `{"report_url","format"}`. NEW `_INGEST_DEFAULT_LAST_N=500`.
- templates/index.html — "Load alerts.json" ingest row (`#alertsBtn`/`#alertsLastN`).
- static/script.js — `#alertsBtn` handler; `isWebAttack()`; web-attack row highlight + WEB
  badge in `renderEvents`/`renderDist`.
- static/style.css — `.web-badge`/`.events-table tr.web-attack`/`.dist-web`.
- tests/test_blue_ingest.py (NEW, 22 tests) + tests/fixtures/wazuh_alerts_sample.jsonl (NEW,
  real captured alert lines + a malformed line).
- FROZEN, verified empty diff: `git diff --stat schemas.py engine/sandbox.py`.
- Prior UNCOMMITTED work (skip legibility + red report fix: modules/scan.py, red_report.py,
  app.py /scan report route, script.js, index.html, style.css, test_red_report_deterministic.py)
  is ALSO still uncommitted — commit alongside or separately.

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
