# RedSee — Session Handoff

**Last updated:** 2026-07-16T03:15:00Z
**Current milestone:** Console UX polish, part 2 — blue-report PDF layout fixes (column
widths, page-break gap, a follow-up right-margin overflow, AND the red report's Evidence
`<pre>`-block overflow), a new Wazuh/SIEM Source Settings panel, a grey cursor on the Settings
tab, AND the console's `fmtTime()` (scan times, event times, finding times — every non-clock
timestamp in the frontend) converted to Asia/Baku, matching the topbar clock fixed earlier.
Builds on this session's earlier work (Baku clock, PDF-only reports, OWASP/MITRE citations).
All live-verified with geometrically-correct PDF tooling (pdfminer.six — see Key decisions;
pypdf's raw text-matrix is NOT trustworthy for position checks). UNCOMMITTED.

## Next step
Review + commit this session's changes (see "Changed files" below), then push. The prior
session's D-025/D-026 live re-verification may still be outstanding — check with the user,
this session didn't touch it.

## In progress
nothing (this session's work is complete and live-verified; no known open PDF-layout or
timezone issues)

## Recently completed (last 5)
- **Fixed the OTHER timezone bug: every non-clock timestamp in the console was still raw
  UTC.** `fmtTime(iso)` (Red Ops scan list started/created time, scan detail panel started/
  finished, Blue Ops events table timestamp) used to regex-extract `HH:MM:SS` VERBATIM from
  whatever ISO string it got — UTC for scan/finding timestamps, the Wazuh SIEM's OWN server
  offset for event timestamps (`log_ingestor.py` passes Wazuh's raw `timestamp` through
  as-is, e.g. `...+0200`, never normalized). Rewritten to parse it as a real `Date` (resolves
  `Z` or any explicit numeric offset correctly) and render through the SAME `fmtClock`/
  Asia-Baku formatter as the topbar clock. An offset-less string (rare/defensive) is treated
  as UTC rather than left to browser-local interpretation. Verified in Node against 7 cases
  (UTC+Z, Wazuh +0200, Wazuh +04:00, offset-less, empty, garbage) — all correct.
- **Fixed the blue-report PDF layout end-to-end** (4 related bugs, found + fixed across this
  session): (1) illegible log table — `.events-table` now explicit raw HTML with per-column
  widths (Description/Target get the bulk); (2) a big blank-page gap — `page-break-inside`
  moved table→row + `thead` repeats; (3) MY OWN fix for (1) introduced a right-margin
  overflow — `th`/`td` lacked `box-sizing: border-box`, so padding+border added on top of each
  column's % width under `table-layout:fixed`, pushing the table wider than the page; (4)
  found during verification of (3): red_report's Evidence `<pre>` blocks (raw sqlmap/Dalfox
  output, single unbreakable lines) also ran off the page — `pre` defaults to `white-space:
  pre` (never wraps), fixed with `pre-wrap` + `overflow-wrap`/`word-break`. ALL fixed in BOTH
  red.css/blue.css. Live-verified with `pdfminer.six` (NOT raw `pypdf` — see Key decisions):
  zero overflowing lines across real generated reports (5626 blue-report lines, 351
  red-report lines checked).
- New Settings panel "Wazuh / SIEM Source" — file path or live API (URL/user/password), a
  `file`/`api` toggle; new `/api/settings/test-wazuh` route; `console_settings.py`'s secret
  handling generalized to cover it. Live-verified: saved, reflected back masked, `/analyze-logs`
  picked up the new path with no restart. Plus: grey cursor on the Settings tab
  (`[data-view="settings"]` CSS override, matching the Red/Blue Ops red/cyan pattern).
- New `tests/test_console_settings.py` (17 tests) + 6 new tests for `_events_table`'s rewrite
  in `test_blue_report_deterministic.py`. 415 tests pass repo-wide (6 pre-existing unrelated
  live-DVWA failures); frozen paths still empty diff.
- Earlier this session: Baku clock (topbar), PDF-only reports (weasyprint re-pinned
  `60.2`→`69.0`), OWASP/MITRE citations — see Key decisions below, not repeated in full here.

## Key decisions
- `_events_table` emits raw HTML (`class="events-table"`, `html.escape()`'d every field) not
  a markdown pipe-table, so blue.css can size ITS columns via `:nth-child(n)` without touching
  the report's other, simpler tables. Escaping matters: real Wazuh events carry literal
  `<script>` payloads that must render as inert text.
- `table { page-break-inside: avoid }` → moved to `tr` in BOTH red.css/blue.css (same latent
  bug, found while fixing blue's complaint — red has tall tables too). The bug pushed a whole
  tall table to the next page (blank gap) instead of letting it split with a repeated header.
- Wazuh settings generalize the EXISTING `_ENV_MAP`/secret-masking machinery (built for the
  LLM api_key) — `_SECRET_FIELDS` is now iterated generically. `wazuh_source` (file/api) does
  NOT clear the other side's config on switch (unlike LLM `provider`) — file path and API
  creds are independent, both may stay configured at once.
- **PDF-only, no HTML fallback** (weasyprint now installed + re-pinned `69.0`, hard-required).
  OWASP/MITRE citations (`_owasp_ref`/`_OWASP_MAP`, richer `_mitre_info`) are presentation-only.
  Report routes call the deterministic generator, never the LLM path. storage/scan_store.py +
  modules/scan.py layering, D-024/D-025/D-026 all still true/unchanged — see DECISIONS.md
  D-012–D-026 and this file's own prior revisions (git history) for full rationale.

## Open issues / blockers
- **Superseded this session:** weasyprint IS now installed in this venv (`69.0`, matches the
  re-pinned `requirements.txt`) and both reports are PDF-only, hard-requiring it. On a FRESH
  environment, `pip install -r requirements.txt` must succeed in installing it (system libs
  pango/cairo/gdk-pixbuf are required — present on this host, not guaranteed elsewhere) or
  every report route will 500 with a clear "weasyprint is not installed" message.
- `OPENROUTER_API_KEY` is empty, `LLM_PROVIDER` unset (defaults openrouter) — the OLD
  LLM-authored report path fails regardless of weasyprint. Ollama IS reachable (`:11434`) if
  a future session wants a free LLM-authored path (`LLM_PROVIDER=ollama`). This is unaffected
  by PDF-only — that only touches the deterministic path the routes actually call.
- `outputs/*.html` IS now in `.gitignore` (the earlier gap is closed) — report HTML fallbacks
  won't be swept by `git add -A`.
- The console runs as ROOT on port 80 (not 5000) via `redsee-console` gunicorn; root can read
  the 640 `wazuh:wazuh` alerts.json. Auth is session-based (public `/` + `/login` → `/console`,
  NOT HTTP Basic Auth — that was replaced), creds still sourced from `.env`
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

## Changed files (this session — UNCOMMITTED)
- pdf_templates/blue.css + red.css — `page-break-inside` moved table→row + `thead` repeats;
  `table-layout: fixed` + `overflow-wrap`/`word-break` on `td`; NEW `th, td { box-sizing:
  border-box }` (table right-margin fix); `pre` gained `white-space: pre-wrap` + `overflow-
  wrap`/`word-break` (evidence-block right-margin fix). blue.css also gained `.events-table`
  column-width rules + `.web-flag` styling.
- blue_report.py — `_events_table` rewritten as escaped raw HTML (`class="events-table"`), not
  a markdown pipe-table (NEW `import html`). `_mitre_from_event` returns (id, tactic,
  technique) triples; `_mitre_section` shows a 4-column table; new "Framework Alignment"
  prose cites MITRE ATT&CK®.
- console_settings.py — `_ENV_MAP`/`_SECRET_FIELDS` extended with `wazuh_path`/`wazuh_api_url`/
  `wazuh_api_user`/`wazuh_api_pass`; `save_settings` generalized to loop over ALL secret
  fields; NEW `test_wazuh_connection()`; `public_settings()` returns the `wazuh_*` fields.
- app.py — NEW `/api/settings/test-wazuh` route; `/analyze-logs` reads
  `REDSEE_WAZUH_ALERTS_PATH` (live) before `WAZUH_ALERTS_DEFAULT_PATH`; report-route
  docstrings reflect PDF-only (no code-path change — try/except already handled it).
- templates/index.html — NEW "Wazuh / SIEM Source" Settings panel; topbar zone `UTC`→`AZT`.
- static/script.js — `fmtClock`/`CONSOLE_TZ` renders `Asia/Baku`; `fmtTime` rewritten to parse
  as a real `Date` and render through `fmtClock` (was: verbatim regex substring, wrong tz);
  `applyWazuhSourceUI`/`currentWazuhSource`/`testWazuhSettings`; `fillSettings`/
  `gatherSettings` extended.
- static/style.css — `[data-view="settings"]` grey cursor override (`--ink-dim`); `.tag-ready`
  generalized to cover `#wazuhStatusTag` too.
- red_report.py — `_render_report` PDF-only (raises `RuntimeError`, no HTML branch). NEW
  `_OWASP_MAP`/`_owasp_ref`/`_owasp_summary_table`; new "Framework Alignment" section.
- log_ingestor.py — NEW `_mitre_info()` (supersedes `_mitre_ids`) zips Wazuh's
  `rule.mitre.id`/`tactic`/`technique` arrays into the `[MITRE: ...]` marker.
- requirements.txt / .env.example — `weasyprint` 60.2→69.0 (old pin broken vs. current pydyf);
  documents `REDSEE_WAZUH_ALERTS_PATH`.
- tests/ — NEW `test_console_settings.py` (17), NEW `test_blue_report_deterministic.py` (18,
  incl. 6 for `_events_table`); `test_red_report_deterministic.py` rewritten (HTML-fallback
  test → fail-loudly test + OWASP tests).
- outputs/*.html (8 stray files) — deleted; untracked/gitignored artifacts from before the fix.
- FROZEN, verified empty diff: `git diff --stat schemas.py engine/ modules/`.

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
