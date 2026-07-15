# RedSee — Progress

This file is the running roadmap + session log for RedSee's transformation from a
static, hard-coded scanner pipeline into an agentic, LLM-driven engine. It answers
"what are we doing next." For "what is true right now" see [`AGENTS.md`](AGENTS.md);
for "why we chose this" see [`DECISIONS.md`](DECISIONS.md); for the current
session's live working state (in-progress detail, blockers, exact file diffs) see
[`HANDOFF.md`](HANDOFF.md).

---

## Current status

The static Phase-4 pipeline (crawler → `modules/sqli,xss,idor,auth` → red/blue PDF
reports, wired through `integration.py` and the 8-route Flask app) is
**integration-complete**: 27 passed / 2 skipped per
[`AGENTS.md`'s Test summary](AGENTS.md#test-summary-post-integration). The project
is now mid-transition to an agentic, Claude-driven engine (see D-002 in
[`DECISIONS.md`](DECISIONS.md)): a sandboxed, LLM-driven `engine/` layer
(scope-gating → sandbox isolation → BYOK LLM client → plan/act/observe agent loop →
Finding mapping → SARIF/run.json output) already exists and is wired in as the
first path for both `modules/sqli.py` (driving sqlmap) and `modules/xss.py`
(driving Dalfox), each falling back to its original static scanner if the agent
engine is unavailable. Full architecture and the current agent-engine contract are
in [`AGENTS.md`'s "Agent engine" section](AGENTS.md#agent-engine-engine).

## Roadmap

| Milestone | Status |
|---|---|
| Phase 4 static pipeline integration | Done |
| Continuity docs (this task) | In progress |
| SQLi agent-driven vertical slice (replace static stub) | Done |
| Sandbox + scope-gating harness for the slice | Done |
| Generalize agent pattern to xss / idor / auth | In progress (xss done, idor/auth not started) |
| nuclei template-scan agent (CVEs / misconfig / exposures) | Done — engine + sandbox + SARIF/JSON/run.json output via report_io + standalone modules/recon.py; live end-to-end run confirmed against Juice Shop — see HANDOFF |
| httpx + tlsx deterministic recon (fingerprint / TLS-cert inspection) | Done — engine/recon_tools.py + report_io recon channel + modules/recon.py extension; live end-to-end run confirmed — see HANDOFF |
| ffuf + pinned wordlist (directory/file brute-force) | Done — pinned sandbox install (v2.1.0 + SecLists common.txt) + deterministic run_ffuf runner, chained off httpx's live URLs; live end-to-end run confirmed — see HANDOFF |
| Unified scan orchestrator (crawl→vuln agents→recon→one scan_<id>.json) | Done — modules/scan.py run_scan; aggregates findings + recon under ONE shared scan_id alongside the existing per-tool outputs; schemas.py + integration.py untouched; 9 offline tests + live Juice Shop run confirmed. NOT yet wired into integration.py/app.py (next) — see HANDOFF |
| Persistent scan store (queue + status lifecycle + history) | Done — storage/scan_store.py; sqlite outputs/redsee.db (gitignored), bounded worker pool, gating up front, restart-survival + orphan reconcile; 10 offline tests + live enqueue→done confirmed. NOT yet wired into Flask routes (next) — see HANDOFF |
| Param-targeted injection + scan modes (fast/standard/deep) + parallelism | Done — engine/params.py (param extraction/ranking), ScanProfile modes in modules/scan.py, direct-agent depth threading, bounded concurrent stages, nuclei memory-scoped by template PATH (256 MB OOM fix), mode threaded store→app→UI. D-024. Live-proven: nuclei completes (67 s), standard on /market sinks → 3 real XSS findings on param endpoints only. schemas.py/sandbox.py untouched |
| Provider-agnostic BYOK LLM layer | Done |
| Operator dashboard (queue / watch / browse history) | Later |
| MCP server control surface | Later |
| SARIF + run.json structured outputs | Done |

Note: the SQLi/sandbox/BYOK-LLM/SARIF rows are marked `Done` ahead of this task's
original seed list because that work was completed in prior sessions — see
[`AGENTS.md`](AGENTS.md) (current contract) and the session log below /
[`HANDOFF.md`](HANDOFF.md) (how it was built). Update this table's Status column
whenever a milestone's state changes.

## Session log

<!-- Template for new entries — copy this block, newest entry goes on top:
### YYYY-MM-DD — <title>
**Done:** ...
**Next:** ...
**Blockers:** ...
-->

### 2026-07-14 — param-targeted injection + scan modes + nuclei OOM fix (D-024)

**Done:** Reworked `run_scan` (see D-024). (1) NEW `engine/params.py` extracts
injectable params (query-string keys + form/body fields, minus submit/CSRF controls)
per crawled endpoint; param-less endpoints are EXCLUDED from sqli/xss and targets are
ranked deterministically (forms→links→api/page, more-params-first, URL tie-break) for
capping. (2) Three scan MODES — `fast` (top 5 params, shallow level/risk 1, 60 s
injection timeout, httpx+tlsx only), `standard` (10 params, level 3, +scoped nuclei
+ffuf), `deep` (all params, agent-default depth, full recon) — as a `ScanProfile`
table (NOT schemas.py). The orchestrator drives the agents DIRECTLY (scan_sqli's
signature is frozen), threading per-mode `max_level/max_risk/max_iterations/timeout_sec`;
`timeout_sec` added (backward-compatibly) to run_sqli_agent/run_xss_agent, `default_tags`
+`timeout_sec` to run_nuclei_agent. (3) Independent tools run CONCURRENTLY via a
ThreadPoolExecutor bounded by `REDSEE_MAX_PARALLEL_SANDBOXES` (default 2); ffuf still
chained after httpx; tools_run assembled in fixed order. (4) **Fixed the nuclei
"timeout" — it was an OOM**: the 256 MB sandbox cap (frozen) can't hold the full
template corpus, so `-t` now points at memory-safe category dirs
(`http/exposures`+`http/misconfiguration`, ~1163 templates) with `-timeout 5 -retries 0
-c 15`. (5) `mode` threaded through enqueue_scan (new DB column) → worker → run_scan;
app `/api/scans` accepts `mode`; launch UI has a Fast/Standard/Deep selector; history +
detail show a mode pill. schemas.py + engine/sandbox.py UNTOUCHED (empty diff).

**Live-proven (redsees.com:3000):** scoped nuclei COMPLETES through the real sandbox
(`status=found exit=0 timed_out=False wall=67s`; was OOM/timeout). `fast` on Juice Shop
= 17 s (crawler surfaces 0 param endpoints → injection correctly SKIPPED). `standard` on
the `/market/*` sinks = 698 s, all 7 tools ran, nuclei completed, and Dalfox confirmed
**3 real High XSS findings** on exactly the 3 param-bearing endpoints (q/name/path).
Tests: `test_params.py` (14) + `test_scan_modes.py` (14) NEW, `test_orchestrator.py`
mocks updated; 46/46 in the primary set + 77 regression pass (6 pre-existing DVWA-live
failures need :8080, fail identically on a clean tree).

**Next:** idor/auth agents. Optional: wire run_scan mode into any remaining call sites;
tune deep-mode nuclei to a larger memory-safe dir set if desired.
**Blockers:** None. Note: the themed Juice Shop (:3001) is fragile under scanning and
crashed twice during nuclei probes; restart via `demo-helper.sh` (`node build/app.js`,
NODE_CONFIG_ENV=redsees) if `/` 502s.

### 2026-07-13 — persistent scan store (storage/scan_store.py)

**Done:** Added `storage/scan_store.py` — a SQLite-backed scan queue + status lifecycle +
history layer over `modules.scan.run_scan` (run_scan itself untouched). `ScanStore` (and
module-level `enqueue_scan`/`list_scans`/`get_scan` over a lazy default instance) persists to
`outputs/redsee.db` (stdlib `sqlite3` only, NO new deps; gitignored via a new `outputs/*.db*`
line). `enqueue_scan(target, *, scope_config=None)` reuses `engine.scope`'s
`require_authorization` + `assert_in_scope` and REFUSES (ScopeError) BEFORE any row is
created, then inserts a `queued` row and hands the id to a bounded background worker pool
(default 1, `REDSEE_SCAN_CONCURRENCY` / `ScanStore(concurrency=)`). The worker flips
`queued -> running -> done` (persisting the summary rollup + the PATH to `scan_<id>.json`,
never the full record — the JSON file stays the single source of truth) or `-> error` with
the message on ANY exception, so a scan is never left stuck in `running`; a store re-opened
after a hard crash reconciles orphaned `running` rows to `error` on init. `list_scans`
(newest-first, status filter, limit/offset) and `get_scan` (row + loads `scan_<id>.json` when
present) complete the read API.

Chose a NEW top-level `storage/` package over `engine/scan_store.py` (the task offered
either): the store imports `modules.scan` (which imports `engine.*`), so `storage -> modules
-> engine` keeps the dependency direction clean and makes an import cycle impossible — nothing
in `modules/` or `engine/` imports `storage/` (the task explicitly warned to avoid cycles).
Live entry: `import storage.scan_store`. 10 offline tests in `tests/test_scan_store.py`
(run_scan faked: enqueue+gating-refusal, queued→running→done with summary/path persisted,
run_scan-raises→error-not-running, list newest-first + filter + paging, get loads the JSON,
restart-survival across a new store instance, orphaned-running reconcile, concurrency bound
respected); 87-test regression green; `git diff --stat schemas.py modules/scan.py app.py
integration.py` empty; `git check-ignore outputs/redsee.db` matches. Live-proven: enqueued a
real Juice Shop scan through the module-level API and watched it reach `done` with the summary
+ scan_json_path persisted and listed.

**Next:** Wire the store into `app.py`'s Flask routes (enqueue/list/get endpoints + the
dashboard tab) — the NEXT prompt, deliberately not done here. Then idor/auth agents.

**Blockers:** None.

### 2026-07-13 — unified scan orchestrator (modules/scan.py)

**Done:** Added `modules/scan.py` — the aggregation spine. `run_scan(target_url, *,
scope_config=None, scan_id=None, out_dir="outputs")` runs ONE authorized target end-to-end
(crawl → scan_sqli + scan_xss → run_nuclei_agent + run_httpx/tlsx/ffuf, ffuf chained off
httpx's live URLs) and writes ONE new `outputs/scan_<id>.json` unifying findings + recon +
a `tools_run` status table + a severity/summary rollup — ALONGSIDE (never replacing) the
existing per-tool outputs, all keyed by ONE shared bare scan_id (the fix for AGENTS.md's
"two differently-named findings files" limitation). Gating (require_authorization +
assert_in_scope) runs FIRST — an unauthorized/out-of-scope target is refused before anything
is written. Each stage is wrapped: a tool that RAISES → an "error" tools_run entry, scan
continues, nothing fabricated; a recon/nuclei tool that returns status="error" results (they
don't raise) is honestly classified as "error" via `_classify_results` (not a misleading
"ran, 0"). `schemas.py` is untouched (the unified record is a NEW json artifact, not a schema
type); `engine/report_io.py` is reused unchanged (write_outputs + its secret scrubber + its
per-tool serializers), proven byte-for-byte identical to a direct write_outputs call.

Chose `modules/scan.py` over `engine/orchestrator.py` (the task offered either): the spine
imports BOTH the modules layer (sqli/xss) and the engine layer (recon/nuclei), and the repo's
dependency direction is modules → engine (nothing in engine/ imports modules/), so engine/
placement would invert the layering. Live entry is `python -m modules.scan`. 9 offline tests
in `tests/test_orchestrator.py` (happy path, tool-error isolation, all-errored-recon
classification, crawl-fail-skips-vuln-agents, unauthorized + out-of-scope refusal writing no
outputs, per-tool byte-for-byte match, secret scrub); 124-test full regression green;
`git diff --stat schemas.py integration.py` empty. LIVE-PROVEN against Juice Shop (scan_id
4caea79d): all 7 tools ran 0-error, httpx fingerprint + 9 ffuf-discovered paths unified into
one scan_<id>.json with the shared-id per-tool files, `llm` block secret-scrubbed. Used the
`REDSEE_LLM_MAX_USD=0` fast path (agents budget-stop instantly, skipping the slow
per-endpoint sandboxed sqlmap/dalfox) so the live proof took ~2 min instead of 10-40.

**Next:** Wire `modules.scan` into `integration.py`/`app.py` (the NEXT prompt — deliberately
not done here). Then idor/auth agents.

**Blockers:** None. (Env aside: the Juice Shop container had to be recreated mid-session
after a killed run left it network-detached — see HANDOFF; not a code issue.)

### 2026-07-13 — ffuf content-discovery runner, chained off httpx's live URLs

**Done:** Added `run_ffuf` to `engine/recon_tools.py` — deterministic sandboxed content
discovery (directory/file brute-force) using the wordlist bundled in the previous task,
mirroring `run_httpx`/`run_tlsx`'s exact shape (scope-gate-first, sandbox-only, no LLM/agent
loop/budget). **Found and fixed a real bug via the mandated live smoke test**: the initial
flag set (`-mc` status-code matching alone) FLOODED 4741 of 4750 wordlist entries as
false-positive "hits" against Juice Shop, because it's a single-page app whose client-side
routing catch-all serves an identical 200 `index.html` for every path — status-code matching
alone can't distinguish that from a genuine hit. Added `-ac` (ffuf's auto-calibration, which
probes the target's "nothing here" response shape and filters matches against it) to the
fixed profile: re-verified it drops the flood to 0 on the SPA while STILL surfacing genuinely
sensitive hits (`.git`, `.git/config`, `.env`, `admin`) on a differentiated test site, and
correctly found Juice Shop's real static routes (`/assets`, `/media`, `/video`, `/promotion`,
`/robots.txt`, `/security.txt`, `/ftp`) once re-run clean. This is the third instance of the
"pin/configure to avoid a problematic real-world behavior, verified against a BUILT image and
a REAL target, not assumed" pattern this branch has now hit (Dalfox's v2.13.0 pin, httpx's
v1.9.0 pin, and now ffuf's `-ac`) — a flag set that looks correct in offline unit tests
(synthetic + throwaway-server fixtures) can still be wrong against realistic modern targets.

`modules/recon.py` now chains httpx -> ffuf: a new `_live_urls_from_httpx` helper feeds ffuf
the LIVE base URLs httpx actually confirmed (`status="observed"`), falling back to the raw
seed targets when httpx found nothing live. ffuf's observations join the SAME
`recon_observations` list as httpx/tlsx, so `engine/report_io.py` needed ZERO changes — it
was already fully generic/duck-typed for the recon channel. Rate/thread-bounded
(`REDSEE_RATE_LIMIT` honored directly as a requests/SECOND cap for ffuf specifically, ceiling
50) with a `-maxtime` backstop that fires before `run_in_sandbox`'s harder kill, so a
rate-bounded scan exits gracefully with whatever hits it found rather than being killed
mid-run. GET-only; recursion, proxy, external-command, and write flags are hard-forbidden
(`_FFUF_FORBIDDEN`). Severity: Medium for a small hand-picked sensitive-path marker list
(`.git`/`.env`/backup/admin/...), Low otherwise — derived solely from parsed ffuf JSON hit
lines, never fabricated. 23 new offline tests in `tests/test_ffuf_recon.py` against a REAL
captured fixture (`tests/fixtures/ffuf_localhost_real.jsonl`); 115-test full regression
clean; `git diff --stat schemas.py` empty. Live end-to-end `modules.recon` run against Juice
Shop (`http://redsees.com:3000/`) confirmed clean: httpx + ffuf both reached the live target
and produced real observations (nuclei found 0 templates, as expected for a custom app).

Also confirmed as a side effect of this session's live smoke: the host-local BRIDGE-mode
sandbox networking blocker that had affected DVWA/Juice-Shop-style published-port targets
throughout prior sessions is no longer reproducing — see `HANDOFF.md`.

**Next:** idor/auth agents (not started), and the long-outstanding live `scan_xss()` smoke
through the full `modules.xss` public API.

**Blockers:** None for this task. See `HANDOFF.md` for the remaining open items.

### 2026-07-13 — ffuf + pinned wordlist installed in sandbox image

**Done:** Added [ffuf](https://github.com/ffuf/ffuf) v2.1.0 to `docker/sandbox/Dockerfile`
— pinned GitHub release binary, sha256-verified against ffuf's own checksums file and
independently re-downloaded/re-hashed locally, same pattern as sqlmap/Dalfox/nuclei/
httpx/tlsx (no `go install`/@latest/apt). Bundled ONE small wordlist at
`/opt/wordlists/common.txt` — SecLists' `Discovery/Web-Content/common.txt` (~4750 lines,
MIT-licensed), fetched as a raw file pinned to one exact commit sha (immune to a tag being
moved/deleted), sha256-verified — NOT a full ~1GB SecLists clone. Confirmed ffuf needs no
`/tmp/.config` XDG bake (unlike the ProjectDiscovery tools) by running `ffuf -V` under the
full hardened flag set (`--read-only --user 10001 --network none`) with zero writes. All
definition-of-done checks green: `ffuf -V` (normal + hardened), wordlist line count (4750),
nuclei/httpx/tlsx/sqlmap/dalfox regression unaffected. Tool-install only —
`docker/sandbox/Dockerfile` + `docs/nuclei_sandbox.md` — no Python/engine/build.sh changes.
New decision D-020.

**Next:** Build the runner — either an LLM-driven `engine/ffuf_agent.py` (mirroring
nuclei_agent) or a deterministic `engine/ffuf_tools.py` (mirroring recon_tools), whichever
fits directory/file brute-forcing better — and wire its output into `report_io`/`modules/`
the same additive way. Then a live end-to-end `modules.recon` run once sandbox networking
is resolved, idor/auth agents, and the long-outstanding live `scan_xss()` smoke.

**Blockers:** None for this task itself (pure tool-install, fully offline-verified). The
runner-build step is unblocked and can start any time.

### 2026-07-13 — deterministic httpx/tlsx recon, surfaced alongside nuclei

**Done:** Added `engine/recon_tools.py` — deterministic sandboxed recon (httpx HTTP
fingerprinting, tlsx TLS/cert inspection), reusing `engine/nuclei_agent.py`'s
scope-gate/sandbox-only SHAPE but with NO LLM, agent loop, or budget (one fixed,
harness-built command per target). `ReconObservation` (local, not `schemas.py`) has
`status ∈ {observed, error, out_of_scope}` — a successful-but-empty probe yields no
observation, never fabricated data. Severity (`Low`/`Medium`) comes solely from real
httpx/tlsx JSON fields. `engine/report_io.py`'s `write_outputs` gained a second additive
channel, `recon_observations=None`, mirroring `nuclei_candidates` exactly (SARIF +
`recon_<id>.json` + a `run.json` summary; independently omittable; findings JSON
untouched). `modules/recon.py` now runs nuclei + httpx + tlsx together into one combined
output. 24 offline tests against REAL captured httpx/tlsx JSON (one from DVWA, one from a
self-signed cert on a throwaway local TLS listener spun up just for the capture).

Also **found and fixed a real bug** while building this: httpx v1.10.0 (pinned by an
earlier, still-uncommitted tool-install task) makes an unconditional network call to
huggingface.co on every single run — not gated by `-disable-update-check` — downloading a
92MB ML model. In the real egress-locked sandbox this would be blocked and stall every
scan. Downgraded the pin to v1.9.0 (independently verified clean), the same
"pin-to-avoid-bad-behavior" pattern as Dalfox's v2.13.0 pin.

**Next:** A live end-to-end `modules.recon` run once the sandbox networking issue is
resolved (see Blockers — re-confirmed this session, independent of any recon code). Then
idor/auth agents, and the long-outstanding live `scan_xss()` smoke.

**Blockers:** Same host-local sandbox-networking issue as the nuclei agent — a trivial
`curl` through `run_in_sandbox` still fails today. Re-verified this session that it is
NOT caused by recon_tools/nuclei_agent code (both correctly surface it as `status="error"`,
never a false clean/found/observed). See `HANDOFF.md` for the exact diagnostic detail.

### 2026-07-12 — nuclei output surfacing (SARIF / JSON / run.json)

**Done:** Surfaced nuclei candidates into the output layer WITHOUT touching the
frozen `schemas.py` or the typed `findings_<id>.json` (decision D-017).
`engine/report_io.py`'s `write_outputs` gained an optional `nuclei_candidates=None`:
found candidates append to the SARIF report (ruleId = template_id; nuclei-severity →
SARIF level), the full raw list writes to `nuclei_<id>.json`, and a `nuclei` summary
block (found/clean/error + by-severity) is added to `run_<id>.json`. With the param
omitted, all existing SQLi/XSS output is byte-for-byte unchanged (proven by diffing
against HEAD). Added `modules/recon.py` (`run_recon_scan`) chaining `run_nuclei_agent`
→ `write_outputs`, deliberately NOT wired into `integration.py`'s resolver.
`tests/test_report_io.py` (11 tests, real captured JSONL); `git diff --stat schemas.py`
empty. New decision D-017.

**Next:** A live end-to-end `modules.recon` run (blocked by the orphaned host-local
sandbox networking state — see `HANDOFF.md`). Then idor/auth agents, and the
long-outstanding live `scan_xss()` smoke.

**Blockers:** Same host-local sandbox-networking blocker as the nuclei agent (leftover
docker network + iptables rules from a crashed run) — see `HANDOFF.md`.

### 2026-07-12 — nuclei template-scan agent (third agent)

**Done:** Added `engine/nuclei_agent.py` — a third agent-driven vuln-class scanner,
parallel to SQLi (`engine/agent.py`) and XSS (`engine/xss_agent.py`), driving nuclei
for CVEs / misconfigurations / exposures. Same shape: ONE harness-owned `run_nuclei`
tool (model supplies only target + optional safe-allowlist tags + note, never flags),
scope-gated + sandbox-only via `run_in_sandbox`, evidence-gated on parsed `-jsonl`
result lines (`status="found"` comes solely from nuclei output), bounded completion
pass, per-candidate `error` status (never a false clean/found). `NucleiCandidate`/
`NucleiAgentResult` are local, not in the frozen `schemas.py`. 34 offline tests against
REAL captured DVWA JSONL fixtures; 105-test regression clean; no engine/schemas
changes. Prereqs completed on this branch: pinned nuclei v3.11.0 + templates v10.4.5
baked into the sandbox image, and a required Dockerfile fix moving nuclei's XDG
config/cache to `/tmp` so real (writing) scans work under the frozen read-only sandbox
(see D-015). New decisions: D-015 (config-dir under /tmp), D-016 (nuclei detection-only
safety profile). See `HANDOFF.md` for exact file diffs + the one live-smoke blocker.

**Next:** Prompt 3 — map `NucleiCandidate(status="found")` → schema-valid `Finding`
(+ severity mapping info/low/medium/high/critical → Critical/High/Medium/Low; decide
how nuclei's CVE/misconfig/exposure results fit the frozen `SQLi/XSS/IDOR/BrokenAuth`
Finding types) and wire output (`report_io` + a `modules/` entry point / resolver).

**Blockers:** Live nuclei smoke is blocked by orphaned host-local sandbox networking
state (a crashed run's leftover docker network + iptables rules), not by agent code —
see `HANDOFF.md` "Open issues / blockers" for the exact user cleanup step.

### 2026-07-12 — Continuity docs created

**Done:** Created `PROGRESS.md` (this file) and `DECISIONS.md` so a new session
or teammate can pick up RedSee's agentic-transformation work without prior
conversation context. Cross-referenced `AGENTS.md` and `HANDOFF.md` instead of
duplicating their content.

**Next:** Generalize the agent-driven pattern (`engine/*_agent.py` +
`engine/*_finding_map.py` + agent-backed `modules/*.py` wrapper with static
fallback) to `idor` and `auth`. See `HANDOFF.md` for the exact in-flight state
and any open blockers as of the last working session.

**Blockers:** None blocking this task. See `HANDOFF.md`'s "Open issues /
blockers" for live blockers on the engine work itself.

## How to use this file

At the **start** of a session, read the most recent session-log entry and the
roadmap table to see where things stand. At the **end** of a session, append a
new dated entry (newest on top, use the template above) and update any roadmap
rows whose Status changed, before the chat ends.
