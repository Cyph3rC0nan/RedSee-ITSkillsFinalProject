# AGENTS.md

Post-integration state of **RedSee** — automated web/API pentesting tool with dual-mode AI reporting (Red Team attack perspective + Blue Team defender perspective).

**Last integration date:** 2026-06-28
**Agent engine bridged into the pipeline:** 2026-07-09
**Active branch:** `main`

---

## Must-follow constraints

- **`schemas.py` is a team contract.** Do not add, rename, or delete fields in any dataclass (`Endpoint`, `Finding`, `Event`, `Sitemap`, `ScanResult`) without explicit instruction. Header comment says "DO NOT MODIFY AFTER DAY 3 WITHOUT TEAM-WIDE ANNOUNCEMENT."
- **Severity values are exact strings:** `Critical`, `High`, `Medium`, `Low`. No "CRITICAL" or "critical".
- **Finding types are exact strings:** `SQLi`, `XSS`, `IDOR`, `BrokenAuth`.
- **Endpoint types are exact strings:** `form`, `api`, `link`, `page`.
- **Event sources are exact strings:** `Wazuh`, `Splunk`.
- **Finding.timestamp must be ISO 8601 with trailing `Z`** (e.g. `"2025-06-01T14:32:00Z"`).
- **`.env` is required** for target URL, auth, Wazuh, and LLM configs. See `.env.example` for all keys.
- **A `Finding` may only be produced from a CONFIRMED, evidence-backed result.** For the agent-backed SQLi path this means `engine.finding_map.candidate_to_finding` only ever accepts a `SqliCandidate` with `status == "injectable"` (a real parsed sqlmap positive) — it raises `ValueError` on `clean`/`error`/`out_of_scope` input. No module may fabricate a Finding from a guess, an LLM claim, or a non-zero-exit/timeout scan.

---

## Agent engine (`engine/`)

A sandboxed, LLM-driven detection engine that sits behind `modules/sqli.py`. Layered so each module only trusts the one below it; every layer is independently testable offline (see `tests/test_agent.py`, `tests/test_sandbox.py`, `tests/test_scope.py`, `tests/test_llm.py`, `tests/test_finding_map.py`).

| Module | One-line contract |
|---|---|
| `engine/scope.py` | Layer 1 — default-deny authorization/scope gate. `assert_in_scope(url, config)` and `require_authorization(config)` must pass before any active test; `load_scope_config()` reads `REDSEE_*` env vars. |
| `engine/sandbox.py` | Layer 2 — isolation boundary. `run_in_sandbox(argv, target_url, config)` runs sqlmap in a throwaway, egress-locked Docker container (target IP:port only); runs a fail-closed isolation self-test before trusting any result; always tears down. |
| `engine/llm.py` | Layer 3 — BYOK LLM client. Provider-agnostic OpenAI-compatible `/chat/completions` wrapper (`LLMClient.chat`) with a hard per-scan `BudgetTracker` cap; fails closed on missing config, never silently swaps providers. |
| `engine/agent.py` | Layer 4 — the plan→act→observe reasoning loop. `run_sqli_agent(endpoints, ...)` drives the model over a fixed, detection-only `run_sqlmap` tool along a bounded escalation ladder, plus a deterministic completion pass; returns `SqliAgentResult` (`candidates: list[SqliCandidate]`, `usage`, `stopped_reason`). `SqliCandidate.status` is one of `injectable`/`clean`/`error`/`out_of_scope` — never fabricated from anything but parsed sqlmap output. |
| `engine/finding_map.py` | Maps a confirmed (`status=="injectable"`) `SqliCandidate` to a schema-valid `Finding` (`candidate_to_finding`). Severity: `High` by default, `Critical` only for union/error-based technique. Raises on any non-injectable input. |
| `engine/report_io.py` | Writes the audit trail for one agent run: `write_outputs(...)` produces `findings_<id>.json` (same shape `integration.py`/`red_report.py` already consume), a minimal hand-built SARIF 2.1.0, and `run_<id>.json` (usage/cost/stopped_reason/status summary) — `llm_meta` is scrubbed of any key/token/secret/authorization-shaped field before writing. An optional `nuclei_candidates=` param additively surfaces found `NucleiCandidate`s into the SARIF (ruleId=template_id), a dedicated `nuclei_<id>.json`, and a `run_<id>.json` nuclei summary — these are broader than the frozen Finding enum so they are NEVER typed Findings and NEVER enter `findings_<id>.json` (see DECISIONS D-017); omitting it leaves all existing output byte-for-byte unchanged. |

**Security invariants (agent engine) — do not weaken without team sign-off:**
- **Scope gate first.** `assert_in_scope` runs before every sandbox execution; an out-of-scope URL is refused, never tested (`status="out_of_scope"`).
- **Sandbox isolation, always.** All sqlmap execution goes through `engine.sandbox.run_in_sandbox` — never the host, never a raw subprocess. A failed isolation self-test aborts the run and returns no scan output (`status="error"`, never treated as clean).
- **Detection-only sqlmap flags.** `engine.agent._FORBIDDEN_LITERAL` permanently bans exploitation flags (`--os-shell`, `--file-read`, `--dump`, `--eval`, ...) **and** enumeration/retrieval flags (`--banner`, `--current-db`, `--current-user`, `--users`, `--dbs`, `--tables`, `--columns`, `--schema`, `--hostname`); `--answers=exploit=N,...` blocks `--batch` from auto-proceeding into exploitation. `--level`/`--risk`/`--technique` are capped by `max_level`/`max_risk` (default 3/2; opt-in 5/3) and restricted to `{B,E,U,S,T}`.
- **Evidence-only findings.** `injectable` is derived SOLELY from parsed sqlmap positive output (`engine.agent._parse_sqlmap_output`) — never from the model's assertion, DBMS detection alone, or HTTP error volume. `engine.finding_map.candidate_to_finding` refuses to build a `Finding` from anything but `status=="injectable"`.
- **Budget cap enforced pre-call.** One `BudgetTracker` per run; `check_before_call()` runs before every LLM turn and raises before the call is made once the cap (`REDSEE_LLM_MAX_USD`, default `1.00`) is reached — no call, no sqlmap execution, `stopped_reason="budget"`.
- **No secrets in output.** `engine.report_io.write_outputs` scrubs any `llm_meta` key containing `key`/`token`/`secret`/`authorization`/`password` before writing `run_<id>.json`; the LLM API key is never logged to a transcript or output file.

---

## Module contract

- Every scanner module (under `modules/`) exposes **exactly one public function**: `scan_sqli(endpoints, session?) → list[Finding]`, `scan_xss(endpoints, session?) → list[Finding]`, `scan_idor(endpoints, session?) → list[Finding]`, `scan_auth(endpoints, session?) → list[Finding]`.
- The `session` parameter is optional — modules must work with or without a `utils.http_helpers.HTTPSession`.
- Any new module **must** add a try/except ImportError block in `integration.py` following the `_has_X` / `_stub_X()` / resolver pattern.
- **`modules/sqli.py` is now agent-backed.** `scan_sqli` tries the sandboxed `engine.agent`-driven path first (`_agent_scan_sqli`, mapped to `Finding` via `engine.finding_map`) and transparently falls back to `_legacy_scan_sqli` — the original direct-HTTP error/time/boolean/UNION scanner — on `engine` import failure (`_HAS_AGENT=False`) OR any runtime failure (LLM/scope/sandbox not configured). The public signature `scan_sqli(endpoints, session=None) → list[Finding]` and `integration.py`'s resolver are unchanged either way.

---

## Validation before finishing

- **Tests are pytest-discoverable standalone scripts.** Run with `PYTHONPATH=. python -m pytest tests/test_<name>.py -v` from project root. Test functions live alongside `if __name__ == "__main__"` blocks so they also work as plain scripts.
- Run tests only for modules you changed. Tests that hit a live `TARGET_URL` from `.env` will fail if the target is unreachable — that is expected.
- **Integration smoke test**: `python integration.py` (runs red + blue pipelines end-to-end and generates PDFs in `outputs/`).
- **Flask smoke test**: start `python app.py`, then curl all 8 routes per `docs/demo_script.md`.

---

## Repo-specific conventions

- **No formatter, no linter, no type-checker configured.** Do not introduce config files for these unless asked.
- `outputs/` is gitignored except `.gitkeep`. Generated PDFs and JSON go here.
- `red_report.py` owns all LLM + PDF utilities: `call_llm`, `load_prompt`, `markdown_to_pdf`. `blue_report.py` imports them from `red_report.py` — do not duplicate.
- Integration uses stub-fallback pattern: `_has_X` flag → `_stub_X()` function → `_X()` resolver that picks real or stub. This keeps the pipeline testable when modules are missing. `modules/sqli.py` uses the same shape internally (`_HAS_AGENT` → `_legacy_scan_sqli()` → `scan_sqli()` resolver) to fall back from the agent engine to the legacy scanner.
- **`app.py` route → `integration.py` → modules/ is the canonical red-team data flow.** The Flask background worker calls `integration.run_full_scan(target_url, scan_id=...)`, which updates `integration._scan_status` (read by `app.py /scan/<id>/status`) and writes `outputs/findings_{scan_id}.json` (read by `app.py /scan/<id>/findings`).
- **`app.py` route → `log_ingestor.py` → `blue_report.py` is the canonical blue-team data flow.** `/analyze-logs` and `/fetch-wazuh-alerts` return normalized `Event` dicts; `/generate-blue-report` consumes the same dict shape.
- **Agent-engine `REDSEE_*` env keys** (see `.env.example`, `engine/scope.py`, `engine/llm.py`): `REDSEE_TARGET_URL`, `REDSEE_ALLOWED_HOSTS` (comma-separated exact hostnames, default-deny), `REDSEE_AUTHORIZED` (must be `"true"` before any active test), `REDSEE_RATE_LIMIT` — scope gate; `REDSEE_LLM_BASE_URL`, `REDSEE_LLM_MODEL`, `REDSEE_LLM_API_KEY` (optional), `REDSEE_LLM_MAX_USD` (hard per-scan spend cap, **defaults to `0` in this repo's `.env`** — export a higher value to let the agent path actually run, otherwise it stops immediately with `stopped_reason="budget"` and 0 sqlmap calls), `REDSEE_LLM_PRICE_IN_PER_1K`, `REDSEE_LLM_PRICE_OUT_PER_1K`, `REDSEE_LLM_TIMEOUT` — BYOK LLM layer. These are separate from the legacy `TARGET_URL`/`LLM_PROVIDER`/`OPENROUTER_*` keys used by `red_report.py`/the direct-HTTP scanners.

---

## File ownership map

| File | Owner | Notes |
|---|---|---|
| `schemas.py` | Team Lead (frozen) | DO NOT MODIFY |
| `red_report.py` | Team Lead | Owns `call_llm`, `load_prompt`, `markdown_to_pdf` |
| `blue_report.py` | Team Lead | Imports LLM/PDF utilities from `red_report.py` |
| `integration.py` | Team Lead | Pipeline orchestrator; extends via `_has_X` stubs |
| `crawler.py` | Member 2 | `crawl(target_url, auth_type="auto") → Sitemap` |
| `utils/http_helpers.py` | Member 2 | `HTTPSession` class |
| `modules/sqli.py` | Member 3 | `scan_sqli(endpoints, session?) → list[Finding]` — agent-backed first, `_legacy_scan_sqli` fallback |
| `modules/xss.py` | Member 3 | `scan_xss(endpoints, session?) → list[Finding]` |
| `modules/idor.py` | Member 4 | `scan_idor(endpoints, session?) → list[Finding]` |
| `modules/auth.py` | Member 4 | `scan_auth(endpoints, session?) → list[Finding]` |
| `log_ingestor.py` | Member 4 | `ingest_log_file`, `fetch_wazuh_alerts` |
| `app.py` | Member 4 | Flask backend, 8 routes |
| `templates/index.html` | Member 4 | Dark cybersecurity dashboard |
| `static/style.css` | Member 4 | Theme + severity coloring |
| `static/script.js` | Member 4 | Frontend logic (tab switch, polling, fetch) |
| `docker/demo-helper.sh` | Member 4 | DVWA + Juice Shop launcher |
| `engine/scope.py` | Agent engine | Layer 1 — authorization/scope gate |
| `engine/sandbox.py` | Agent engine | Layer 2 — isolated Docker sqlmap execution |
| `engine/llm.py` | Agent engine | Layer 3 — BYOK LLM client + budget tracker |
| `engine/agent.py` | Agent engine | Layer 4 — `run_sqli_agent` plan→act→observe loop |
| `engine/finding_map.py` | Agent engine | `candidate_to_finding(cand, *, target_url, scan_id) → Finding` |
| `engine/report_io.py` | Agent engine | `write_outputs(...)` — findings/SARIF/run.json audit trail |

---

## Project layout

```
RedSee/
├── schemas.py                 # Frozen dataclass contract (DO NOT MODIFY)
├── red_report.py              # LLM call + PDF generation (Red Team)
├── blue_report.py             # LLM call + PDF generation (Blue Team)
├── integration.py             # Pipeline orchestrator + stub-fallback
├── crawler.py                 # BFS web crawler → Sitemap
├── scanner.py                 # Standalone SQLi+XSS scanner (Member 3 CLI)
├── app.py                     # Flask backend, 8 API routes
├── log_ingestor.py            # Wazuh/Splunk parser + live Wazuh API
├── requirements.txt
├── .env / .env.example
│
├── modules/                   # Scanner modules (one public fn each)
│   ├── __init__.py
│   ├── sqli.py                # Member 3 — agent-backed + _legacy_scan_sqli fallback
│   ├── xss.py                 # Member 3
│   ├── idor.py                # Member 4
│   └── auth.py                # Member 4
│
├── engine/                    # Sandboxed, LLM-driven SQLi detection agent
│   ├── __init__.py
│   ├── scope.py               # Layer 1 — authorization/scope gate
│   ├── sandbox.py             # Layer 2 — isolated Docker sqlmap execution
│   ├── llm.py                 # Layer 3 — BYOK LLM client + budget tracker
│   ├── agent.py               # Layer 4 — run_sqli_agent plan→act→observe loop
│   ├── finding_map.py         # SqliCandidate -> schema-valid Finding
│   └── report_io.py           # findings/SARIF/run.json audit-trail writer
│
├── utils/
│   ├── __init__.py
│   └── http_helpers.py        # HTTPSession, DVWA auth helper
│
├── templates/index.html       # Member 4
├── static/
│   ├── style.css              # Member 4 (636 lines)
│   └── script.js              # Member 4 (614 lines, 19 fns)
│
├── prompts/                   # LLM system prompts
│   ├── red_prompt.txt
│   ├── blue_prompt.txt
│   └── sqli_agent.txt         # System prompt for engine/agent.py's run_sqli_agent
│
├── pdf_templates/             # WeasyPrint CSS
│   ├── red.css
│   └── blue.css
│
├── sample_data/               # Demo + fallback JSON fixtures
│   ├── mock_findings.json
│   ├── mock_sitemap.json
│   ├── mock_wazuh_alerts.json # Normalized Event format (Phase 4 fallback)
│   ├── findings_fallback.json # Phase 6 fallback
│   ├── wazuh_alerts_fallback.json  # Phase 6 fallback (15 events)
│   ├── sample_wazuh_alerts.json    # Raw Wazuh format (10 events)
│   └── sample_splunk_export.json   # Raw Splunk format (4 events)
│
├── tests/                     # pytest-discoverable structural tests
│   ├── test_idor.py           # 7 tests (6 structural + 1 live skipped)
│   ├── test_auth.py           # 9 tests (8 structural + 1 live skipped)
│   ├── test_ingestor.py       # 9 tests (all structural, all pass)
│   ├── test_sqli.py           # 10 tests: 4 legacy live-DVWA + 6 offline agent-backed/fallback
│   ├── test_xss.py            # XSS tests (some require live DVWA)
│   ├── test_crawler.py        # Crawler tests
│   ├── test_red_report.py     # Report engine tests
│   ├── test_blue_report.py    # Blue report tests
│   ├── test_scope.py          # engine/scope.py — offline, all pass
│   ├── test_sandbox.py        # engine/sandbox.py — offline, all pass
│   ├── test_llm.py            # engine/llm.py — offline, all pass
│   ├── test_agent.py          # engine/agent.py — 47 tests, fully offline (mocked sandbox/LLM)
│   └── test_finding_map.py    # engine/finding_map.py + report_io.py — 12 tests, offline
│
├── docker/
│   ├── demo-helper.sh         # DVWA + Juice Shop launcher
│   └── sandbox/               # Dockerfile + build.sh for the sqlmap sandbox image
│
├── docs/
│   └── demo_script.md
│
└── outputs/                   # Generated PDFs + findings JSON (gitignored)
    └── .gitkeep
```

---

## API routes (Flask)

| Method | Route | Handler | Backed by |
|---|---|---|---|
| GET  | `/` | `index()` | `templates/index.html` |
| POST | `/scan` | `start_scan()` | spawns thread → `integration.run_full_scan` |
| GET  | `/scan/<id>/status` | `scan_status()` | `integration.get_scan_status` |
| GET  | `/scan/<id>/findings` | `scan_findings()` | `outputs/findings_{id}.json` |
| POST | `/scan/<id>/report` | `generate_report()` | `red_report.generate_red_report` |
| POST | `/analyze-logs` | `analyze_logs()` | `log_ingestor.ingest_log_file` |
| POST | `/fetch-wazuh-alerts` | `fetch_wazuh_alerts_route()` | `log_ingestor.fetch_wazuh_alerts` |
| POST | `/generate-blue-report` | `generate_blue_report_route()` | `blue_report.generate_blue_report` |
| GET  | `/downloads/filename` | `download_file()` | `outputs/*.pdf` |

---

## Integration points (verified working)

```
IP-1:  app.py  → integration.run_full_scan(target_url, scan_id)
IP-2:  integration → modules/sqli.scan_sqli(endpoints)
         → (agent-backed) engine.agent.run_sqli_agent → engine.finding_map.candidate_to_finding
         → (fallback) _legacy_scan_sqli  [see "Agent engine" section above]
IP-3:  integration → modules/xss.scan_xss(endpoints)
IP-4:  integration → modules/idor.scan_idor(endpoints)
IP-5:  integration → modules/auth.scan_auth(endpoints)
IP-6:  integration → red_report.generate_red_report(findings, scan_id)
IP-7:  app.py  → log_ingestor.ingest_log_file / fetch_wazuh_alerts
                → blue_report.generate_blue_report(events, report_id)
```

All 7 integration points live-tested via curl + Python requests in Phase 5 of integration.

---

## Test summary (post-integration)

```
PYTHONPATH=. python -m pytest tests/test_idor.py tests/test_auth.py \
  tests/test_ingestor.py tests/test_crawler.py::test_mock_sitemap_loads \
  tests/test_sqli.py::test_sqli_no_false_positive \
  tests/test_xss.py::test_xss_no_false_positive

Result: 27 passed, 2 skipped (live tests requiring DVWA), 1 warning
```

Agent engine (fully offline, no Docker/LLM/network):

```
PYTHONPATH=. python -m pytest tests/test_scope.py tests/test_sandbox.py tests/test_llm.py \
  tests/test_agent.py tests/test_finding_map.py tests/test_sqli.py

Result: 98 passed, 3 skipped (live target/Ollama/weasyprint-dependent checks that
skip cleanly when unavailable; 4 legacy test_sqli.py tests need a live DVWA target
and use the print-based pass/fail convention, not pytest asserts — see file header)
```

End-to-end pipeline smoke test:
- `python integration.py` → red + blue PDFs in `outputs/`
- `python red_report.py` → `outputs/red_report_test_001.pdf` (62KB)
- `python blue_report.py` → `outputs/blue_report_incident_001.pdf` (61KB)
- `python log_ingestor.py sample_data/sample_wazuh_alerts.json` → 10 events parsed
- All 8 Flask routes verified via curl (200/400/404/500 paths)
- Phase 6 fallback PDFs generated: `outputs/red_report_fallback.pdf`, `outputs/blue_report_fallback.pdf`

---

## Demo-day fallback strategy

If live target / Wazuh / LLM is unreachable, the pipeline degrades gracefully:

| Component | Live | Fallback |
|---|---|---|
| Crawler | BFS target | Returns empty sitemap (pipeline continues, findings=0) |
| Vuln scanners | Real requests | Each module returns `[]` on empty sitemap |
| LLM | OpenRouter / DeepSeek | Could swap to Ollama via `LLM_PROVIDER=ollama` |
| Wazuh fetch | Live API | Returns 500 JSON (graceful error, no crash) |
| PDF generation | `outputs/red_report_<id>.pdf` | Always available — falls back to `outputs/red_report_fallback.pdf` |
| Demo data | `sample_data/*.json` | Pre-built fixtures always loadable via Flask UI |
| SQLi agent engine | Sandboxed sqlmap + configured LLM | Falls back to `_legacy_scan_sqli` (direct-HTTP scanner) on `engine` import failure or any runtime failure (LLM/scope/sandbox not configured, `REDSEE_LLM_MAX_USD=0`, etc.) — `scan_sqli` always returns a valid list, never raises |

---

## Known limitations / next steps

- 2 SQLi tests require a live DVWA target (`TARGET_URL` from `.env`). Skipped when unreachable.
- Wazuh fetch route returns 500 when Wazuh is unreachable — the UI surfaces this as a toast error. No retry/backoff yet.
- Flask debug mode is enabled in `app.py` for development — disable for production deployment.
- No persistent storage: scans are kept in-memory + `outputs/findings_{id}.json`. Restarting Flask loses in-memory status but findings JSONs remain on disk.
- The agent-backed SQLi path writes its own `findings_<agent-scan-id>.{json,sarif}` and `run_<agent-scan-id>.json` under a self-generated scan_id (separate from `integration.py`'s pipeline scan_id, by design — see `HANDOFF.md`), so a single `run_full_scan` can produce two differently-named findings JSON files if the agent path fires. Not yet unified into one audit trail per pipeline run.
- `docker/sandbox/` must be built (`bash docker/sandbox/build.sh`) and the host must have `iptables`/`docker` access (root) for the agent engine's sandbox isolation to work; without it, `run_in_sandbox` raises and `scan_sqli` falls back to `_legacy_scan_sqli`.

---

*Last updated: 2026-07-09 — SQLi agent engine (`engine/`) bridged into the red-team pipeline via `modules/sqli.py`.*
