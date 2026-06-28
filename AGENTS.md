# AGENTS.md

Post-integration state of **RedSee** — automated web/API pentesting tool with dual-mode AI reporting (Red Team attack perspective + Blue Team defender perspective).

**Last integration date:** 2026-06-28
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

---

## Module contract

- Every scanner module (under `modules/`) exposes **exactly one public function**: `scan_sqli(endpoints, session?) → list[Finding]`, `scan_xss(endpoints, session?) → list[Finding]`, `scan_idor(endpoints, session?) → list[Finding]`, `scan_auth(endpoints, session?) → list[Finding]`.
- The `session` parameter is optional — modules must work with or without a `utils.http_helpers.HTTPSession`.
- Any new module **must** add a try/except ImportError block in `integration.py` following the `_has_X` / `_stub_X()` / resolver pattern.

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
- Integration uses stub-fallback pattern: `_has_X` flag → `_stub_X()` function → `_X()` resolver that picks real or stub. This keeps the pipeline testable when modules are missing.
- **`app.py` route → `integration.py` → modules/ is the canonical red-team data flow.** The Flask background worker calls `integration.run_full_scan(target_url, scan_id=...)`, which updates `integration._scan_status` (read by `app.py /scan/<id>/status`) and writes `outputs/findings_{scan_id}.json` (read by `app.py /scan/<id>/findings`).
- **`app.py` route → `log_ingestor.py` → `blue_report.py` is the canonical blue-team data flow.** `/analyze-logs` and `/fetch-wazuh-alerts` return normalized `Event` dicts; `/generate-blue-report` consumes the same dict shape.

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
| `modules/sqli.py` | Member 3 | `scan_sqli(endpoints, session?) → list[Finding]` |
| `modules/xss.py` | Member 3 | `scan_xss(endpoints, session?) → list[Finding]` |
| `modules/idor.py` | Member 4 | `scan_idor(endpoints, session?) → list[Finding]` |
| `modules/auth.py` | Member 4 | `scan_auth(endpoints, session?) → list[Finding]` |
| `log_ingestor.py` | Member 4 | `ingest_log_file`, `fetch_wazuh_alerts` |
| `app.py` | Member 4 | Flask backend, 8 routes |
| `templates/index.html` | Member 4 | Dark cybersecurity dashboard |
| `static/style.css` | Member 4 | Theme + severity coloring |
| `static/script.js` | Member 4 | Frontend logic (tab switch, polling, fetch) |
| `docker/demo-helper.sh` | Member 4 | DVWA + Juice Shop launcher |

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
│   ├── sqli.py                # Member 3
│   ├── xss.py                 # Member 3
│   ├── idor.py                # Member 4
│   └── auth.py                # Member 4
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
│   └── blue_prompt.txt
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
│   ├── test_sqli.py           # SQLi tests (some require live DVWA)
│   ├── test_xss.py            # XSS tests (some require live DVWA)
│   ├── test_crawler.py        # Crawler tests
│   ├── test_red_report.py     # Report engine tests
│   └── test_blue_report.py    # Blue report tests
│
├── docker/
│   └── demo-helper.sh         # DVWA + Juice Shop launcher
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

---

## Known limitations / next steps

- 2 SQLi tests require a live DVWA target (`TARGET_URL` from `.env`). Skipped when unreachable.
- Wazuh fetch route returns 500 when Wazuh is unreachable — the UI surfaces this as a toast error. No retry/backoff yet.
- Flask debug mode is enabled in `app.py` for development — disable for production deployment.
- No persistent storage: scans are kept in-memory + `outputs/findings_{id}.json`. Restarting Flask loses in-memory status but findings JSONs remain on disk.

---

*Last updated: 2026-06-28 — Phase 4 integration complete.*
