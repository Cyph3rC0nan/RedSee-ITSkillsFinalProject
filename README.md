# RedSee

> **Dual-mode automated pentesting tool.** One scan, two reports: attacker's perspective and defender's perspective, both generated from real findings and live SIEM alerts.

RedSee crawls a target web application, runs four vulnerability scanners (SQL injection, XSS, IDOR, broken authentication), feeds the same activity to a Wazuh/Splunk SIEM, and produces two professional PDF reports through an LLM:

- **Red Team Report** — CVSS-scored findings, proof-of-concept, exploitation steps, remediation
- **Blue Team Report** — attack timeline, missed detections, copy-paste-ready Wazuh/Splunk rules

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Layout](#project-layout)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Full Pipeline (Recommended)](#full-pipeline-recommended)
  - [Standalone Scanner](#standalone-scanner)
  - [Crawler Only](#crawler-only)
  - [Log Ingestor Only](#log-ingestor-only)
  - [Report Engines Only](#report-engines-only)
  - [Flask Web UI](#flask-web-ui)
- [Vulnerability Modules](#vulnerability-modules)
- [Output Files](#output-files)
- [Demo Mode (Offline)](#demo-mode-offline)
- [Testing](#testing)
- [Project Constraints](#project-constraints)
- [Tech Stack](#tech-stack)
- [License](#license)

---

## Features

- **BFS web crawler** discovers pages, forms, and API endpoints (depth 5, max 100 pages)
- **Four scanner modules** with their own detection techniques:
  - `SQLi` — error-based, time-based blind, boolean-based blind, UNION-based
  - `XSS` — reflected, stored, DOM-based
  - `IDOR` — object-level authorization checks
  - `BrokenAuth` — default credentials, weak session handling
- **Dual-mode reports** generated via LLM (OpenRouter / DeepSeek / Claude / Ollama)
- **Live SIEM ingestor** for Wazuh and Splunk, normalized into a common `Event` shape
- **Graceful fallbacks** — every module has a stub; the pipeline never crashes on a missing dependency
- **Flask dashboard** (`app.py`) for launching scans and downloading reports from the browser
- **PDF generation** via WeasyPrint with custom Red/Blue themed CSS templates

---

## Architecture

```
                              ┌──────────────────────┐
   TARGET_URL  ──────────►   │  crawler.py          │
                              │  (BFS → Sitemap)     │
                              └──────────┬───────────┘
                                         │ list[Endpoint]
                  ┌──────────────────────┼──────────────────────────┐
                  ▼                      ▼                          ▼
         ┌─────────────────┐   ┌─────────────────┐         ┌─────────────────┐
         │ modules/sqli.py │   │ modules/xss.py  │  ...    │ modules/auth.py │
         │  scan_sqli()    │   │  scan_xss()     │         │  scan_auth()    │
         └────────┬────────┘   └────────┬────────┘         └────────┬────────┘
                  │                     │                          │
                  └──────────────┬──────┴──────────┬───────────────┘
                                 ▼                 ▼
                          list[Finding]      ───►  Wazuh / Splunk
                                 │                       │
                                 ▼                       ▼
                       ┌──────────────────┐   ┌────────────────────┐
                       │  red_report.py   │   │  log_ingestor.py   │
                       │  (LLM → PDF)     │   │  parse + fetch     │
                       └──────────────────┘   └─────────┬──────────┘
                                                         │ list[Event]
                                                         ▼
                                               ┌──────────────────┐
                                               │  blue_report.py  │
                                               │  (LLM → PDF)     │
                                               └──────────────────┘
```

**Red team data flow:** `crawler → modules/* → integration.run_full_scan → red_report`
**Blue team data flow:** `log_ingestor → integration.run_blue_analysis → blue_report`
**UI flow:** `app.py (Flask) → integration / log_ingestor → red_report / blue_report`

All cross-module data is typed by the dataclasses in `schemas.py` — these are a frozen team contract.

---

## Project Layout

```
RedSee/
├── schemas.py                 # Frozen dataclass contract (DO NOT MODIFY)
├── red_report.py              # LLM call + PDF generation (Red Team)
├── blue_report.py             # LLM call + PDF generation (Blue Team)
├── integration.py             # Pipeline orchestrator + stub-fallback
├── crawler.py                 # BFS web crawler → Sitemap
├── scanner.py                 # Standalone SQLi+XSS scanner
├── app.py                     # Flask backend, 8 API routes
├── log_ingestor.py            # Wazuh/Splunk parser + live Wazuh API
├── requirements.txt
├── .env / .env.example
│
├── modules/                   # Scanner modules (one public fn each)
│   ├── sqli.py
│   ├── xss.py
│   ├── idor.py
│   └── auth.py
│
├── utils/
│   └── http_helpers.py        # HTTPSession class + DVWA auth helper
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
│   ├── mock_wazuh_alerts.json
│   ├── findings_fallback.json
│   ├── wazuh_alerts_fallback.json
│   ├── sample_wazuh_alerts.json
│   └── sample_splunk_export.json
│
├── tests/                     # Standalone test scripts (run with `python`)
│   ├── test_sqli.py
│   ├── test_xss.py
│   ├── test_idor.py
│   ├── test_auth.py
│   ├── test_ingestor.py
│   ├── test_crawler.py
│   ├── test_red_report.py
│   └── test_blue_report.py
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

## Installation

### Prerequisites

- **Python 3.10+**
- **Docker** (only if you want local DVWA / Juice Shop targets)
- **WeasyPrint system deps** on Linux: `libpango`, `libcairo`, `libgdk-pixbuf` (already installed on macOS and Windows via wheels)

### Steps

```bash
# 1. Clone
git clone https://github.com/<your-org>/RedSee.git
cd RedSee

# 2. Virtual env
python -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows

# 3. Install
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
# edit .env with your values
```

---

## Configuration

All runtime config comes from `.env`. Copy `.env.example` to `.env` and fill in:

| Key | Required | Default | Purpose |
|---|---|---|---|
| `LLM_PROVIDER` | yes | `openrouter` | `openrouter` / `deepseek` / `ollama` |
| `OPENROUTER_API_KEY` | if openrouter | — | OpenRouter API key |
| `OPENROUTER_BASE_URL` | no | `https://openrouter.ai/api/v1` | OpenRouter endpoint |
| `LLM_MODEL` | no | `deepseek/deepseek-v4-flash` | Fast model |
| `LLM_MODEL_DETAILED` | no | `anthropic/claude-sonnet-4-20250514` | Polished model |
| `OLLAMA_URL` / `OLLAMA_MODEL` | if ollama | — | Local fallback |
| `TARGET_URL` | yes | — | Pentest target (DVWA / Juice Shop / custom) |
| `TARGET_AUTH_USER` / `TARGET_AUTH_PASS` | for authenticated scans | — | Login creds |
| `WAZUH_API_URL` / `WAZUH_API_USER` / `WAZUH_API_PASS` | for live Wazuh | — | SIEM API |
| `WAZUH_DASHBOARD_URL` | no | — | Wazuh UI link |

---

## Quick Start

```bash
# 1. Start demo targets (DVWA + Juice Shop) + Flask server
bash docker/demo-helper.sh start

# 2. Open the dashboard
# http://localhost:5000

# 3. Click "Start Scan" — the pipeline runs end to end

# 4. Download the Red report and the Blue report
```

That's it. The full pipeline crawls the target, runs all four scanners, generates the Red PDF, and (if Wazuh is configured) generates the Blue PDF.

---

## Usage

### Full Pipeline (Recommended)

Runs crawler → all 4 scanners → red report. Optionally run blue report if SIEM is available.

```python
from integration import run_full_scan, run_blue_analysis

# Red team
result = run_full_scan("http://localhost", scan_id="demo_001")
print(result["report_path"])           # → outputs/red_report_demo_001.pdf

# Blue team (needs Wazuh or sample_data/sample_wazuh_alerts.json)
result = run_blue_analysis("sample_data/sample_wazuh_alerts.json", report_id="incident_001")
print(result["report_path"])           # → outputs/blue_report_incident_001.pdf
```

Or as a CLI smoke test:

```bash
python integration.py
```

### Standalone Scanner

Run SQLi + XSS only (no full pipeline):

```bash
# Auto-discover + scan
python scanner.py

# Specific target
python scanner.py --target http://localhost:80

# Use a pre-crawled sitemap
python scanner.py --sitemap sample_data/mock_sitemap.json

# Quick mode — targeted endpoints only
python scanner.py --quick
```

### Crawler Only

```bash
python crawler.py http://localhost
# Writes Sitemap JSON, prints summary
```

### Log Ingestor Only

```bash
# Parse a local file
python log_ingestor.py sample_data/sample_wazuh_alerts.json

# Or import the parser
python -c "from log_ingestor import ingest_log_file; print(ingest_log_file('sample_data/sample_splunk_export.json'))"
```

### Report Engines Only

```bash
# Generate a Red report from a findings JSON
python red_report.py

# Generate a Blue report from an events JSON
python blue_report.py
```

### Flask Web UI

```bash
python app.py
# Open http://localhost:5000
```

The dashboard exposes all 8 routes:

| Method | Route | Use |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `POST` | `/scan` | Start a red-team scan in the background |
| `GET` | `/scan/<id>/status` | Poll scan progress |
| `GET` | `/scan/<id>/findings` | Fetch findings JSON for a scan |
| `POST` | `/scan/<id>/report` | Generate the Red PDF for a scan |
| `POST` | `/analyze-logs` | Parse a Wazuh/Splunk log file |
| `POST` | `/fetch-wazuh-alerts` | Fetch live alerts from the Wazuh API |
| `POST` | `/generate-blue-report` | Generate the Blue PDF from events |
| `GET` | `/downloads/<filename>` | Download a generated PDF |

---

## Vulnerability Modules

Every module is a single public function with the same signature:

```python
def scan_<name>(endpoints: list[Endpoint], session: Optional[HTTPSession] = None) -> list[Finding]
```

| Module | File | Detection techniques |
|---|---|---|
| SQLi | `modules/sqli.py` | error-based, time-based blind, boolean-based blind, UNION-based (SQLite, MySQL, PostgreSQL, MSSQL, Oracle) |
| XSS | `modules/xss.py` | reflected, stored, DOM-based (HTML + JSON contexts) |
| IDOR | `modules/idor.py` | object-level authorization checks via parameter mutation |
| BrokenAuth | `modules/auth.py` | default credentials, weak session handling, missing auth on sensitive endpoints |

If `HTTPSession` is passed, scanners use the pre-authenticated session. Otherwise they make raw `requests` calls with a fresh session.

---

## Output Files

Everything lands in `outputs/`:

```
outputs/
├── findings_<scan_id>.json      # Raw findings (one JSON per scan)
├── red_report_<scan_id>.pdf     # Red Team report
├── blue_report_<report_id>.pdf  # Blue Team report
├── red_report_test_001.pdf      # Standalone red_report.py test output
├── blue_report_incident_001.pdf # Standalone blue_report.py test output
├── red_report_fallback.pdf      # Demo-day fallback (always available)
└── blue_report_fallback.pdf     # Demo-day fallback (always available)
```

The `outputs/` directory is gitignored except for `.gitkeep`.

---

## Demo Mode (Offline)

Every component has a fallback so the pipeline can run with **no live target, no LLM, and no SIEM**:

| Component | Live | Fallback |
|---|---|---|
| Crawler | BFS against target | Returns an empty Sitemap (pipeline continues, findings=0) |
| Vulnerability scanners | Real requests | Each module returns `[]` on empty Sitemap |
| LLM | OpenRouter / DeepSeek / Claude | Swap to Ollama via `LLM_PROVIDER=ollama` |
| Wazuh fetch | Live API | Returns 500 JSON (graceful error, no crash) |
| PDF generation | `outputs/red_report_<id>.pdf` | Falls back to `outputs/red_report_fallback.pdf` |
| Demo data | `sample_data/*.json` | Pre-built fixtures loadable from the Flask UI |

For a guaranteed demo with no external services, point the pipeline at `sample_data/findings_fallback.json` and `sample_data/wazuh_alerts_fallback.json` — pre-built Red and Blue PDFs will be produced.

---

## Testing

Tests are **standalone scripts**, not pytest. Each test file is runnable as a plain Python script.

```bash
# From project root
python tests/test_sqli.py
python tests/test_xss.py
python tests/test_idor.py
python tests/test_auth.py
python tests/test_ingestor.py
python tests/test_crawler.py
python tests/test_red_report.py
python tests/test_blue_report.py
```

Some tests (`test_sqli.py`, `test_xss.py`, `test_crawler.py` DVWA/Juice Shop variants) require a live target from `TARGET_URL` in `.env`. They are designed to fail gracefully when the target is unreachable — that is expected and not a regression.

Run only the tests for modules you changed.

---

## Project Constraints

These are team-wide rules enforced by review, not by tooling. See `AGENTS.md` for the full list.

- `schemas.py` is a **frozen contract**. Do not add, rename, or delete fields.
- Enum values are **exact strings**:
  - Severity: `Critical` / `High` / `Medium` / `Low`
  - Finding type: `SQLi` / `XSS` / `IDOR` / `BrokenAuth`
  - Endpoint type: `form` / `api` / `link` / `page`
  - Event source: `Wazuh` / `Splunk`
- `Finding.timestamp` must be **ISO 8601 with trailing `Z`**.
- New scanner modules must expose **one public function** and **add a stub + try/except block** in `integration.py` following the existing pattern.
- **No formatter, linter, or type-checker** is configured. Do not add config files for these unless asked.
- `red_report.py` owns `call_llm`, `load_prompt`, `markdown_to_pdf`. `blue_report.py` imports from it — do not duplicate.

---

## Tech Stack

- **Python 3.10+**
- `requests` + `beautifulsoup4` + `lxml` — crawling and HTTP
- `flask` + `flask-cors` — web UI
- `weasyprint` + `markdown` — PDF generation
- `openai` (>=1.6.0) — OpenAI-compatible chat completions (works with OpenRouter, DeepSeek, Ollama)
- `python-dotenv` — `.env` loading
- **Docker** — local DVWA / Juice Shop demo targets

---

## License

See `LICENSE` in the repository root.
