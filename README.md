# RedSee

> **An authorized-only, agentic web-app pentesting platform with dual Red/Blue reporting.** A sandboxed, LLM-driven agent engine drives real security tools (sqlmap, Dalfox, nuclei, httpx, tlsx, ffuf) against one authorized target, aggregates everything into one unified scan record, and turns it into both an attacker's report and a defender's report — from the same evidence.

RedSee started as a static four-scanner pipeline and has since grown into an **agent-driven security engine**: a plan → act → observe loop drives real, sandboxed tools instead of hard-coded payload lists, every action is gated by an explicit authorization + scope check, every "found" verdict is derived solely from parsed tool output (never an LLM's say-so), and the whole thing runs behind a persistent scan queue and a dark-themed operations console.

---

## Table of Contents

- [What it does](#what-it-does)
- [Key capabilities](#key-capabilities)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Scan modes](#scan-modes)
- [Project layout](#project-layout)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick start](#quick-start)
- [Dashboard / API routes](#dashboard--api-routes)
- [Blue team / SIEM ingestion](#blue-team--siem-ingestion)
- [Reports](#reports)
- [Demo target](#demo-target)
- [Testing](#testing)
- [Known limitations](#known-limitations)
- [Tech stack](#tech-stack)
- [License](#license)

---

## What it does

Point RedSee at one authorized target's root URL. It:

1. **Crawls** the target (BFS, forms/links/JSON APIs, including endpoints only referenced inside JS bundles).
2. **Discovers** hidden top-level paths via content discovery (ffuf) — sections nothing on the crawled pages links to.
3. **Re-crawls** those discovered paths (bounded, scope-checked) to surface their own params.
4. **Seeds** common parameter names onto discovered API paths that expose no crawlable parameter (a JSON endpoint like `/rest/products/search?q=` often has no HTML form advertising `q`).
5. **Tests** every real parameter it now has — crawled or seeded — for SQL injection (sqlmap) and reflected XSS (Dalfox), each inside an isolated, egress-locked Docker sandbox.
6. **Runs recon** in parallel: template/CVE matching (nuclei), HTTP fingerprinting (httpx), TLS inspection (tlsx).
7. **Aggregates** all of it — findings, recon, tool statuses, discovery/seeding transparency — into one `scan_<id>.json`.
8. **Reports** it two ways: a Red Team report (findings, evidence, remediation) and a Blue Team report (from live/ingested SIEM alerts — attack timeline, missed detections, ready-to-use Wazuh/Splunk rules).

A single scan of the *root* URL — never told where `/market` or `/rest/products/search` live — finds vulnerabilities on both, automatically.

---

## Key capabilities

- **Sandboxed, LLM-driven agent engine** — a plan→act→observe loop drives sqlmap and Dalfox through a fixed, harness-owned, detection-only tool profile. The model chooses *what* to test; it never supplies raw tool flags, and it can't escalate past a hard-coded ceiling (`--level`/`--risk` caps, no exploitation/enumeration flags, ever).
- **Discovery-first scan orchestrator** (`modules/scan.py`) — crawl → discover (ffuf/httpx) → re-crawl discovered paths → build injection targets (crawled *and* seeded) → inject + recon concurrently, all under one shared `scan_id`.
- **Common-parameter seeding** (`engine/params.py`) — a curated, pinned parameter-name wordlist gets paired onto parameter-less API paths, so a JSON endpoint with no visible form field still gets tested. Seeding only proposes *candidates*; a finding still requires the tool to confirm injection.
- **Three scan modes** — `fast` (~2 min, top params only), `standard` (~5–8 min, discovery + seeding + scoped nuclei), `deep` (full breadth, no caps).
- **Six sandboxed tools, one harness** — sqlmap (SQLi), Dalfox (reflected XSS), nuclei (template/CVE matching, memory-scoped to fit a 256 MB sandbox), httpx (fingerprinting), tlsx (TLS/cert inspection), ffuf (content discovery) — each pinned to an exact, sha256-verified release in the sandbox image.
- **Evidence-only findings** — `injectable`/`found` is derived *solely* from parsed positive tool output (sqlmap's confirmed-injection text, Dalfox's `[POC]`/`[V]` lines, nuclei's JSONL matches, ffuf's hit lines). Never from a model's assertion.
- **Default-deny scope gating** — an explicit authorization attestation + host allow-list must pass *before* any active test; every URL is scope-checked again immediately before the sandbox runs it.
- **Egress-locked sandbox** — every tool run happens inside a throwaway, non-root, `--cap-drop=ALL`, read-only Docker container whose firewall allows *only* the single target `ip:port` it's authorized to contact — verified by a fail-closed isolation self-test before any result is trusted.
- **Persistent scan store** — a SQLite-backed queue + status lifecycle + history (`storage/scan_store.py`) survives a process restart; a scan interrupted mid-run reconciles to `error`, never left stuck.
- **Dark-themed operations console** — a Red Ops / Blue Ops dashboard: launch a scan (with a mode selector), watch it move through queued→running→done, browse history, drill into tool-by-tool status (with legible skip/error reasons, not just a bare status word), findings, and recon — plus a Blue Ops tab for SIEM log ingestion and blue-team reporting.
- **Deterministic report fallback** — both the Red and Blue report generators can build a full, professional report directly from the scan/event data via string templates (no LLM call, no `weasyprint` system-lib dependency required) if an LLM/PDF toolchain isn't configured — a report button never dead-ends.
- **Deployed** behind gunicorn/systemd with HTTP basic auth, reachable on a real domain.

---

## Architecture

```
                        ┌───────────────────────────────────────────┐
                        │              modules/scan.py                │
                        │         run_scan(target, mode=...)          │
                        └───────────────────────┬─────────────────────┘
                                                 │
   1. crawl(root) ──────────────────────────────┤
   2. discover (ffuf + httpx, concurrent) ──────┤
   3. re-crawl discovered paths (bounded) ───────┤
   4. build injection targets:                  │
        crawled params  ∪  seeded params ────────┤
   5. inject (sqlmap/Dalfox) + recon             │
        (nuclei/tlsx), concurrent ───────────────┤
   6. write ONE scan_<id>.json ──────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
              ┌──────────────────┐                              ┌──────────────────┐
              │ storage/         │                              │  outputs/         │
              │ scan_store.py    │                              │  scan_<id>.json   │
              │ (SQLite queue +  │                              │  findings/.sarif  │
              │  history)        │                              │  run/nuclei/recon │
              └────────┬─────────┘                              └──────────────────┘
                       │
                       ▼
              ┌──────────────────┐        ┌──────────────────┐
              │  app.py (Flask)  │───────▶│ red_report.py    │──▶ PDF or HTML
              │  dark SOC console│        │ (LLM or          │
              │  /api/scans      │        │  deterministic)  │
              └────────┬─────────┘        └──────────────────┘
                       │
                       ▼
              ┌──────────────────┐        ┌──────────────────┐
              │ log_ingestor.py  │───────▶│ blue_report.py   │──▶ PDF or HTML
              │ Wazuh/Splunk     │        │ (LLM or          │
              │ parse + fetch    │        │  deterministic)  │
              └──────────────────┘        └──────────────────┘
```

**The agent engine** (`engine/`) is the layered core every active tool runs through:

| Layer | Module | Contract |
|---|---|---|
| 1 — Scope | `engine/scope.py` | Default-deny authorization + host allow-list gate. Nothing active runs until this passes. |
| 2 — Sandbox | `engine/sandbox.py` | Isolated, egress-locked Docker execution. Fail-closed isolation self-test before any result is trusted. Frozen API. |
| 3 — LLM | `engine/llm.py` | Provider-agnostic (OpenAI-compatible) BYOK client with a hard per-scan spend cap, checked before every call. |
| 4 — Agents | `engine/agent.py` (sqlmap), `engine/xss_agent.py` (Dalfox), `engine/nuclei_agent.py` (nuclei) | The plan→act→observe loop. Model picks targets/depth; harness owns every tool flag. |
| Deterministic recon | `engine/recon_tools.py` | httpx/tlsx/ffuf — no model in the loop, one fixed profile per tool. |
| Seeding | `engine/params.py` | Injectable-parameter extraction from crawl output + common-parameter seeding for parameter-less API paths. |
| Mapping | `engine/finding_map.py` | Maps a *confirmed* candidate to a schema-valid `Finding` — refuses anything else. |
| Audit trail | `engine/report_io.py` | Writes `findings/.sarif/run/nuclei/recon` artifacts; scrubs secrets before anything touches disk. |

Full rationale for every architectural choice is in [`DECISIONS.md`](DECISIONS.md) (D-001 through D-026); day-to-day state lives in [`HANDOFF.md`](HANDOFF.md) and [`PROGRESS.md`](PROGRESS.md).

---

## Security model

RedSee performs **active** testing (sqlmap, Dalfox) against real targets, so the harness — not the model — owns every safety-relevant decision:

- **Authorization gate first.** `REDSEE_AUTHORIZED=true` and an explicit `REDSEE_ALLOWED_HOSTS` allow-list are required before any active test; refused targets are never touched.
- **Scope-checked per action.** Every URL is checked against the allow-list immediately before it reaches a sandbox — not just once at scan start.
- **Sandboxed, never the host.** All tool execution goes through `run_in_sandbox`: a throwaway, non-root container with `--cap-drop=ALL`, `--security-opt=no-new-privileges`, a read-only rootfs, resource caps (256 MB / 1 CPU / 128 PIDs), and **never** `--privileged` or `NET_ADMIN`.
- **Default-deny egress.** A dedicated bridge network + host-managed iptables rules allow the container to reach *only* the single `ip:port` it's authorized to test — no DNS, no other host, no public internet, no SSH.
- **Fail-closed isolation self-test.** Before any tool output is trusted, the sandbox proves from the inside that the target is reachable and everything else isn't. If that can't be confirmed, the run aborts with no output — a dead target can never masquerade as "clean."
- **Evidence-only verdicts.** `injectable`/`found` comes solely from parsed positive tool output — sqlmap's confirmed-injection text, Dalfox's `[POC]`/`[V]` lines, nuclei's JSONL results, ffuf's hit lines. The model's own claims are never trusted, and a seeded *candidate* parameter only becomes a finding if the tool itself confirms it.
- **Detection-only, permanently.** Exploitation/enumeration flags (`--os-shell`, `--dump`, `--users`, `--current-db`, ...) are hard-banned in the argv builder regardless of what the model asks for; nuclei's OOB/interactsh callbacks and intrusive/fuzz/brute template tags are excluded unconditionally.
- **Hard spend cap.** One budget tracker per scan; a per-scan USD ceiling is checked *before* every LLM call, so a runaway loop can't overspend regardless of provider.
- **No secrets in output.** Any LLM metadata (API keys, tokens) is scrubbed before touching any artifact on disk.
- **Bounded, not unbounded.** Concurrency, injection-target counts, discovery re-crawls, and seeded parameters are all mode-aware capped — including a hard, mode-independent ceiling on total sandboxed injection runs per scan.

---

## Scan modes

| Mode | Wall-clock | Breadth | Depth | Recon |
|---|---|---|---|---|
| **fast** | ~2 min | Top 5 crawled param-bearing endpoints only | Shallow (level/risk 1) | httpx + tlsx only |
| **standard** | ~5–8 min | Discovery (4 re-crawled paths) + seeding (1 API path, the full lean param list) | Medium | + scoped nuclei + ffuf |
| **deep** | full | Every param-bearing endpoint + wider discovery/seeding | Agent-default (full ladder) | Everything, nuclei's full default profile |

Every mode's effective caps are recorded in the scan's `caps` block, and the discovery→injection loop's own counters (`paths_discovered`, `paths_recrawled`, `params_seeded`, `injection_targets_tested`) are recorded under `discovery` — so exactly how a scan was tuned is always visible, never implicit.

---

## Project layout

```
RedSee/
├── schemas.py                  # Frozen dataclass contract (Endpoint/Finding/Event/Sitemap)
├── crawler.py                  # BFS crawler → Sitemap (incl. JS-embedded API path detection)
├── app.py                      # Flask console: /api/scans spine + legacy routes + blue-team routes
├── log_ingestor.py             # Wazuh/Splunk parsing + live Wazuh API fetch
├── red_report.py               # Red Team report: LLM-authored PDF, or deterministic PDF/HTML fallback
├── blue_report.py              # Blue Team report: same dual path as red_report.py
├── integration.py              # Legacy pipeline orchestrator (static 4-scanner path)
├── scanner.py                  # Standalone legacy SQLi+XSS CLI scanner
│
├── engine/                     # The sandboxed, LLM-driven agent engine
│   ├── scope.py                #   Layer 1 — authorization/scope gate
│   ├── sandbox.py               #   Layer 2 — isolated Docker execution (frozen API)
│   ├── llm.py                  #   Layer 3 — BYOK LLM client + budget tracker
│   ├── agent.py                #   Layer 4 — SQLi agent (drives sqlmap)
│   ├── xss_agent.py            #   Layer 4 — XSS agent (drives Dalfox)
│   ├── nuclei_agent.py         #   Layer 4 — template-scan agent (drives nuclei)
│   ├── recon_tools.py          #   Deterministic httpx/tlsx/ffuf runners (no model)
│   ├── params.py               #   Injectable-param extraction + common-parameter seeding
│   ├── finding_map.py          #   Candidate → schema-valid Finding (confirmed-only)
│   └── report_io.py            #   findings/SARIF/run.json audit-trail writer + secret scrub
│
├── modules/
│   ├── scan.py                 # THE unified discovery→injection scan orchestrator
│   ├── recon.py                # Standalone nuclei+httpx+tlsx+ffuf runner
│   ├── sqli.py / xss.py        # Agent-backed-first, legacy-direct-HTTP-fallback wrappers
│   └── idor.py / auth.py       # Legacy static modules (not yet agent-converted)
│
├── storage/
│   └── scan_store.py           # SQLite-backed scan queue + status lifecycle + history
│
├── templates/index.html        # Dark SOC console (Red Ops / Blue Ops)
├── static/{style.css,script.js}# Console theme + frontend logic
│
├── docker/
│   ├── demo-helper.sh          # Launches DVWA / Juice Shop / the themed marketplace demo
│   └── sandbox/                # Dockerfile (sqlmap/Dalfox/nuclei/httpx/tlsx/ffuf, pinned+
│                                #   sha256-verified) + bundled wordlists (common.txt, params.txt)
│
├── demo-target/                # Themed "RedSees Marketplace" demo target
│   ├── redsees-themepack/      #   Juice Shop reskin (frontend, images, fonts)
│   ├── gateway/                #   Node reverse-proxy unifying Juice Shop + sinks on one port
│   └── marketplace_sinks.py    #   Companion Flask app with reflected-XSS/SQLi sinks
│
├── scripts/
│   └── scan_root_verify.py     # Live scan verification/diagnostic script
│
├── utils/http_helpers.py       # HTTPSession (auth, cookies, rate limiting)
├── prompts/                    # LLM system prompts (per agent)
├── pdf_templates/              # red.css / blue.css (shared by LLM + deterministic paths)
├── sample_data/                # Demo + fallback JSON fixtures
├── tests/                      # 30 test files — pytest-discoverable, most fully offline
│
├── DECISIONS.md                # Architecture decision record (D-001 → D-026)
├── PROGRESS.md                 # Roadmap + dated session log
├── HANDOFF.md                  # Live session state snapshot
├── AGENTS.md                   # Frozen-contract + invariants reference
│
└── outputs/                    # scan_<id>.json, findings/.sarif, reports (gitignored)
```

---

## Installation

### Prerequisites

- **Python 3.10+**
- **Docker** (native Docker Engine — required for the sandbox's iptables-based egress isolation; Docker Desktop's split-VM architecture on Windows/Mac does **not** work for this, since it runs containers in a separate network namespace from the host running the Python process. On Windows, use **WSL2 with a native Docker Engine installed inside the distro**, not Docker Desktop's WSL2 integration.)
- **Root** on whichever host runs the scan (the sandbox layer manages `iptables` rules directly)

### Steps

```bash
git clone <this-repo>
cd RedSee-ITSkillsFinalProject

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt        # if weasyprint fails to install, skip it —
                                        # the deterministic report path doesn't need it

cp .env.example .env
# edit .env — see Configuration below

bash docker/sandbox/build.sh           # builds the pinned sqlmap/Dalfox/nuclei/httpx/tlsx/ffuf image
```

---

## Configuration

All runtime config comes from `.env` (copy from `.env.example`).

**Agent engine (required for active scanning):**

| Key | Purpose |
|---|---|
| `REDSEE_AUTHORIZED` | Must be `"true"` before any active test runs |
| `REDSEE_ALLOWED_HOSTS` | Comma-separated exact hostnames — default-deny scope allow-list |
| `REDSEE_TARGET_URL` | Default target for CLI entry points |
| `REDSEE_RATE_LIMIT` | Max requests/min against in-scope hosts |
| `REDSEE_LLM_BASE_URL` / `REDSEE_LLM_MODEL` / `REDSEE_LLM_API_KEY` | Any OpenAI-compatible endpoint — a local Ollama, OpenRouter, etc. |
| `REDSEE_LLM_MAX_USD` | Hard per-scan spend cap — checked before every LLM call |
| `REDSEE_MAX_PARALLEL_SANDBOXES` | How many sandboxed stages run concurrently (default 2) |

**Dashboard:**

| Key | Purpose |
|---|---|
| `REDSEE_DASH_USER` / `REDSEE_DASH_PASS` | HTTP basic auth for the console (unset password = auth disabled, for local dev) |

**Blue team / legacy pipeline:**

| Key | Purpose |
|---|---|
| `WAZUH_API_URL` / `WAZUH_API_USER` / `WAZUH_API_PASS` | Live Wazuh SIEM API |
| `LLM_PROVIDER` / `OPENROUTER_API_KEY` / `TARGET_AUTH_USER` / ... | Legacy pipeline + LLM-authored report path |

See `.env.example` for the complete, commented list.

---

## Quick start

```bash
# 1. Bring up a demo target (themed marketplace, or plain DVWA/Juice Shop)
bash docker/demo-helper.sh marketplace

# 2. Start the console
python app.py
# → http://localhost (or wherever deployed)

# 3. In the dashboard: enter the target URL, pick a mode (fast/standard/deep),
#    confirm authorization, launch. Watch it move queued → running → done.

# 4. Drill into the result: tools_run status (with legible skip/error reasons),
#    confirmed findings, recon observations, discovery/seeding transparency.

# 5. Export a Red Report (PDF if weasyprint+LLM configured, HTML fallback otherwise).
```

Or drive a scan directly, without the dashboard:

```python
from engine.scope import ScopeConfig
from modules.scan import run_scan

scope = ScopeConfig(target_url="http://target:3000/", allowed_hosts=["target"], authorized=True)
record = run_scan("http://target:3000/", scope_config=scope, mode="standard")
print(record["summary"])
```

---

## Dashboard / API routes

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/` | Console UI |
| `POST` | `/api/scans` | Queue a scan — `{"target_url", "authorized", "mode"}` |
| `GET` | `/api/scans` | List scan history (newest first) |
| `GET` | `/api/scans/<id>` | Full scan record (status + `scan_<id>.json` once done) |
| `POST` | `/scan/<id>/report` | Generate the Red report (PDF or HTML) |
| `POST` | `/analyze-logs` | Parse a Wazuh/Splunk log file |
| `POST` | `/fetch-wazuh-alerts` | Fetch live alerts from the Wazuh API |
| `POST` | `/generate-blue-report` | Generate the Blue report from ingested events |
| `GET` | `/downloads/<filename>` | Download a generated report |

The legacy `/scan`, `/scan/<id>/status`, `/scan/<id>/findings` routes (backed by `integration.py`'s static pipeline) still exist for the original 4-scanner flow, gated behind graceful degradation if that pipeline's dependencies aren't installed.

---

## Blue team / SIEM ingestion

`log_ingestor.py` normalizes Wazuh alerts or Splunk exports (JSON or CSV) into a common `Event` shape, live or from a file:

```bash
python log_ingestor.py sample_data/sample_wazuh_alerts.json
```

or via the dashboard's Blue Ops tab: upload a log file or fetch live Wazuh alerts, triage by severity, and export an incident report — `blue_report.py` builds it either via an LLM (attack timeline, missed-detection analysis, ready-to-paste Wazuh/Splunk rules) or the same deterministic fallback pattern as the Red report, so it never dead-ends on a missing API key.

---

## Reports

Both report generators follow the same pattern:

1. **LLM-authored** (`generate_red_report` / `generate_blue_report`) — a real LLM call produces polished, narrative prose (executive summary, CVSS-style scoring, remediation guidance), rendered to PDF via `weasyprint`.
2. **Deterministic fallback** (`generate_deterministic_report` / `generate_deterministic_blue_report`) — the *same* report structure built directly from the scan/event data via string templates — no LLM call, no `weasyprint` system-library dependency. Renders PDF if `weasyprint` happens to be importable, otherwise a self-contained HTML file.

The dashboard's report buttons always use the deterministic path by default, so a report is always produced — a 0-finding scan still gets a real "no vulnerabilities confirmed" report, not an error.

---

## Demo target

`demo-target/` ships a themed "RedSees Marketplace" — a reskinned OWASP Juice Shop plus a companion Flask service with deliberately planted reflected-XSS/SQLi sinks, unified behind a small Node gateway on one port. `docker/demo-helper.sh marketplace` builds and starts it. Ground-truth vulnerabilities are documented in `docs/redsees_marketplace_vulns.txt` for verifying scan results against a known-answer target.

---

## Testing

Most tests are fully offline (mocked sandbox/LLM/network) and pytest-discoverable:

```bash
PYTHONPATH=. python -m pytest tests/ -v
```

A handful of legacy tests (`test_sqli.py`, `test_xss.py` DVWA-live variants) require a reachable `TARGET_URL` and fail gracefully (connection-refused, not a crash) when no live target is configured — expected in an offline dev environment, not a regression.

---

## Known limitations

- `modules/idor.py` and `modules/auth.py` are still the original static, non-agentic scanners — not yet converted to the sandboxed agent pattern.
- The legacy `/scan` pipeline (`integration.py`) and the new `/api/scans` spine (`modules/scan.py` + `storage/scan_store.py`) coexist; the legacy path is kept only for backward compatibility with the original static 4-scanner flow.
- Sandbox isolation requires a native Docker Engine + root — Docker Desktop's split-VM architecture (common on Windows/Mac) does not satisfy the host-level iptables assumption the sandbox layer relies on.
- No automatic cleanup yet for sandbox-network/iptables state left behind by a killed (not gracefully stopped) scan process — see `HANDOFF.md` for the manual inspect/clean procedure.

Full architecture rationale: [`DECISIONS.md`](DECISIONS.md). Current session state: [`HANDOFF.md`](HANDOFF.md). Roadmap: [`PROGRESS.md`](PROGRESS.md).

---

## Tech stack

- **Python 3.10+** — `requests`, `beautifulsoup4`, `lxml` (crawling); `flask`, `flask-cors` (dashboard); `markdown` + optional `weasyprint` (reports); `openai>=1.6.0` (OpenAI-compatible LLM client, works with OpenRouter/DeepSeek/Ollama); `python-dotenv`
- **Docker** — sandboxed tool execution: sqlmap, Dalfox v2.13.0, nuclei v3.11.0 (+ templates v10.4.5), httpx v1.9.0, tlsx v1.2.2, ffuf v2.1.0 — every binary pinned to an exact release and sha256-verified at build time
- **SQLite** (stdlib) — persistent scan store
- **gunicorn + systemd** — production deployment

---

## License

See `LICENSE` in the repository root.
