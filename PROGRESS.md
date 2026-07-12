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
| nuclei template-scan agent (CVEs / misconfig / exposures) | Done offline (engine + sandbox + SARIF/JSON/run.json output via report_io + standalone modules/recon.py); only a live end-to-end run is pending, blocked by env — see HANDOFF |
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
