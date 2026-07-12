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
