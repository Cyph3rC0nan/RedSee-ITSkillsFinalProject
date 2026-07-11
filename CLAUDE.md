## Session Handoff Protocol (always follow)

You maintain a living file `HANDOFF.md` at the repo root that lets any new
session resume this work without re-explanation.

**At the START of every session:**
1. Read `HANDOFF.md` (if it doesn't exist yet, create it using the template below).
2. Briefly tell me where we left off and what the next step is.

**At the END of every task (i.e. once you've finished what I asked and any
tests/checks are done), update `HANDOFF.md` BEFORE you finish your reply:**
- Set "Last updated" to the current date/time.
- Move the just-completed item into "Recently completed" (keep only the last 5).
- Update "Current milestone", "Next step", and "Open issues / blockers".
- Record any new decision + one-line rationale under "Key decisions".
- Note any file you created/changed under "Changed files (this session)".

**Rules for HANDOFF.md:**
- Keep it under ~150 lines. It's a state snapshot, not a changelog — trim old detail.
- Never restate the frozen contract from AGENTS.md; link to it instead.
- Always preserve these invariants in your notes so they survive a fresh session:
  the `schemas.py` dataclasses must not break; severity strings are exactly
  Critical/High/Medium/Low; all active testing stays inside the sandbox and
  within the declared scope allow-list; authorization gating runs before any
  active scan.
- If you did NOT finish a task, say so explicitly under "In progress" with the
  exact next action, so the next session can pick it up mid-stream.

**HANDOFF.md template (create it if missing):**
---
# RedSee — Session Handoff

**Last updated:** <ISO 8601 timestamp>
**Current milestone:** <e.g. SQLi static stub → agent-driven vertical slice>

## Next step
<the single most immediate action>

## In progress
<anything half-done + the exact next action; or "nothing">

## Recently completed (last 5)
- <item> — <date>

## Key decisions
- <decision> — <one-line why>

## Open issues / blockers
- <issue> — <status>

## Changed files (this session)
- <path> — <what changed>

## Invariants to preserve
- schemas.py contract frozen · severity strings exact · sandbox + scope gating · auth gating first
- See AGENTS.md for the full contract.
---
