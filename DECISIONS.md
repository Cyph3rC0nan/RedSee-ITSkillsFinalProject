# RedSee — Decisions

Lightweight architecture decision record (ADR) for RedSee's agentic-transformation
work. Answers "why we chose this." For "what is true now" see
[`AGENTS.md`](AGENTS.md); for "what we're doing next" see
[`PROGRESS.md`](PROGRESS.md); for a session's live working detail see
[`HANDOFF.md`](HANDOFF.md).

**Supersede, don't delete** — if a decision changes, add a new entry that
references the old one and flip the old one's Status to `Superseded by D-0XX`.

---

### D-001: Interface = operator dashboard

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Operators queue targets, watch scans run, and browse/search past
scan history & findings through a dashboard. Scans run autonomously in the
background, not by a human driving a terminal.
**Why:** The operator's job is to authorize and review, not to babysit a live
scan session — background execution with a queryable history matches how a
pentest engagement is actually run and reported on.
**Alternatives / trade-off:** A CLI-only tool would be simpler to build first but
would not support "queue and check back later" or historical findings search,
which the product needs from day one.

---

### D-002: Runtime engine = autonomous agent backend service

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** The engine is an autonomous agent backend service with a
provider-agnostic BYOK ("bring your own key") LLM layer. Agent loop: plan → call
a RedSee tool (run tool in sandbox / fetch URL) → observe → decide → repeat.
**Why:** A fixed, hard-coded payload list (the original `modules/*.py` scanners)
can't adapt probe values, escalate detection depth, or reason about ambiguous
results the way an LLM-driven loop can — see `engine/agent.py`'s ladder
escalation + deterministic completion pass for the concrete payoff.
**Alternatives / trade-off:** Keep the static scanners as the only detection
path — simpler and already working, but caps detection quality at whatever was
hand-coded and can't generalize to new tools/vuln classes without new code for
every payload variant.

---

### D-003: LLM backend is pluggable, not vendor-locked

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** RedSee accepts an OpenAI-compatible endpoint + model + key.
Preference order, best-first: (a) Anthropic API key via Claude Agent SDK
(highest-quality reasoning); (b) any other paid OpenAI-compatible provider;
(c) free/local open model via Ollama (zero cost, offline). No free Anthropic API
access exists.
**Why:** A single hard-coded provider would block anyone without that exact
vendor's paid key from running RedSee at all; an OpenAI-compatible interface is
the lowest-common-denominator contract nearly every provider (including local
Ollama) already speaks.
**Alternatives / trade-off:** Anthropic-only would give the best reasoning
quality out of the box but makes the tool unusable for anyone without an
Anthropic key and unusable offline/free — unacceptable for a demo/lab tool.

---

### D-004: Credential split

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Development uses Claude Code on the team's Pro/Max subscription (no
API key, no extra cost). Production is BYOK — each operator supplies their own
endpoint + key. RedSee itself owns no key.
**Why:** Keeps the team's own dev workflow free while ensuring RedSee never
becomes a shared-cost or shared-liability API key holder for production users.
**Alternatives / trade-off:** RedSee could ship with a built-in shared key, but
that centralizes cost and abuse risk on the project maintainers — rejected.

---

### D-005: Per-scan token/cost budget cap is mandatory

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Every agent run enforces a hard per-scan token/cost budget cap,
regardless of LLM provider.
**Why:** An autonomous plan/act/observe loop with no cap can run away (cost or
time) on a misbehaving model or an unexpectedly large target; a mandatory cap
bounds the worst case for every provider, including "free" local models where
cost is really wall-clock/compute time.
**Alternatives / trade-off:** Rely on max_iterations alone — rejected, since
iteration count doesn't bound $ cost when different providers/models have very
different per-call pricing. Implemented today as `engine/llm.py`'s
`BudgetTracker` (`REDSEE_LLM_MAX_USD`), checked before every LLM call.

---

### D-006: MCP is a secondary control surface, built after the engine works

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Not MCP-first. RedSee's own agent engine + dashboard ships first;
an MCP server (so Claude Code can trigger scans / read findings) comes later.
**Why:** MCP is a control-surface convenience layer on top of a working engine —
building it first would mean designing an interface for a capability set that
doesn't exist yet.
**Alternatives / trade-off:** MCP-first would let Claude Code drive scans
earlier, but risks locking in an interface before the underlying agent loop
(tool set, Finding shape, budget semantics) has stabilized through real use.

---

### D-007: First implementation milestone = SQLi vertical slice

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Replace the one static SQLi stub module with an agent-driven
version that proves engine + sandbox + scope-gating + Finding output end to end,
then generalize to xss/idor/auth.
**Why:** SQLi already had sqlmap as a mature, drivable open-source tool (see
D-012) and an existing static scanner to fall back to — the smallest surface
area to prove the full engine stack (scope → sandbox → LLM → agent →
finding-map → SARIF/run.json) before repeating the pattern.
**Alternatives / trade-off:** Build all four vuln-class agents in parallel —
rejected as higher risk of compounding design mistakes across all four before
any one was validated end-to-end.
**Status update:** the SQLi slice is done (`engine/agent.py`), and the pattern
has since been generalized once, to XSS (`engine/xss_agent.py`, driving Dalfox)
— see `PROGRESS.md`'s roadmap and `HANDOFF.md` for current detail. idor/auth are
not yet started.

---

### D-008: Authorization gating is a product feature, not a disclaimer

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** The operator must confirm authorized scope (explicit target
allow-list + ownership/permission attestation) before any active testing runs.
No scope → recon-only or refuse.
**Why:** RedSee performs active testing against real targets; a checkbox in a
README is not a control — the software itself must refuse to act without an
explicit, structured authorization.
**Alternatives / trade-off:** A ToS/disclaimer-only approach was rejected as
insufficient — it does not prevent misuse, only disclaims liability for it.
Implemented as `engine/scope.py`'s `require_authorization` (`REDSEE_AUTHORIZED`
must be `"true"`), checked before every sandboxed tool run.

---

### D-009: Runtime scope enforcement

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** The agent stays within the declared host allow-list; out-of-scope
hosts are never touched. Rate limits and a global kill switch are mandatory.
**Why:** An LLM-driven agent can propose a URL outside the intended target
(hallucination, prompt injection from scanned content, or simple mistake) — the
harness, not the model, must be the enforcement point.
**Alternatives / trade-off:** Trust the model's own judgment about scope via
prompt instructions alone — rejected, since a prompt is not an enforcement
mechanism. Implemented as `engine/scope.py`'s `assert_in_scope`, called before
every tool execution regardless of what the model requested.

---

### D-010: Sandbox everything

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** All active testing runs inside an isolated, network-restricted
container that cannot reach the operator's other systems. Agent-driven tools are
never run on the host.
**Why:** Tools like sqlmap/Dalfox execute arbitrary requests an LLM chose; the
blast radius of a mistake or an adversarial target must be contained to a
throwaway container, not the operator's real network.
**Alternatives / trade-off:** Run tools directly on the host with just an
allow-list check — rejected, since a scope-check bug or bypass would then have
full host network access. Implemented as `engine/sandbox.py`: default-deny
egress firewall, non-root, `--cap-drop=ALL`, read-only rootfs, and a fail-closed
isolation self-test that must pass before every scan.

---

### D-011: Human-in-the-loop for destructive actions

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Anything beyond read/observe (data dumping, shells, exploitation)
requires explicit operator approval or is disabled by default.
**Why:** Detection (proving a vulnerability exists) and exploitation (acting on
it) carry very different risk profiles — RedSee's default posture is
detection-only so an autonomous loop can't escalate into real damage or data
exposure on its own.
**Alternatives / trade-off:** Full auto-exploitation for "complete" proof of
impact — rejected as the default; too risky for an autonomous, LLM-driven
decision-maker. Implemented as detection-only tool profiles (e.g.
`engine/agent.py`'s `_FORBIDDEN_LITERAL` bans sqlmap's `--dump`/`--os-shell`/etc;
`engine/xss_agent.py`'s bans Dalfox's `--blind`/`--exploit`) — the harness
refuses the flag outright rather than asking approval mid-run, since no
approval flow exists yet.

---

### D-012: Drive established open-source tools inside the sandbox

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** The agent drives established tools (sqlmap, Dalfox, and — later —
tools like nuclei/httpx/katana) rather than hand-writing novel offensive
payloads. No malware or self-propagating code, ever.
**Why:** Mature tools have years of detection-technique refinement and edge-case
handling; the agent's value-add is choosing targets/parameters/depth and
interpreting results, not reinventing payload generation.
**Alternatives / trade-off:** Have the LLM generate payloads directly —
rejected: higher risk of unreliable/unsafe output and duplicated effort versus
tools that already do this well. Currently implemented: sqlmap (SQLi, v1.9.6)
and Dalfox v2.13.0 (reflected XSS), both installed in `docker/sandbox/`.

---

### D-013: Responsible reporting

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Findings are evidence-backed (never fabricated), include
remediation guidance, and support responsible-disclosure workflows.
**Why:** A false-positive or unsubstantiated finding damages trust in the whole
tool and wastes a defender's time; a finding with no fix guidance is only half
useful.
**Alternatives / trade-off:** Let the LLM assert a finding based on its own
judgment — rejected. Implemented as the evidence-gated status contract:
`injectable`/confirmed is derived SOLELY from parsed tool positive output
(sqlmap's verdict, Dalfox's `[POC]`/`[V]` lines), never from the model; see
`engine/finding_map.py`'s `candidate_to_finding`/`xss_candidate_to_finding`,
which raise rather than fabricate a Finding for any non-confirmed candidate, and
always attach remediation text.

---

### D-014: Preserve the `schemas.py` contract and existing PDF reports

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** Add Markdown + SARIF (machine-readable findings format) +
`run.json` outputs alongside, not instead of, the current PDF report path.
`schemas.py`'s `Finding`/`Endpoint`/`Event`/`Sitemap`/`ScanResult` contract is
frozen.
**Why:** The PDF pipeline (`red_report.py`/`blue_report.py`) and the
`schemas.py` contract are load-bearing for the rest of the team's work
(dashboard, integration orchestration) — breaking either would block everyone
else mid-stream for a benefit (structured output) that can be additive instead.
**Alternatives / trade-off:** Redesign `schemas.py`/the report path around the
new agent engine's needs — rejected; the frozen contract (see `AGENTS.md`) is a
team-wide agreement, not this workstream's to change unilaterally. Implemented:
`engine/report_io.py`'s `write_outputs` emits `findings_<id>.json` (same shape
`integration.py`/`red_report.py` already read), `findings_<id>.sarif`, and
`run_<id>.json`, all additive to the existing PDF path.
