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
tools that already do this well. Currently implemented: sqlmap (SQLi, v1.9.6),
Dalfox v2.13.0 (reflected XSS), and nuclei v3.11.0 + nuclei-templates v10.4.5
(template-based CVE/misconfig/exposure detection — `engine/nuclei_agent.py`), all
installed in `docker/sandbox/`. Tool versions are pinned + sha256-verified, never
`@latest`, and never auto-updated at build or scan time (see D-016).

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

---

### D-015: nuclei's config/cache dir lives under `/tmp`, not a read-only image path

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** In the sandbox image, nuclei's `XDG_CONFIG_HOME`/`XDG_CACHE_HOME`
point at `/tmp/.config` / `/tmp/.cache` (pre-populated at build time), NOT a
baked read-only path like `/opt/nuclei-config`.
**Why:** Unlike sqlmap/Dalfox, nuclei resolves its config/cache via
`$XDG_CONFIG_HOME`/`$XDG_CACHE_HOME` (Go's `os.UserConfigDir`/`UserCacheDir`), not
`$HOME`. A *real* scan WRITES `config.yaml` / `reporting-config.yaml` / the
template cache at startup and dies with `FTL … could not create config file` if
that dir is on the `--read-only` rootfs. `engine/sandbox.py` (frozen, D-010)
exposes exactly one writable path: `--tmpfs /tmp` with `HOME=/tmp`. Putting XDG
under `/tmp` means the baked files satisfy read-only `-tv`/`-version` self-checks
(no tmpfs mounted), while the sandbox's tmpfs *overlays* them with a writable dir
for real scans. The scan always passes `-t /opt/nuclei-templates` explicitly, so
template resolution never depends on the config nuclei regenerates on the tmpfs.
**Alternatives / trade-off:** Keep the earlier read-only `/opt` bake (which passed
Prompt 1's `-tv`/`-version` checks) — rejected: it silently breaks every real
scan on the read-only rootfs. Modify `engine/sandbox.py` to add a writable mount —
rejected: the sandbox contract is frozen (D-010). Full details in
`docs/nuclei_sandbox.md`.

---

### D-016: nuclei runs a fixed, harness-owned, detection-only profile

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** The model chooses only a target, optional focus tags (from a safe
allowlist), and a note — never nuclei flags. The harness fixes the profile:
`-jsonl -omit-raw -disable-update-check -no-interactsh`, the bundled templates
(`-t /opt/nuclei-templates`), a severity floor that excludes info-only noise
(`-severity low,medium,high,critical`), and `-exclude-tags dos,intrusive,fuzz,
brute,oob`. Auto-update (`-up`/`-ut`), interactsh/OAST out-of-band callbacks,
code-protocol/headless execution, and cloud upload are hard-banned; an auth cookie
is attached harness-side as the only permitted `-H "Cookie: …"`.
**Why:** Extends D-011 (detection-only) and D-012 (drive tools, not payloads) to
nuclei's much larger surface. nuclei can send OOB callbacks, run intrusive/DoS
templates, and phone home for updates — an LLM must not be able to enable any of
those. `status="found"` derives SOLELY from parsed `-jsonl` result lines (D-013),
never the model. Info-severity templates are excluded by default as noise, not
findings.
**Alternatives / trade-off:** Let the model pass nuclei flags/severities/OOB
options for flexibility — rejected: the harness, not the model, is the safety
enforcement point (D-009). Tags smuggling a flag or a dangerous category raise
rather than silently run. Implemented in `engine/nuclei_agent.py`
(`_FORBIDDEN_LITERAL`, `_sanitize_tags`, `_validate_target`, `_assert_note_safe`,
`_assert_no_forbidden_flags`); no OOB/exploit config was added, matching the task's
detection-only mandate.

---

### D-017: nuclei results are surfaced into SARIF/JSON/run.json, NOT typed Findings

**Status:** Accepted
**Date:** 2026-07-12
**Decision:** nuclei's findings (CVEs, misconfigurations, exposures) are broader
than the frozen `schemas.py` Finding enum (SQLi/XSS/IDOR/BrokenAuth), so they do
NOT become typed `Finding` objects and NEVER enter `findings_<id>.json`. Instead a
list of `NucleiCandidate(status="found")` is surfaced ADDITIVELY into the SARIF
report (ruleId = nuclei `template_id`), a dedicated `nuclei_<id>.json` (the raw
candidate list), and a `nuclei` summary block in `run_<id>.json`.
`engine.report_io.write_outputs` gained an optional `nuclei_candidates=None` param;
when omitted, every existing output is byte-for-byte unchanged. `schemas.py` is
NOT modified, and nuclei is NOT wired into `integration.py`'s resolver /
`scan_sqli` / `scan_xss` — the standalone `modules/recon.py` (`run_recon_scan`)
chains the agent into `write_outputs` separately.
**Why:** Forcing nuclei's open-ended template catalogue into four fixed Finding
types would mean either mis-typing results or expanding the frozen contract
(D-014) that the rest of the team's pipeline (dashboard, red_report) depends on.
SARIF's `ruleId` is already free-form, so it carries the real template id losslessly
and machine-readably without touching `schemas.py`. Keeping nuclei out of the
typed-Finding pipeline also preserves the "a Finding is a CONFIRMED typed vuln"
contract (AGENTS.md) — a nuclei match is evidence of an exposure, surfaced as such,
not silently relabelled as SQLi/XSS/IDOR/BrokenAuth.
**Alternatives / trade-off:** (a) Add a `Recon`/`Misconfig` value to the Finding
enum — rejected: `schemas.py` is frozen (D-014, AGENTS.md). (b) Map every nuclei
result onto the closest existing Finding type — rejected: lossy and misleading.
(c) Put nuclei rows in `findings_<id>.json` with a synthetic type — rejected: it
would corrupt the typed shape `integration.py`/`red_report.py` consume. Implemented
in `engine/report_io.py` (`nuclei_candidates` param, getattr duck-typing so
report_io stays decoupled from `engine.nuclei_agent`) + `modules/recon.py`; covered
by `tests/test_report_io.py`.
**Extended 2026-07-13:** the same reasoning and the same mechanism now also cover
`engine.recon_tools`'s httpx/tlsx `ReconObservation`s, via a second, independent,
equally-optional `recon_observations` param on `write_outputs` (see D-019) — proving
the D-017 pattern generalizes to a second, unrelated tool family without touching
`schemas.py` or the nuclei channel.

---

### D-018: httpx/tlsx recon is deterministic — no LLM, no agent loop, no budget

**Status:** Accepted
**Date:** 2026-07-13
**Decision:** `engine/recon_tools.py`'s `run_httpx`/`run_tlsx` reuse the SHAPE of
`engine/nuclei_agent.py` (scope-gate every target first, sandbox-only via
`run_in_sandbox`, evidence-gated JSON parsing) but deliberately have NO LLM client,
NO plan/act/observe loop, and NO `BudgetTracker`. Each call is ONE fixed,
harness-built command per target, run deterministically.
**Why:** httpx/tlsx fingerprinting and TLS inspection are single-shot, single-target
probes with no meaningful escalation ladder or parameter choice for a model to
reason about (unlike sqlmap's depth/technique ladder or nuclei's template-tag
selection) — an LLM in this loop would add latency and cost for zero decision
value. Since there is no model in the loop, there is also nothing to
sanitize/refuse from a caller; the argv is entirely harness-built, and
`_assert_no_forbidden_flags` is a pure regression backstop, not a security
boundary against adversarial input (contrast with nuclei_agent's `_sanitize_tags`,
which DOES guard against model-supplied values).
**Alternatives / trade-off:** Wrap httpx/tlsx in the same agent-loop shape as
nuclei "for consistency" — rejected: would add an LLM dependency (cost, latency,
a `REDSEE_LLM_*` requirement) to two tools that have no use for one, and would
falsely suggest there's something for a model to decide here. `ReconObservation`
deliberately has no "clean" status (unlike `NucleiCandidate`'s
found/clean/error/out_of_scope) — a successful probe with nothing to report simply
yields no observation for that target, since there is no completion-pass/ladder
concept to report "clean" against.

---

### D-019: httpx is pinned to v1.9.0, not the newer v1.10.0

**Status:** Accepted
**Date:** 2026-07-13
**Decision:** The sandbox image pins `projectdiscovery/httpx` to v1.9.0, not the
release that was current when httpx was first added to the image (v1.10.0).
**Why:** v1.10.0 makes an **unconditional network call on every single run** —
confirmed with a minimal flag set (`-status-code` alone), and NOT gated by
`-disable-update-check` — downloading a ~92MB ML "page type" classifier model from
`huggingface.co/datasets/happyhackingspace/dit`. In the real hardened sandbox
(egress locked to the single target IP:port, D-010), that request is DROPped by
the firewall, so every recon scan would first stall on a doomed connection to an
unrelated host before ever probing the target — a reliability and "no phone home"
violation. v1.9.0 was independently downloaded, sha256-verified, and confirmed
clean (no such call; its JSON `knowledgebase` object has no `PageType` key) against
the exact flag set `engine/recon_tools.py` uses.
**Alternatives / trade-off:** Keep v1.10.0 and try to find a flag/env var to
disable the model download — rejected: no such flag exists in httpx's `-h` output
for this behavior, so there is no known way to suppress it in v1.10.0. This is the
same "pin to avoid a problematic behavior" pattern as D-012's Dalfox v2.13.0 pin
(avoiding the v3.x CLI rewrite) — pin to the last version WITHOUT the issue rather
than working around it. Full detail in `docs/nuclei_sandbox.md`.
