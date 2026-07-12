# RedSee — Session Handoff

**Last updated:** 2026-07-12T13:30:00Z
**Current milestone:** nuclei candidates surfaced into SARIF + nuclei_<id>.json + run.json (NOT typed Findings) via engine/report_io.py; standalone modules/recon.py entry. Branch `feat/nuclei`.

## Next step
The nuclei track is functionally complete end-to-end EXCEPT a live run (blocked by the
host-local sandbox networking cruft — see blockers). Options next: (a) get a green live
`modules.recon` run once the orphaned iptables/network state is cleaned; (b) a live
`scan_xss()` smoke through modules.xss (long-outstanding); (c) idor/auth agents. Note the
settled decision (D-017): nuclei results are BROADER than the frozen Finding enum and
DELIBERATELY never become typed Findings / never enter findings_<id>.json — do NOT
"finish" that mapping.

## In progress
nothing

## Recently completed (last 5)
- Surfaced nuclei candidates into the output layer WITHOUT touching schemas.py or
  findings_<id>.json (settled decision D-017). engine/report_io.py: write_outputs gained
  an optional `nuclei_candidates=None` param — found ones append to the SARIF report
  (ruleId=template_id, level from nuclei severity: critical/high->error, medium->warning,
  low/info->note; rules[] for distinct template_ids), the full raw list writes to
  nuclei_<id>.json, and a nuclei summary block (found/clean/error + by-severity) is added
  to run_<id>.json. findings_<id>.json stays typed-Finding-only. report_io duck-types the
  candidates via getattr (no import of engine.nuclei_agent); _endpoint_status_summary now
  falls back endpoint_url->target so a NucleiAgentResult can be the agent_result. When
  nuclei_candidates is omitted, output is BYTE-FOR-BYTE identical to before (proven by
  diffing against HEAD's report_io). New modules/recon.py (run_recon_scan) chains
  run_nuclei_agent -> write_outputs(nuclei_candidates=...); NOT wired into integration.py.
  tests/test_report_io.py (11 tests, real captured JSONL); 43 pass w/ test_nuclei_agent;
  regression 42 passed/1 skipped; `git diff --stat schemas.py` empty — 2026-07-12
- Built engine/nuclei_agent.py — template-scan agent parallel to SQLi/XSS, driving
  nuclei. run_nuclei_agent -> NucleiAgentResult; NucleiCandidate/NucleiAgentResult local.
  ONE harness-owned run_nuclei tool (model gives target/tags-allowlist/note, never flags);
  fixed detection-only profile (-jsonl/-omit-raw/-disable-update-check/-no-interactsh,
  bundled templates, info-severity floor, exclude dos/intrusive/fuzz/brute/oob).
  status="found" from parsed JSONL only; sandbox/timeout/non-zero -> "error". Smuggling
  raises. 34 offline tests vs REAL captured DVWA JSONL; grep proves run_in_sandbox-only.
  Committed f4cf76b — 2026-07-12
- Dockerfile: installed pinned nuclei v3.11.0 + templates v10.4.5 (sha256-verified) and
  moved nuclei's XDG config/cache from the read-only /opt bake to /tmp/.config //tmp/.cache.
  Reason: -tv/-version only READ config, but a REAL scan WRITES config + cache and died
  `FTL could not create config file` on the read-only rootfs. The frozen sandbox mounts
  one writable path (`--tmpfs /tmp` + HOME=/tmp), so config must live there: baked /tmp
  files serve read-only -tv/-version, the tmpfs overlay makes them writable for a real
  scan. Verified all 4 states; sandbox.py untouched. Committed f4cf76b — 2026-07-12
- Mapped XssCandidate -> Finding(type="XSS"); made modules/xss.scan_xss agent-backed
  (mirrors SQLi). engine/finding_map.py: xss_candidate_to_finding (injectable-only,
  severity always "High"). engine/report_io.py generalized (agent-type-agnostic SARIF
  ruleId from Finding.type; getattr for missing .depth) — SQLi output byte-for-byte
  unchanged. _HAS_AGENT resolver + _agent_scan_xss falls back to _legacy_scan_xss. New
  tests/test_xss_finding_map.py + offline tests; zero regressions — 2026-07-11

## Key decisions
- Host-local target detection = loopback OR the resolved IP is one of THIS host's own
  interface IPs (incl. docker bridge gateways). Route via the bridge GATEWAY, never
  hairpin via the public IP. `connect_ip` (gateway for host-local, public IP for
  remote) is used consistently by --add-host, the egress ACCEPT rule, AND the
  self-test probe, so a passing self-test proves the exact path the scan takes.
  `SandboxResult.target_ip` still reports the resolved IP, not connect_ip.
- Docker-PUBLISHED host-local ports (DVWA) need an extra nat/PREROUTING DNAT bypass
  beyond gateway routing (Docker DNATs published ports before our filter ACCEPT can
  match); host-PROCESS targets (Juice Shop) don't. The bypass is best-effort, targeted
  to subnet->gateway:port only, and torn down — never fatal, never broadened.
- engine/xss_agent.py is a NEW PARALLEL module — engine/agent.py (SQLi) untouched.
  Shared generic helpers are IMPORTED from engine.agent, not copied.
- Dalfox writes [POC] to stdout and [V]/[I] to stderr — the runner parses both
  COMBINED. stopped_reason for XSS is {done, completed_by_ladder, budget,
  max_iterations} (no "error" reason, unlike SQLi) — a failed scan surfaces only via
  per-candidate status="error", never a false "clean".
- auth_cookie is sanitized then threaded via --cookie; REQUIRED for DVWA's xss_r route.
- Dalfox pinned to v2.13.0, not latest v3.1.2 (full CLI/output rewrite in v3.x).
- engine/report_io.py's generalization uses getattr() defaults + Finding.type read
  dynamically (no isinstance/type-check branch) — extends to future agent shapes
  automatically as long as candidates expose .endpoint_url/.status.
- modules/sqli.py and modules/xss.py's _agent_scan_X wrappers are left duplicated
  (~25 lines each) rather than factored into a shared helper — task asked to "mirror
  the exact pattern"; revisit if a 3rd agent-backed module appears.
- nuclei's XDG_CONFIG_HOME/XDG_CACHE_HOME are set to **/tmp/.config //tmp/.cache** and
  pre-populated at build time (NOT /opt — earlier bake, now superseded). This one path
  serves both runtimes: baked read-only files satisfy -tv/-version (no tmpfs), and the
  sandbox's `--tmpfs /tmp` + HOME=/tmp overlay makes it WRITABLE for real scans (which
  must write config.yaml/reporting-config.yaml + cache). /tmp is the sandbox's only
  writable mount, so XDG must live there. engine/sandbox.py NOT touched.
- nuclei engine pinned to v3.11.0 (current stable v3; no rewrite-avoidance reason like
  Dalfox's v2 pin) and nuclei-templates pinned to v10.4.5 (GitHub codeload tag source
  archive, sha256 == nuclei-templates' own checksums.txt; no separate binary asset).
- nuclei_agent mirrors xss_agent EXACTLY (imports generic helpers from engine.agent, not
  copied); NucleiCandidate/NucleiAgentResult local (not schemas.py). Model supplies
  target/tags/note only; harness owns all flags. Tags are an ALLOWLIST (unknown-safe
  dropped, dangerous/flag-like RAISES). Auth cookie threaded harness-side as `-H
  "Cookie: <val>"` — the ONLY -H permitted (any other -H = injection, trips the guard).
  stopped_reason has NO "error" (like XSS): a failed scan is only per-candidate
  status="error". Default tags = tech,exposure,misconfig when model gives none.
- D-017 (settled): nuclei results are BROADER than the frozen Finding enum, so they are
  surfaced into SARIF + nuclei_<id>.json + run.json ONLY — never typed Findings, never in
  findings_<id>.json; schemas.py NOT modified. write_outputs's `nuclei_candidates` is
  additive & optional (omitted => byte-for-byte unchanged); report_io stays decoupled
  (getattr duck-typing, no nuclei import). modules/recon.py is the standalone entry,
  deliberately NOT in integration.py's resolver.

## Open issues / blockers
- nuclei_agent has NO Finding mapping / output wiring yet — that's Prompt 3 (see Next step).
- Live nuclei_agent smoke is BLOCKED by host-local sandbox networking, NOT by agent code:
  a trivial `curl` through run_in_sandbox against localhost:8080 AND :3000 both fail the
  isolation self-test with `target=7` (refused) right now. Root cause: orphaned sandbox
  state from a crashed earlier run — an orphaned docker network `redsee-sbx-net-1dad3e0d`
  (172.18.0.0/16) + leftover DOCKER-USER/INPUT iptables rules (incl. a catch-all DROP).
  Cleaning those needs firewall/network changes I declined to make autonomously (the
  auto-mode classifier flags flushing DROP rules as security-weakening). USER ACTION to
  unblock: `docker network rm redsee-sbx-net-1dad3e0d` and delete the stale 172.18.0.0/16
  DOCKER-USER/INPUT rules (`iptables -S DOCKER-USER`/`-S INPUT` to list). The agent itself
  is proven correct: it surfaced the failure as status="error" (never a false clean/found),
  and a real nuclei scan under the EXACT sandbox flags finds templates (verified directly).
- Not yet run: a live `scan_xss()` call through the full modules.xss public API.
- This dev sandbox lacks `markdown`/`weasyprint` — red_report.py/blue_report.py + their
  tests fail to import here (pre-existing, unrelated).
- Container lifecycle is volatile across turns: check `docker ps` / `curl` before
  assuming DVWA (:8080) or Juice Shop (:3000) is up.
- The DNAT bypass assumes docker userland-proxy is enabled (docker-proxy for :8080 IS
  running on this host, so the bypass precondition holds — the blocker above is stale rules).

## Changed files (this session — nuclei output surfacing)
- engine/report_io.py — write_outputs gained optional `nuclei_candidates=None`;
  found -> SARIF (ruleId=template_id, nuclei-severity level map) + nuclei_<id>.json +
  run.json nuclei summary. Duck-typed via getattr; _endpoint_status_summary falls back
  endpoint_url->target. Omitted => byte-for-byte identical (proven vs HEAD).
- modules/recon.py (NEW) — run_recon_scan chains run_nuclei_agent -> write_outputs; NOT
  in integration.py's resolver, no scan_<vuln> signature.
- tests/test_report_io.py (NEW) — 11 tests (real captured JSONL): found->SARIF+json+
  run summary, findings_<id>.json nuclei-free, omitted==unchanged, secret scrub intact.
- (earlier this branch: engine/nuclei_agent.py, prompts/nuclei_agent.txt,
  tests/test_nuclei_agent.py, tests/fixtures/nuclei_dvwa_real.jsonl, docker/sandbox/
  Dockerfile, docs/nuclei_sandbox.md — all committed in f4cf76b.)
- schemas.py, engine/sandbox.py, engine/agent.py, engine/xss_agent.py, modules/sqli.py,
  modules/xss.py, integration.py, build.sh — UNTOUCHED (verified). schemas.py NOT modified.

## Invariants to preserve
- schemas.py contract frozen · severity strings exact · sandbox + scope gating · auth gating first
- run_in_sandbox public API + hardening flags frozen (--cap-drop=ALL, no-new-privileges,
  --read-only, non-root, NEVER --privileged/NET_ADMIN) · fail-closed self-test never softened
- Egress allows ONLY the single connect_ip:port actually contacted — never broadened ·
  public internet + host SSH(22) stay blocked & self-tested
- Host-local targets route via the bridge gateway, never hairpin via the public IP
- injectable/found derives SOLELY from parsed tool positive output (sqlmap for SQLi; Dalfox
  [POC]/[V] for XSS; nuclei -jsonl result lines for templates) · never from the model ·
  nuclei/XSS/SQLi agents never let the model supply raw flags; harness-owned profile only ·
  no interactsh/OOB, no exploit/intrusive/dos/fuzz/brute, no auto-update, ever
- All tool execution via engine.sandbox.run_in_sandbox; every URL scope-checked first;
  detection-only (no exploit/blind-callback flags, ever)
- load_env() only at true entry points · override=False always
- See AGENTS.md for the full contract.
