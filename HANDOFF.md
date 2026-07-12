# RedSee — Session Handoff

**Last updated:** 2026-07-12T12:05:00Z
**Current milestone:** engine/nuclei_agent.py — sandboxed, agent-driven nuclei detection (agent + offline tests only; branch `feat/nuclei`). Third scanning agent, parallel to SQLi/XSS.

## Next step
Prompt 3: map NucleiCandidate(status="found") -> schema-valid Finding + output wiring
(engine.finding_map + report_io, and a modules/ entry point / integration.py resolver).
Open design Q carried over: nuclei covers CVEs/misconfig/exposed-panels, which do NOT
map 1:1 to the 4 frozen Finding types (SQLi/XSS/IDOR/BrokenAuth) — decide the mapping
(reuse a type vs. request a new one; note schemas.py finding types are a frozen contract).
Map nuclei severity (info/low/medium/high/critical) -> exact Critical/High/Medium/Low.
Still outstanding from earlier: a live `scan_xss()` smoke through modules.xss.

## In progress
nothing

## Recently completed (last 5)
- Built engine/nuclei_agent.py — the template-scan agent, a parallel to
  engine/agent.py (SQLi) / engine/xss_agent.py (XSS), driving nuclei. run_nuclei_agent(
  targets, *, ..., auth_cookie) -> NucleiAgentResult; NucleiCandidate/NucleiAgentResult
  (NOT in schemas.py). ONE harness-owned run_nuclei tool: model supplies only
  target/tags(safe allowlist)/note — NEVER flags. Harness fixes -jsonl/-omit-raw/
  -disable-update-check/-no-interactsh, -t /opt/nuclei-templates, -severity
  low,medium,high,critical (excludes info), -exclude-tags dos,intrusive,fuzz,brute,oob.
  _parse_nuclei_output (JSONL) is the SOLE source of status="found"; sandbox/timeout/
  non-zero -> status="error" (never a false clean/found). Smuggling a forbidden flag/tag
  via tags/target/note RAISES (_sanitize_tags/_validate_target/_assert_note_safe +
  _assert_no_forbidden_flags header-injection guard). stopped_reason {done,
  completed_by_ladder, budget, max_iterations}, bounded completion pass. 34 offline tests
  vs REAL captured DVWA JSONL (tests/fixtures/nuclei_dvwa_real.jsonl); regression 105
  passed/2 skipped; grep proves run_in_sandbox-only. Live smoke reached the sandbox and
  correctly surfaced the host-local self-test failure as status="error" (see blockers) — 2026-07-12
- REQUIRED Dockerfile fix for real nuclei scans: moved nuclei's XDG_CONFIG_HOME/
  XDG_CACHE_HOME from the read-only /opt bake to **/tmp/.config //tmp/.cache**. Reason:
  -tv/-version only READ config (so the /opt read-only bake passed Prompt 1), but a REAL
  scan WRITES config.yaml/reporting-config.yaml + cache index.gob and died with
  `FTL could not create config file` on the --read-only rootfs. engine/sandbox.py
  (frozen) mounts exactly one writable path — `--tmpfs /tmp` + HOME=/tmp — so the config
  must live there: the baked /tmp files serve read-only -tv/-version (no tmpfs), and the
  tmpfs overlay makes them writable for a real scan. Verified all 4 states: -version/-tv
  read-only pass; a real scan under the EXACT sandbox flags finds `configuration-listing`
  (medium); sqlmap/dalfox unaffected. engine/sandbox.py NOT touched — 2026-07-12
- Installed pinned nuclei v3.11.0 + nuclei-templates v10.4.5 into the Dockerfile (tool
  install), sha256-verified. Pre-baked a valid-but-empty uncover provider-config.yaml
  (`{}`) since uncover creates it on every startup. docs/nuclei_sandbox.md has the full
  transcript + pin provenance — 2026-07-12
- Mapped XssCandidate -> Finding(type="XSS"); made modules/xss.scan_xss agent-backed
  (mirrors SQLi). engine/finding_map.py: xss_candidate_to_finding (injectable-only,
  severity always "High"). engine/report_io.py generalized (agent-type-agnostic SARIF
  ruleId from Finding.type; getattr for missing .depth) — SQLi output byte-for-byte
  unchanged. _HAS_AGENT resolver + _agent_scan_xss falls back to _legacy_scan_xss. New
  tests/test_xss_finding_map.py + offline tests; zero regressions — 2026-07-11
- Fixed the sandbox host-local reachability (hairpin/NAT) in engine/sandbox.py: host-local
  targets route via the bridge GATEWAY (not the public IP); host-PUBLISHED ports (DVWA
  :8080) also need a torn-down nat/PREROUTING DNAT bypass. Egress still gateway:port +
  ESTABLISHED only; self-test unchanged. Verified live for :3000 and :8080 — 2026-07-11

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

## Changed files (this session)
- engine/nuclei_agent.py (NEW) — the nuclei agent (run_nuclei_agent + NucleiCandidate/
  NucleiAgentResult + run_nuclei tool + parser + guards). Imports generic helpers from
  engine.agent; nuclei runs ONLY via run_in_sandbox (grep-verified, no raw subprocess).
- prompts/nuclei_agent.txt (NEW) — system prompt, mirrors prompts/xss_agent.txt.
- tests/test_nuclei_agent.py (NEW) — 34 offline tests (mock LLM + monkeypatched
  run_in_sandbox); tests/fixtures/nuclei_dvwa_real.jsonl (NEW) — REAL captured nuclei
  JSONL (configuration-listing/tech-detect/ssh-sha1-hmac-algo from DVWA).
- docker/sandbox/Dockerfile — moved nuclei XDG config/cache from /opt to /tmp/.config //
  tmp/.cache so real scans can write under the sandbox's tmpfs (see Key decisions). The
  v3.11.0/v10.4.5 pins, templates at /opt/nuclei-templates, and the uncover-config bake
  are unchanged; only the config-dir location moved.
- docs/nuclei_sandbox.md — updated for the /tmp config-dir design + an "agent layer"
  section (the file was new last session).
- engine/sandbox.py, schemas.py, modules/*, integration.py, build.sh, engine/agent.py,
  engine/xss_agent.py — all UNTOUCHED (verified). schemas.py NOT modified.

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
