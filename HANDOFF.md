# RedSee — Session Handoff

**Last updated:** 2026-07-11T09:30:00Z
**Current milestone:** Sandbox host-local hairpin bug FIXED — host-published targets (DVWA :8080) now reachable through the isolated sandbox; full XSS pipeline confirmed end-to-end

## Next step
Map XssCandidate -> schema.Finding (type EXACTLY "XSS") in a new engine/xss_finding_map.py
mirroring engine/finding_map.py (injectable-only: only status=="injectable" candidates
become a Finding; raise on clean/error/out_of_scope). Then wire an agent-backed scan_xss
into modules/xss.py (agent-first + legacy fallback, exactly like modules/sqli.py) and emit
the same findings/SARIF/run.json audit trail via engine.report_io. NOT started. (The
sandbox reachability blocker that stopped the last live XSS run is now RESOLVED — see below.)

## In progress
nothing

## Recently completed (last 5)
- Fixed the sandbox host-local reachability (hairpin/NAT) bug in engine/sandbox.py — the
  blocker from the prior session. When the target hostname resolves to one of THIS host's
  own IPs (is_host_local_ip: loopback or any host interface IP incl. docker gateways), the
  container can't hairpin back to that public IP from the restricted bridge; now it routes
  via the sandbox bridge GATEWAY (_network_gateway) — on-bridge, never leaving the host.
  New: is_host_local_ip / _host_ip_addresses (hostname -I + gethostbyname), _network_gateway
  (with subnet .1 fallback). The --add-host mapping, egress ACCEPT rule, and self-test all
  use ONE address (connect_ip = gateway for host-local, public IP for remote). Remote path
  UNCHANGED. For host-PUBLISHED ports (DVWA :8080) Docker's DNAT (`! -i docker0`) fired from
  our custom bridge and rewrote the dest past our ACCEPT -> added _apply_prerouting_bypass:
  a torn-down nat/PREROUTING ACCEPT for ONLY subnet->gateway:port so the packet reaches the
  host's local listener (docker-proxy / host service) instead of being NAT'd to the target
  container. Does NOT broaden egress (filter still allows only gateway:port + ESTABLISHED,
  DROP everything else). Self-test unchanged in logic (target requires exit 0; public 1.1.1.1
  + host SSH:22 must stay blocked/7|28). run_in_sandbox API + all hardening flags UNCHANGED.
  Verified: 12/12 offline tests (pytest + __main__); real integration test PASSES against
  BOTH host-process :3000 and host-published :8080 (target reachable AND public+ssh blocked);
  manual check: run_in_sandbox curl to DVWA :8080 now returns 302 (was curl-exit-28 timeout);
  and the FULL XSS agent live run now finds DVWA reflected XSS through the isolated sandbox
  (status=injectable, param=name, real [POC] evidence) — 2026-07-11
- Built engine/xss_agent.py — the reflected-XSS agent, a parallel to engine/agent.py
  driving Dalfox instead of sqlmap. Mirrors the proven design: scope-gate-first,
  sandbox-only execution (run_in_sandbox), one BudgetTracker/run, evidence-gated parsing,
  status field {injectable|clean|error|out_of_scope}, deterministic completion pass,
  transcript for run.json. Public: run_xss_agent(endpoints, *, max_iterations=6,
  scope_config, llm_config, llm_client, auth_cookie) -> XssAgentResult; dataclasses
  XssCandidate / XssAgentResult (NOT in schemas.py). ONE harness-owned tool run_dalfox
  (model supplies only url/param/note — never flags); detection-only base profile
  ["--no-color","--format","plain"] + optional -p param + optional --cookie auth_cookie;
  _assert_no_forbidden_flags bans -b/--blind/--exploit/--remote-*/--custom-payload/
  -o/--output/--cookie-from-raw/etc. _parse_dalfox_output is the SOLE injectable source:
  True ONLY from a [POC] line and/or "[V] Triggered XSS Payload"; negative guard so mere
  XSS/reflection mentions never confirm; extracts parameter/context/payload/evidence.
  Reuses engine.agent's generic helpers by IMPORT (_endpoint_field, _parse_tool_call,
  _endpoint_key, _primary_param) — engine/agent.py itself untouched. prompts/xss_agent.txt
  + tests/test_xss_agent.py (21 offline tests, pytest + __main__ runner, all pass).
  Verified the parser against REAL ground truth: captured genuine Dalfox-v2.13.0-vs-DVWA
  output (authenticated, security=low) — `[POC][V][GET][inHTML-none(1)] ...` +
  `[V] Triggered XSS Payload (found DOM Object): ...`, [issues: 2] — and _parse_dalfox_output
  correctly returns injectable=True, param="name", context="inHTML-none(1)", payload +
  [POC] evidence. LIVE FULL-SANDBOX smoke against DVWA is BLOCKED by a sandbox-infra issue
  (see blockers) but the agent correctly classified it status="error" (never a false
  clean) — 2026-07-10
- Stood up DVWA locally + wired into RedSee scope: extended docker/demo-helper.sh
  (refactored into _start_dvwa/_start_juiceshop/_print_dvwa_scope; new `dvwa`/`juiceshop`
  subcommands) with DVWA on host port 8080 (avoids Juice Shop's 3000); prints the exact
  REDSEE_TARGET_URL/REDSEE_ALLOWED_HOSTS + the one-time browser setup checklist. Confirmed
  genuine reflected XSS by hand at /vulnerabilities/xss_r/ (raw unescaped payload). Juice
  Shop launcher/port untouched. Installed beautifulsoup4 + python-dotenv (both already in
  requirements.txt) — 2026-07-10
- Added Dalfox v2.13.0 (reflected/DOM XSS scanner) to docker/sandbox/Dockerfile
  alongside sqlmap: sha256-pinned GitHub release download (not `go install`), same
  non-root/cap-drop/read-only/egress-restricted container as sqlmap, engine/sandbox.py
  untouched. Pinned to v2.13.0 (last release before the v3.x CLI rewrite) so
  `dalfox version`/`dalfox url TARGET` and the classic `[POC]`/`[V]` output work. Ran a
  ground-truth check through engine.sandbox.run_in_sandbox against Juice Shop: correct
  TRUE NEGATIVE (Juice Shop's XSS is DOM-based/Angular, undetectable without a headless
  browser this minimal image intentionally lacks). Documented the negative run AND the
  positive-detection format (sourced from dalfox's own printing/poc.go source, since no
  live positive existed yet) in docs/dalfox_sandbox.md — 2026-07-10
- Auto-load .env at process entry points: new engine/env.py (load_env(), override=False,
  ImportError-safe, idempotent), wired into engine/agent.py's __main__, integration.py's
  __main__, and app.py's module top. tests/test_env.py (5 tests). Verified manually with
  no `source .env` needed — 2026-07-09

## Key decisions
- Host-local target detection = loopback OR the resolved IP is one of THIS host's own
  interface IPs (hostname -I, which includes docker bridge gateways like 172.17.0.1).
  Route host-local via the sandbox BRIDGE GATEWAY, never the public IP (no hairpin).
- Two distinct host-local sub-cases, both handled: a host-PROCESS service (e.g. Juice
  Shop :3000) works via gateway+INPUT alone; a docker-PUBLISHED port (DVWA :8080) also
  needs the nat/PREROUTING DNAT bypass because Docker DNATs published ports for every
  non-docker0 interface, rewriting the dest to the target container before our filter
  ACCEPT can match. The bypass is targeted (only subnet->gateway:port) and torn down.
- The DNAT bypass depends on docker's userland-proxy being enabled (it is here); it
  delivers to the local docker-proxy listener. A host-process target needs no bypass, so
  _apply_prerouting_bypass is best-effort (returns [] on failure) and never fatal.
- connect_ip (gateway for host-local, public IP for remote) is used consistently by the
  --add-host mapping, the egress ACCEPT rule, AND the self-test probe — so a passing
  self-test proves the exact path the scan takes. SandboxResult.target_ip still reports
  the RESOLVED IP (what the hostname resolved to), not connect_ip.
- Self-test logic UNCHANGED: target probe requires exit 0; public (1.1.1.1:80) and host
  SSH ($HOST:22) probes must stay blocked (7|28). Fail-closed preserved.
- engine/xss_agent.py is a NEW PARALLEL module — engine/agent.py (SQLi) is NOT modified.
  Shared generic helpers (_endpoint_field, _parse_tool_call, _endpoint_key, _primary_param)
  are IMPORTED from engine.agent, not copied. XSS-specific parsing/argv/loop are fresh.
- injectable comes ONLY from a [POC] line and/or "[V] Triggered XSS Payload" — a bare
  "[V]" or a "Reflected <param> param" info line is NOT enough (negative guard). Verified
  against real captured DVWA+Dalfox output, not just synthetic fixtures.
- run_dalfox tool exposes only url/param/note; the model NEVER supplies a Dalfox flag.
  Detection-only base profile + _assert_no_forbidden_flags bans blind/exploit/remote/
  file-output flags (defense-in-depth; some are v3-only, banned anyway).
- Dalfox writes [POC] to stdout and [V]/[I] to stderr — the runner parses stdout+stderr
  COMBINED (test_stdout_and_stderr_are_both_parsed covers this).
- stopped_reason kept to exactly {done, completed_by_ladder, budget, max_iterations} per
  the task spec (NO "error" reason, unlike the SQLi agent) — a scan that could not run is
  surfaced only via per-candidate status="error", never as a false "clean".
- auth_cookie is sanitized (reject flag-like/newline/oversized) then threaded via --cookie;
  REQUIRED for DVWA's xss_r route or the scan hits the login redirect and looks clean.
- Dalfox pinned to v2.13.0, not latest v3.1.2 (full CLI/output rewrite in v3.x).

## Open issues / blockers
- The prior session's sandbox↔host-published-port blocker is RESOLVED (see the fix above).
  The full XSS pipeline now runs end-to-end against DVWA :8080 through the isolated sandbox.
- This dev sandbox lacks `markdown`/`weasyprint` — red_report.py/blue_report.py + their
  tests fail to import here (pre-existing, unrelated). python-dotenv + beautifulsoup4 now
  installed.
- Container lifecycle is volatile across turns: redsee-dvwa is up (:8080, --restart
  unless-stopped, DB set up); something serves :3000 as a host process. Check `docker ps`
  / `curl` before assuming a target is up.
- The DNAT bypass assumes docker userland-proxy is enabled (confirmed on this host). If a
  deployment disables it, a docker-PUBLISHED host-local target would need a different route
  (e.g. allow the target container IP:container-port); host-PROCESS targets are unaffected.

## Changed files (this session)
- engine/sandbox.py — added is_host_local_ip / _host_ip_addresses / _network_gateway /
  _apply_prerouting_bypass / _remove_prerouting_bypass; run_in_sandbox now computes
  connect_ip (bridge gateway for host-local, public IP for remote) and applies the nat
  bypass for host-local; _build_hardening_argv / _apply_egress_firewall / _run_isolation_
  selftest params renamed to connect_ip/allow_ip and thread it through. Public API
  (run_in_sandbox signature, SandboxResult, SandboxError) + all hardening flags UNCHANGED.
- tests/test_sandbox.py — fake distinguishes Gateway vs Subnet inspect; remote-path tests
  pin _host_ip_addresses to force the public-IP path; +4 tests (is_host_local_ip,
  host-local→gateway routing, self-test block-probes, self-test hardening). 12 pass.
- No other files changed. engine/agent.py, engine/xss_agent.py, engine/scope.py,
  engine/llm.py, schemas.py, modules/* all UNTOUCHED.

## Invariants to preserve
- schemas.py contract frozen · severity strings exact · sandbox + scope gating · auth gating first
- run_in_sandbox public API + hardening flags frozen (--cap-drop=ALL, no-new-privileges,
  --read-only, non-root, NEVER --privileged/NET_ADMIN) · fail-closed self-test never softened
- Egress allows ONLY the single connect_ip:port actually contacted (gateway for host-local,
  public IP for remote) — never broadened · public internet + host SSH(22) stay blocked & self-tested
- Host-local targets route via the bridge gateway, never hairpin via the public IP
- injectable derives SOLELY from parsed tool positive output (sqlmap for SQLi; Dalfox
  [POC]/[V] for XSS) · never from the model · Only status=="injectable" -> Finding
- All tool execution via engine.sandbox.run_in_sandbox; every URL scope-checked first;
  detection-only (no exploit/blind-callback flags, ever)
- load_env() only at true entry points · override=False always
- See AGENTS.md for the full contract.
