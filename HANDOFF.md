# RedSee — Session Handoff

**Last updated:** 2026-07-11T11:15:00Z
**Current milestone:** XSS candidate->Finding mapping + agent-backed modules/xss.scan_xss — SQLi and XSS now fully symmetric through the same pipeline

## Next step
Both scan_sqli and scan_xss are now agent-backed end-to-end with the same
finding-mapping/audit-trail path. Natural next steps: (a) a live end-to-end
`scan_xss()` smoke against DVWA :8080 (REDSEE_XSS_COOKIE set) — the underlying pieces
(xss_agent live run, sandbox hairpin fix, finding-map tests) are each verified
individually but not yet chained through the exact modules.xss.scan_xss entry point;
(b) consider a shared `_agent_scan(...)` helper if a 3rd module (IDOR/BrokenAuth)
ever gets an agent — modules/sqli.py and modules/xss.py currently duplicate the same
~25-line _agent_scan_X wrapper shape on purpose (task asked to "mirror the exact
pattern"; not done yet).

## In progress
nothing

## Recently completed (last 5)
- Mapped XssCandidate -> Finding(type="XSS") and made modules/xss.scan_xss
  agent-backed, mirroring the SQLi path exactly. engine/finding_map.py gained
  xss_candidate_to_finding(cand, *, target_url, scan_id) (injectable-only: raises
  ValueError on clean/error/out_of_scope, same contract as candidate_to_finding);
  severity always "High" (Dalfox's `context` is syntactic, not a severity signal, and
  the agent only confirms REFLECTED — no escalation tier like SQLi's union/error).
  engine/report_io.py was minimally generalized (NOT duplicated) to be
  agent-type-agnostic: `_build_sarif` derives `ruleId` from each Finding's own
  `.type` (was hardcoded "SQLi"), builds `rules[]` from the distinct types present;
  `_endpoint_status_summary` uses `getattr(c, "depth", None)` so it no longer crashes
  on XssCandidate (no `depth` field) — SQLi's own output verified byte-for-byte
  unchanged. modules/xss.py: renamed the existing full scanner to _legacy_scan_xss,
  added the _HAS_AGENT resolver + _agent_scan_xss (reads optional REDSEE_XSS_COOKIE,
  threads it into run_xss_agent's auth_cookie); scan_xss(endpoints, session=None)
  tries the agent path first, falls back to _legacy_scan_xss on import OR runtime
  failure — signature + integration.py's resolver verified unchanged. New
  tests/test_xss_finding_map.py (9 tests) + 8 new offline tests in tests/test_xss.py;
  the 4 legacy live-DVWA tests now call _legacy_scan_xss directly (same reasoning as
  test_sqli.py). All new/offline tests pass; only the same 3 pre-existing
  live-DVWA-unreachable failures test_sqli.py already has (zero regressions) — 2026-07-11
- Fixed the sandbox host-local reachability (hairpin/NAT) bug in engine/sandbox.py:
  when the target hostname resolves to one of THIS host's own IPs
  (is_host_local_ip), route via the sandbox bridge GATEWAY instead of the public IP
  (which can't hairpin back from the restricted bridge). Host-PUBLISHED ports (DVWA
  :8080) additionally needed a targeted, torn-down nat/PREROUTING bypass since
  Docker's own DNAT rewrote the dest past our ACCEPT rule first. Egress still allows
  only gateway:port + ESTABLISHED; self-test logic unchanged (target must succeed,
  public+SSH must stay blocked). run_in_sandbox API + all hardening flags unchanged.
  Verified: 12/12 offline tests; real integration test passes for both host-process
  (:3000) and host-published (:8080) targets; full XSS agent live run now finds DVWA
  reflected XSS through the isolated sandbox — 2026-07-11
- Built engine/xss_agent.py — the reflected-XSS agent, a parallel to engine/agent.py
  driving Dalfox instead of sqlmap (same scope-gate-first/sandbox-only/budget-capped/
  status-field/completion-pass shape). run_xss_agent(endpoints, *, ..., auth_cookie)
  -> XssAgentResult; XssCandidate/XssAgentResult (not in schemas.py). One harness-owned
  run_dalfox tool (model never supplies flags); _parse_dalfox_output is the SOLE
  injectable source (a [POC] line and/or "[V] Triggered XSS Payload" — negative guard
  against bare mentions). 21 offline tests; parser validated against REAL captured
  DVWA+Dalfox ground truth (not just synthetic fixtures) — 2026-07-10
- Stood up DVWA locally + wired into RedSee scope: extended docker/demo-helper.sh with
  `dvwa`/`juiceshop` subcommands, DVWA on host port 8080 (avoids Juice Shop's 3000),
  printing exact REDSEE_TARGET_URL/REDSEE_ALLOWED_HOSTS + setup checklist. Confirmed
  genuine reflected XSS by hand at /vulnerabilities/xss_r/ — 2026-07-10
- Added Dalfox v2.13.0 to docker/sandbox/Dockerfile alongside sqlmap (sha256-pinned
  GitHub release, same hardened non-root/read-only/egress-restricted container).
  Pinned to v2.13.0, the last release before the v3.x CLI/output rewrite — 2026-07-10

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

## Open issues / blockers
- Not yet run: a live `scan_xss()` call through the full modules.xss public API
  against DVWA with REDSEE_XSS_COOKIE set (constituent pieces verified individually).
- This dev sandbox lacks `markdown`/`weasyprint` — red_report.py/blue_report.py + their
  tests fail to import here (pre-existing, unrelated). python-dotenv + beautifulsoup4
  are installed.
- Container lifecycle is volatile across turns: check `docker ps` / `curl` before
  assuming DVWA (:8080) or Juice Shop (:3000) is up.
- The DNAT bypass assumes docker userland-proxy is enabled (confirmed on this host).

## Changed files (this session)
- engine/finding_map.py — added xss_candidate_to_finding (+ _severity_for_xss,
  _XSS_REMEDIATION); imports XssCandidate. candidate_to_finding (SQLi) untouched.
- engine/report_io.py — _build_sarif/_endpoint_status_summary generalized (see Key
  decisions); write_outputs's SQLi output byte-for-byte unchanged (verified).
- modules/xss.py — agent-backed scan_xss + _agent_scan_xss + _HAS_AGENT block;
  existing scanner renamed _legacy_scan_xss; __main__ calls _legacy_scan_xss directly.
- tests/test_xss_finding_map.py (NEW) — 9 tests mirroring test_finding_map.py.
- tests/test_xss.py — +8 offline agent-backed/fallback/cookie tests; 4 legacy live
  tests now call _legacy_scan_xss explicitly.
- No other files changed. engine/agent.py, engine/xss_agent.py, engine/sandbox.py,
  engine/scope.py, engine/llm.py, schemas.py, integration.py all UNTOUCHED (verified).

## Invariants to preserve
- schemas.py contract frozen · severity strings exact · sandbox + scope gating · auth gating first
- run_in_sandbox public API + hardening flags frozen (--cap-drop=ALL, no-new-privileges,
  --read-only, non-root, NEVER --privileged/NET_ADMIN) · fail-closed self-test never softened
- Egress allows ONLY the single connect_ip:port actually contacted — never broadened ·
  public internet + host SSH(22) stay blocked & self-tested
- Host-local targets route via the bridge gateway, never hairpin via the public IP
- injectable derives SOLELY from parsed tool positive output (sqlmap for SQLi; Dalfox
  [POC]/[V] for XSS) · never from the model · Only status=="injectable" -> Finding
- All tool execution via engine.sandbox.run_in_sandbox; every URL scope-checked first;
  detection-only (no exploit/blind-callback flags, ever)
- load_env() only at true entry points · override=False always
- See AGENTS.md for the full contract.
