# RedSee — Session Handoff

**Last updated:** 2026-07-13T15:10:00Z
**Current milestone:** ffuf + a pinned small wordlist installed in the sandbox image (tool-install only, no runner yet). Branch `feat/nuclei`, all uncommitted.

## Next step
Build an `engine/ffuf_agent.py` (LLM-driven, mirroring nuclei_agent's shape) or a
deterministic `engine/ffuf_tools.py` (mirroring recon_tools' shape — TBD which fits ffuf's
use case better: directory/file brute-forcing is arguably closer to a bounded deterministic
sweep than an LLM-judged detection loop) and wire its output into `report_io`/`modules/` the
same additive way nuclei/recon were. Everything in this session is UNCOMMITTED — commit when
ready (Dockerfile ffuf+wordlist blocks + docs/nuclei_sandbox.md section). Also still pending
from before: a live end-to-end `modules.recon` run (blocked by host-local sandbox
networking — see blockers) and a live `scan_xss()` smoke.

## In progress
nothing

## Recently completed (last 5)
- Installed pinned ffuf v2.1.0 (github.com/ffuf/ffuf, sha256-verified against ffuf's own
  checksums file + independently re-downloaded/re-hashed locally) into docker/sandbox/Dockerfile,
  same pattern as sqlmap/Dalfox/nuclei/httpx/tlsx (official GitHub release binary, NOT
  go install/@latest/apt). Bundled ONE small pinned wordlist at /opt/wordlists/common.txt —
  SecLists' Discovery/Web-Content/common.txt (~4750 lines, MIT), fetched as a raw file pinned
  to one exact commit sha (not just a tag, which can move), sha256-verified, NOT a full
  SecLists clone. Confirmed ffuf needs NO XDG config-dir bake (unlike the ProjectDiscovery
  tools) — `ffuf -V` succeeds under `--read-only --user 10001 --network none` with zero
  writes. All DoD checks green: ffuf -V (both normal + hardened), wordlist line count (4750),
  nuclei/httpx/tlsx/sqlmap/dalfox regression unaffected. docker/sandbox/ + docs only — no
  Python/engine/build.sh changes — 2026-07-13
- Built engine/recon_tools.py — deterministic sandboxed httpx (HTTP fingerprint) + tlsx
  (TLS/cert inspect) recon, reusing nuclei_agent's SHAPE (scope-gate-first, sandbox-only)
  WITHOUT any LLM/agent loop/budget — one fixed harness-built command per target.
  ReconObservation (local, not schemas.py) has status={observed,error,out_of_scope} — no
  "clean" status; a successful-but-empty probe yields no observation, never fabricated.
  httpx: -status-code/-title/-web-server/-tech-detect/-content-length/-cdn/-tls-grab,
  GET-only (-x/-path hard-forbidden). tlsx: -tls-version/-cipher/-serial/-expired/
  -self-signed/-mismatched + a BOUNDED -cipher-enum -cipher-type weak; -san/-cn/-so
  deliberately omitted (this tlsx build rejects combining them with other probes —
  subject fields already appear by default via omitempty). tlsx derives -host/-port from
  the target URL using the EXACT SAME formula run_in_sandbox uses internally, so the
  probed port always matches what the firewall opens. Severity (Low/Medium, Finding's
  title-case convention) comes solely from real tlsx fields (self_signed/expired/
  mismatched/weak cipher_enum entries) — never fabricated. 24 offline tests vs REAL
  captured fixtures: tests/fixtures/httpx_dvwa_real.jsonl (DVWA :8080) and
  tests/fixtures/tlsx_selfsigned_real.jsonl (a real self-signed cert from a throwaway
  local TLS listener spun up just for the capture, then torn down) — 2026-07-13
- **Found + fixed a real bug**: httpx v1.10.0 (pinned by the prior tool-install task) makes
  an UNCONDITIONAL network call on EVERY run — even with just `-status-code` alone,
  `-disable-update-check` does NOT gate it — downloading a ~92MB ML model from
  huggingface.co/datasets/happyhackingspace/dit. In the real hardened sandbox (egress
  locked to the target IP:port) this would be DROPped, stalling every recon scan on a
  doomed connection before ever probing the target. Downgraded the Dockerfile pin to
  v1.9.0 (independently sha256-verified, confirmed clean — no such call, no `PageType` key
  in its knowledgebase JSON) — same "pin to avoid bad behavior" pattern as Dalfox's v2.13.0
  pin. Rebuilt + reverified all httpx/tlsx/nuclei/sqlmap/dalfox DoD checks pass — 2026-07-13
- engine/report_io.py extended with a SECOND additive channel: `recon_observations=None`
  mirrors the nuclei_candidates channel exactly — observed rows -> SARIF (ruleId=category,
  level from the SAME Finding-style Low/Medium map, reused not duplicated) +
  recon_<id>.json + a `recon` run.json summary block (count_by_tool + count_by_severity).
  modules/recon.py extended: run_recon_scan now ALSO runs run_httpx+run_tlsx (sharing one
  resolved scope_config with the nuclei agent) and passes recon_observations into the SAME
  write_outputs call as nuclei_candidates. Both channels independently omittable; byte-
  for-byte unchanged when both omitted. tests/test_report_io.py-style tests added directly
  in test_recon_tools.py (SARIF/json/run.json/no-findings-leak/omitted-unchanged) — 2026-07-13
- Surfaced nuclei candidates into the output layer WITHOUT touching schemas.py or
  findings_<id>.json (settled decision D-017). write_outputs gained optional
  `nuclei_candidates=None` — found ones append to SARIF (ruleId=template_id) +
  nuclei_<id>.json + a run.json summary. New modules/recon.py (run_recon_scan); NOT
  wired into integration.py. tests/test_report_io.py (11 tests) — 2026-07-12

## Key decisions
- Host-local sandbox targets route via the bridge GATEWAY (never hairpin the public IP);
  Docker-PUBLISHED ports (DVWA) additionally need a torn-down nat/PREROUTING DNAT bypass.
  See AGENTS.md/docs for full detail — unchanged this session.
- engine/xss_agent.py, engine/nuclei_agent.py, engine/recon_tools.py are each NEW PARALLEL
  modules — engine/agent.py (SQLi) untouched throughout. Shared generic helpers are
  IMPORTED, not copied (recon_tools deliberately does NOT import from nuclei_agent —
  trivial helpers like `_target_url` are reimplemented locally to stay decoupled, since
  recon_tools has no LLM/agent loop at all and shouldn't depend on one that does).
- Dalfox pinned to v2.13.0 (avoid v3.x CLI rewrite); nuclei pinned to v3.11.0 + templates
  v10.4.5; **httpx pinned to v1.9.0, NOT v1.10.0** — v1.10.0 makes an unconditional
  network call to huggingface.co on every run (not gated by -disable-update-check),
  downloading a 92MB ML model; confirmed absent in v1.9.0. Same "pin to avoid bad
  behavior" pattern each time.
- nuclei's (and now httpx's/tlsx's) XDG_CONFIG_HOME/XDG_CACHE_HOME are set to
  **/tmp/.config //tmp/.cache**, pre-populated at build time. One path serves two
  runtimes: baked read-only files satisfy `-version` (no tmpfs), and the sandbox's
  `--tmpfs /tmp` + HOME=/tmp overlay makes it WRITABLE for real scans. /tmp is the
  sandbox's only writable mount — engine/sandbox.py NOT touched.
- nuclei_agent's model-facing safety pattern (harness owns all flags; tags are an
  ALLOWLIST; auth cookie threaded as the only permitted `-H`; a bad tool-call is refused,
  not fatal) does NOT apply to recon_tools — recon_tools has NO model in the loop, so
  there is nothing to sanitize/refuse from a caller; its `_assert_no_forbidden_flags` is a
  pure coding-regression backstop on an entirely harness-built argv.
- tlsx's `-host`/`-port` (not a URL) are derived via `_host_port_from_target`, using the
  EXACT SAME port formula `engine.sandbox.run_in_sandbox` uses internally — required so
  the port tlsx actually probes always matches the port the sandbox firewall opens.
  `-san`/`-cn`/`-so` are omitted (this tlsx build rejects combining them with any other
  probe flag; the same subject fields already appear via Go's omitempty regardless).
- D-017 (settled, extended this session to recon): nuclei/httpx/tlsx results are BROADER
  than the frozen Finding enum, so they are surfaced into SARIF + a dedicated per-source
  JSON (`nuclei_<id>.json` / `recon_<id>.json`) + run.json ONLY — never typed Findings,
  never in findings_<id>.json; schemas.py NOT modified. Both `nuclei_candidates` and
  `recon_observations` on write_outputs are additive, optional, and independently
  omittable (either/both omitted => byte-for-byte unchanged); report_io stays decoupled
  from both source modules via getattr duck-typing. modules/recon.py is the standalone
  entry for all three tools, deliberately NOT in integration.py's resolver.
- D-020: ffuf pinned to v2.1.0 (GitHub release binary, sha256-verified, NOT go
  install/@latest/apt) — same reproducibility pattern as every other sandbox tool. Bundled
  wordlist is SecLists' `Discovery/Web-Content/common.txt` ONLY (~4750 lines), pinned to one
  exact commit sha (not a movable tag), sha256-verified — NOT a full SecLists clone
  (~1GB would bloat the image and isn't needed for a single small list). Confirmed ffuf
  needs no `/tmp/.config` XDG bake (unlike nuclei/httpx/tlsx) — it writes nothing at
  startup, verified under `--read-only --user 10001 --network none`.

## Open issues / blockers
- nuclei_agent/recon_tools have NO Finding mapping — by design (D-017), not a gap.
- Live smoke (nuclei_agent AND recon_tools/modules.recon) is BLOCKED by host-local sandbox
  networking, NOT by any agent/recon code: a trivial `curl` through run_in_sandbox against
  localhost:8080 still fails the isolation self-test with `target=7` (refused) — re-verified
  fresh this session, independent of any code here. The orphaned network from the prior
  session (`redsee-sbx-net-1dad3e0d`) has been removed and no orphaned sandbox networks
  remain now, but the underlying host-local reachability issue persists (root cause not
  yet found — possibly still the stale 172.18.0.0/16 DOCKER-USER/INPUT catch-all DROP
  rules, which STILL exist: `iptables -S DOCKER-USER | grep 172.18`; deleting them needs
  firewall changes I decline to make autonomously — USER ACTION to try next).
  BOTH engine/nuclei_agent.py and engine/recon_tools.py are proven correct against this:
  they surface the failure as status="error" (never a false clean/found/observed) — see
  tests/test_recon_tools.py's error-path tests, which assert exactly this using the SAME
  real error message captured from this live failure.
- Not yet run: a live `scan_xss()` call through the full modules.xss public API.
- This dev sandbox lacks `markdown`/`weasyprint` — red_report.py/blue_report.py + their
  tests fail to import here (pre-existing, unrelated).
- Container lifecycle is volatile across turns: check `docker ps` / `curl` before
  assuming DVWA (:8080) or Juice Shop (:3000) is up.

## Changed files (this session — ffuf + wordlist tool-install)
- docker/sandbox/Dockerfile — added FFUF_VERSION=v2.1.0 (+sha256) install block (mirrors
  Dalfox/nuclei's pinned-GitHub-release pattern exactly) and a wordlist-fetch block
  (SECLISTS_COMMIT pinned sha + WORDLIST_SHA256) writing /opt/wordlists/common.txt,
  chmod'd a+rX. No changes to any existing tool's pin, the XDG bake, the USER/ENTRYPOINT
  lines, or anything below the existing nuclei-templates block's insertion point.
- docs/nuclei_sandbox.md — new "ffuf + a pinned wordlist" section at the end: pin
  provenance, confirms no XDG bake needed, verification commands.
- docker/sandbox/build.sh — UNTOUCHED (verified: `git diff --stat build.sh` empty).
- No engine/*, modules/*, schemas.py, or other Python file touched (verified via
  `git status`/`git diff --stat` — only the two files above changed).
- tests/test_recon_tools.py (NEW, 24 tests) + tests/fixtures/httpx_dvwa_real.jsonl +
  tests/fixtures/tlsx_selfsigned_real.jsonl (NEW, both real captured JSON).
- docs/nuclei_sandbox.md — httpx pin note corrected to v1.9.0 + phone-home writeup; new
  "Deterministic recon" section; Output-surfacing section extended for the recon channel.
- schemas.py, engine/sandbox.py, engine/agent.py, engine/xss_agent.py, engine/nuclei_agent.py,
  modules/sqli.py, modules/xss.py, modules/idor.py, integration.py, build.sh — UNTOUCHED
  (verified). schemas.py NOT modified.

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
