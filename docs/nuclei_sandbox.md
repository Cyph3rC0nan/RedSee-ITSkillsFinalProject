# nuclei in the RedSee sandbox

`docker/sandbox/Dockerfile` installs [nuclei](https://github.com/projectdiscovery/nuclei)
engine v3.11.0 (pinned, official GitHub release, sha256-verified) plus a pinned
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) v10.4.5 baked in
at `/opt/nuclei-templates`, alongside sqlmap and Dalfox. Tool install only — no agent code,
no engine changes. It runs through the exact same `engine.sandbox.run_in_sandbox` path:
same non-root user (uid 10001), same `--cap-drop=ALL`/`--read-only`/no-new-privileges, same
egress-restricted network, same fail-closed isolation self-test. No sandbox hardening was
changed to add it.

## The config-dir design (one location, two very different runtimes)

Unlike sqlmap/Dalfox, nuclei does not key its state off `$HOME`. It resolves its config and
cache directories via Go's `os.UserConfigDir()`/`os.UserCacheDir()`, which prefer
`$XDG_CONFIG_HOME`/`$XDG_CACHE_HOME` over `$HOME/.config`/`$HOME/.cache` when set. The
Dockerfile points **both under `/tmp`** — `XDG_CONFIG_HOME=/tmp/.config`,
`XDG_CACHE_HOME=/tmp/.cache` — and pre-populates them at build time (a
`.templates-config.json` pointing `nuclei-templates-directory` at the bundled
`/opt/nuclei-templates` and recording its version, plus an empty-mapping uncover
`provider-config.yaml`). This single location satisfies two runtimes that need opposite
things:

1. **`-tv` / `-version` self-checks** run `docker run --read-only` with **no `--tmpfs`**.
   There the baked `/tmp/.config` files are present and read-only-readable, so nuclei
   reports the bundled templates version with zero writes and no network.
   `-disable-update-check` (passed on every scan) independently blocks any update call.

2. **A real scan** runs via `engine/sandbox.py`, which mounts a fresh **`--tmpfs /tmp`**
   with `HOME=/tmp`. That tmpfs *overlays* (hides) the baked `/tmp` files with an empty
   **writable** dir, so nuclei can create the config/cache files it insists on writing at
   scan start — `config.yaml`, `reporting-config.yaml`, `uncover/provider-config.yaml`, and
   the template cache `index.gob`. These MUST be writable; a real scan against a read-only
   XDG dir dies with `FTL … could not create config file`. `/tmp` (the sandbox's only
   writable mount) is therefore the only viable XDG location — **do not move XDG off `/tmp`**
   or real scans break. The scan always passes `-t /opt/nuclei-templates` explicitly, so
   template resolution never depends on the config nuclei regenerates on the fresh tmpfs.

> Why this changed from an earlier `/opt/nuclei-config` bake: `-tv`/`-version` only *read*
> config, so a read-only `/opt` bake passed those checks — but a real scan *writes* config
> and failed on the read-only rootfs. Since `engine/sandbox.py` is frozen and exposes
> exactly one writable path (`--tmpfs /tmp`, `HOME=/tmp`), the config dir has to live there.
> A harmless `[ERR] Could not read nuclei-ignore file … no such file or directory` may print
> on a real scan (the optional `.nuclei-ignore` isn't on the fresh tmpfs); the scan still
> completes and the JSONL results are unaffected.

The uncover `provider-config.yaml` is pre-baked because nuclei's bundled uncover package
unconditionally tries to create it on every startup regardless of flags; it must be a valid
(if empty) YAML mapping `{}` — a 0-byte file makes nuclei's YAML decoder fail with EOF (both
discovered by running as uid 10001, not assumed).

This means `-version`/`-tv` succeed under `--read-only` with **no `--tmpfs` at all**, while a
real scan gets a writable config via the tmpfs the sandbox already mounts.

## Verifying the image

```bash
bash docker/sandbox/build.sh

docker run --rm redsee-sandbox:latest nuclei -version                          # v3.11.0
docker run --rm redsee-sandbox:latest nuclei -tv -disable-update-check         # v10.4.5, offline
docker run --rm --read-only --user 10001 --network none \
    redsee-sandbox:latest nuclei -tv -disable-update-check                    # same, no writes at all

docker run --rm redsee-sandbox:latest sqlmap --version   # unaffected
docker run --rm redsee-sandbox:latest dalfox version     # unaffected
docker run --rm redsee-sandbox:latest id                 # uid=10001(redsee) — still non-root
```

To prove a **real scan** works under the exact hardening `engine/sandbox.py` applies
(read-only rootfs + writable tmpfs at `/tmp`, non-root), against a reachable target:

```bash
docker run --rm --network host \
    --cap-drop=ALL --security-opt=no-new-privileges --read-only \
    --tmpfs /tmp --env HOME=/tmp --user 10001 \
    redsee-sandbox:latest \
    nuclei -u http://TARGET/ -jsonl -disable-update-check -no-interactsh \
    -t /opt/nuclei-templates -tags tech,exposure,misconfig \
    -severity low,medium,high,critical -exclude-tags dos,intrusive,fuzz,brute,oob
# → prints one JSON object per match on stdout; exits 0. (`--network host` only for this
#   manual check; the real runner locks egress to the single target IP:port.)
```

`PYTHONPATH=. python -m pytest tests/test_sandbox.py -v` still passes unmodified
(`engine/sandbox.py` was not touched — the config-dir move is entirely inside the Dockerfile).

## Provenance of the pins

- **Engine (`NUCLEI_VERSION=v3.11.0`, sha256 `dc238d60...076283`):** downloaded from
  `github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_amd64.zip`,
  checksum matches the `nuclei_3.11.0_checksums.txt` ProjectDiscovery publishes alongside
  the release (independently re-verified by downloading and hashing the asset locally, not
  just trusting the checksums file).
- **Templates (`NUCLEI_TEMPLATES_VERSION=v10.4.5`, sha256 `34f5f8a2...8927`):** the
  nuclei-templates release ships no separate binary asset — its
  `nuclei-templates-10.4.5_checksums.txt` pins the sha256 of GitHub's own
  auto-generated tag source archive (`nuclei-templates-10.4.5.tar.gz`). The Dockerfile
  fetches that exact archive via `codeload.github.com/.../tar.gz/refs/tags/v10.4.5`
  (GitHub's stable, deterministic source-archive endpoint) and verifies it against that
  same pinned sha256 — confirmed locally to produce a byte-identical file to the checksums
  entry before baking this into the Dockerfile.
- **Template signatures:** spot-checked that extracted templates carry a trailing
  `# digest: ...` line (nuclei's own signing format, verified against nuclei's embedded
  public key at template-load time) — confirms these are the genuine, pre-signed official
  templates and load with no separate signing setup.

## httpx and tlsx (same ProjectDiscovery family, same fix — and one MORE fix)

`docker/sandbox/Dockerfile` also installs [httpx](https://github.com/projectdiscovery/httpx)
v1.9.0 and [tlsx](https://github.com/projectdiscovery/tlsx) v1.2.2 — pinned, official
GitHub releases, sha256-verified (`HTTPX_SHA256`/`TLSX_SHA256` in the Dockerfile), single
Go binaries at `/usr/local/bin/{httpx,tlsx}`. This is `projectdiscovery/httpx` (the Go
HTTP prober) — **not** the Python `httpx` library and **not** Kali's `httpx-toolkit` apt
package; `apt-get` is never used for either tool.

Both are the same Go-family shape as nuclei and hit the exact same config-dir problem:
they resolve config via `$XDG_CONFIG_HOME` (not `$HOME`) and each writes its own
`config.yaml` at startup. They share nuclei's `/tmp/.config`/`/tmp/.cache` design (see
above) — a pre-baked one-line `config.yaml` under `/tmp/.config/{httpx,tlsx}/` satisfies
read-only `-version` checks with zero writes, and the sandbox's real-scan tmpfs overlay
makes the same path writable when a scan actually runs. Confirmed by testing (not assumed)
that neither tool rewrites an existing `config.yaml` (mtime unchanged across repeated
runs), so the bake is never fought at scan time.

**Why httpx is pinned to v1.9.0, not the newer v1.10.0:** v1.10.0 makes an
**unconditional network call on every single run** — regardless of flags, including with
just `-status-code` alone — to download a ~92MB ML "page type" model from
`huggingface.co/datasets/happyhackingspace/dit`. `-disable-update-check` does **not** gate
it (that flag only covers httpx's own engine-update check). Discovered by running v1.10.0
with a minimal flag set and observing `INFO Model not found, downloading url=https://
huggingface.co/...` in the log even with `-silent` set. In the real hardened sandbox
(egress locked to the single target IP:port), that request would be DROPped by the
firewall, so every recon scan would first stall on a doomed connection to an unrelated
host before ever probing the target. v1.9.0 was independently downloaded, sha256-verified,
and confirmed clean — no such call, and its JSON `knowledgebase` object has no `PageType`
key — with the exact flag set `engine/recon_tools.py` uses. This mirrors the same
"pin to avoid a problematic behavior" pattern already used for Dalfox (pinned to v2.13.0 to
avoid the v3.x CLI rewrite).

Verified working under the exact `--read-only --tmpfs /tmp --env HOME=/tmp --user 10001`
sandbox flags with a real network probe (`httpx -target http://TARGET/ ...`,
`tlsx -host TARGET -port PORT ...`), not just `-version`. `-disable-update-check` is
required on every scan invocation for both, same as nuclei — no `-update`/auto-update is
ever baked or run.

```bash
docker run --rm redsee-sandbox:latest httpx -version   # v1.9.0
docker run --rm redsee-sandbox:latest tlsx -version    # v1.2.2
docker run --rm --read-only --user 10001 --network none redsee-sandbox:latest httpx -version
docker run --rm --read-only --user 10001 --network none redsee-sandbox:latest tlsx -version
```

## The agent layer (`engine/nuclei_agent.py`)

`run_nuclei_agent(targets, …)` drives the model over ONE harness-owned `run_nuclei` tool,
mirroring `engine/agent.py` (SQLi) and `engine/xss_agent.py` (XSS): scope-gate-first,
sandbox-only via `run_in_sandbox`, a fixed detection-only flag profile the model cannot
alter, evidence-gated parsing, per-candidate status, a bounded deterministic completion
pass, and a `stopped_reason`. The model supplies only a target, optional focus tags (from a
safe allowlist), and a free-text note; the harness builds the argv with the fixed flags
above and refuses any smuggled flag/tag or header injection. `status="found"` is derived
SOLELY from parsed nuclei `-jsonl` result lines — never from the model. See
`tests/test_nuclei_agent.py` (offline, real captured JSONL fixtures in
`tests/fixtures/nuclei_dvwa_real.jsonl`).

## Deterministic recon: httpx + tlsx (`engine/recon_tools.py`)

`run_httpx(targets, *, scope_config)` and `run_tlsx(targets, *, scope_config)` reuse
`engine/nuclei_agent.py`'s SHAPE — scope-gate-first (`assert_in_scope` before every
target), sandbox-only via `run_in_sandbox`, evidence-gated JSON parsing — but WITHOUT any
LLM, agent plan/act/observe loop, or `BudgetTracker`: each is ONE fixed, harness-built
command per target, run deterministically. There is nothing to sanitize/refuse from a
caller (no model in the loop), so the argv is entirely built by this module; a
`_assert_no_forbidden_flags` backstop still guards against a future coding regression.

httpx's fixed profile fingerprints status code, title, web server, tech stack, content
length, and CDN/TLS info (`-status-code -title -web-server -tech-detect -content-length
-cdn -tls-grab`), GET-only (`-x`/`-path`, i.e. other-method probing and path bruteforce,
are hard-forbidden). tlsx's fixed profile reports TLS version, cipher, serial, and
misconfigurations (`-tls-version -cipher -serial -expired -self-signed -mismatched`) plus a
**bounded** weak-cipher-only probe (`-cipher-enum -cipher-type weak` — not a full cipher
enumeration). `-san`/`-cn`/`-so` are deliberately omitted: this tlsx build rejects
combining them with any other probe flag, and the subject fields (`subject_cn`,
`subject_dn`, `subject_an`) already appear in the default JSON output regardless (Go's
`omitempty`), so nothing is lost. tlsx takes `-host`/`-port` (not a URL), so
`_host_port_from_target` derives them using the **exact same formula**
`engine.sandbox.run_in_sandbox` itself uses internally (`port = explicit URL port, else 443
for https, else 80`) — required so tlsx always probes the same port the sandbox's egress
firewall actually opens for that target.

`ReconObservation` (local, not in `schemas.py`) has `status ∈ {observed, error,
out_of_scope}` — no "clean" status: a successful probe with nothing to report yields **no**
observation for that target (not an error, not fabricated). Severity (`"Low"`/`"Medium"`,
same title-case convention as `Finding`) comes solely from real fields: httpx's
fingerprint rows are informational (`Low`); tlsx emits a baseline `tls-info` (`Low`) plus
one additional observation per detected condition — `tls-self-signed`,
`tls-expired`, `tls-hostname-mismatch`, `tls-weak-cipher` (all `Medium`) — read directly
from tlsx's own JSON booleans/lists, never inferred or fabricated. Covered by
`tests/test_recon_tools.py` against REAL captured JSON: `tests/fixtures/httpx_dvwa_real.jsonl`
(DVWA `:8080`) and `tests/fixtures/tlsx_selfsigned_real.jsonl` (a real self-signed
certificate, captured from a throwaway local TLS listener spun up just for that capture).

## Output surfacing (`engine/report_io.py` + `modules/recon.py`)

nuclei/httpx/tlsx results are ALL BROADER than the frozen `schemas.py` Finding enum
(SQLi/XSS/IDOR/BrokenAuth), so none of them are typed Findings (decision D-017).
`engine.report_io.write_outputs(...)` takes two optional params, both additive and
independently omittable:

- `nuclei_candidates=`: found candidates are added to the SARIF report (`ruleId` = nuclei
  `template_id`; SARIF level from nuclei severity — critical/high → `error`, medium →
  `warning`, low/info → `note`), the full raw list is written to `nuclei_<id>.json`, and a
  `nuclei` summary block (counts by status + by severity) is added to `run_<id>.json`.
- `recon_observations=`: observed rows are added to the SAME SARIF report (`ruleId` =
  recon `category`, e.g. `http-fingerprint`/`tls-self-signed`; SARIF level from the
  `Finding`-style title-case severity map — `Low`→`note`, `Medium`→`warning`), the full raw
  list is written to `recon_<id>.json`, and a `recon` summary block (counts by tool + by
  severity) is added to `run_<id>.json`.

`findings_<id>.json` stays typed-Finding-only and contains no nuclei/recon rows; with both
params omitted the existing SQLi/XSS output is byte-for-byte unchanged.
`modules/recon.py`'s `run_recon_scan(targets, …)` chains `run_nuclei_agent` +
`run_httpx` + `run_tlsx` → ONE `write_outputs(nuclei_candidates=…, recon_observations=…)`
call, and is invoked on its own (e.g. `python -m modules.recon`) — it is intentionally NOT
wired into `integration.py`'s resolver or the `scan_<vuln>` pipeline. Covered by
`tests/test_report_io.py` and `tests/test_recon_tools.py`.
