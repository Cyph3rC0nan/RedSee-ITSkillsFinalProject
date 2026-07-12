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

## Output surfacing (`engine/report_io.py` + `modules/recon.py`)

nuclei results are BROADER than the frozen `schemas.py` Finding enum
(SQLi/XSS/IDOR/BrokenAuth), so they are DELIBERATELY not typed Findings (decision D-017).
`engine.report_io.write_outputs(...)` takes an optional `nuclei_candidates=`: found
candidates are added to the SARIF report (`ruleId` = nuclei `template_id`; SARIF level from
nuclei severity — critical/high → `error`, medium → `warning`, low/info → `note`), the full
raw list is written to `nuclei_<id>.json`, and a `nuclei` summary block (counts by status +
by severity) is added to `run_<id>.json`. `findings_<id>.json` stays typed-Finding-only and
contains no nuclei rows; with `nuclei_candidates` omitted the existing SQLi/XSS output is
byte-for-byte unchanged. `modules/recon.py`'s `run_recon_scan(targets, …)` chains
`run_nuclei_agent` → `write_outputs(nuclei_candidates=…)` and is invoked on its own (e.g.
`python -m modules.recon`) — it is intentionally NOT wired into `integration.py`'s resolver
or the `scan_<vuln>` pipeline. Covered by `tests/test_report_io.py`.
