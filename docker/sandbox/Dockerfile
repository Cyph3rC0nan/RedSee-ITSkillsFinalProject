# docker/sandbox/Dockerfile
# RedSee sandbox image — Layer 2 isolation boundary.
# Throwaway container that runs active tools (sqlmap, dalfox, ...) with NO host
# access beyond the single resolved target IP:port. curl is included solely for
# the isolation self-test performed by engine/sandbox.py.
#
# Build:  bash docker/sandbox/build.sh   (tags redsee-sandbox:latest)
#
# Runtime hardening (--cap-drop=ALL, --read-only, --pids-limit, egress firewall,
# etc.) is applied by engine/sandbox.py at `docker run` time, NOT baked here.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        sqlmap \
        curl \
        ca-certificates \
        unzip \
 && rm -rf /var/lib/apt/lists/*

# Dalfox (reflected/DOM XSS scanner) — a single Go binary. Pinned to the last
# release (v2.13.0) BEFORE the v3.x rewrite: v3.x changed the CLI entirely
# (no `version`/`url` subcommands, different flags), while v2.13.0 keeps the
# classic `dalfox version` / `dalfox url TARGET` interface and the documented
# [POC]/[VULN] output format the next prompt's parser will target. Downloaded
# from the official GitHub release and verified against a pinned sha256 (NOT
# `go install`, to keep the image small/reproducible and avoid a Go toolchain
# layer).
# See docs/dalfox_sandbox.md for: the verification commands, a real captured
# ground-truth run through engine.sandbox.run_in_sandbox, and the exact
# [POC]/[V] output format (sourced from dalfox's own printing package) a
# future parser should target.
ARG DALFOX_VERSION=v2.13.0
ARG DALFOX_SHA256=083fa42856cac58054ff1ffff98d232fd2643b9b375113fba2761213bfb227a0
RUN curl -fsSL -o /tmp/dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/${DALFOX_VERSION}/dalfox-linux-amd64.tar.gz" \
 && echo "${DALFOX_SHA256}  /tmp/dalfox.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/dalfox.tar.gz -C /tmp \
 && install -m 0755 /tmp/dalfox-linux-amd64 /usr/local/bin/dalfox \
 && rm -f /tmp/dalfox.tar.gz /tmp/dalfox-linux-amd64 \
 && dalfox version

# nuclei (template-based vulnerability scanner) — a single Go binary. Pinned
# to v3.11.0, the current stable v3 release (NOT `go install`/@latest — same
# reproducibility rationale as sqlmap/Dalfox above). Downloaded from the
# official GitHub release and verified against a pinned sha256 (taken from
# ProjectDiscovery's own nuclei_3.11.0_checksums.txt for this exact tag).
ARG NUCLEI_VERSION=v3.11.0
ARG NUCLEI_SHA256=dc238d6040813e14fc30514dac5a2eb1b430c694f3ca99eee2a5097e55076283
RUN curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" \
 && echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c - \
 && unzip -q /tmp/nuclei.zip -d /tmp/nuclei-extract \
 && install -m 0755 /tmp/nuclei-extract/nuclei /usr/local/bin/nuclei \
 && rm -rf /tmp/nuclei.zip /tmp/nuclei-extract \
 && nuclei -version

# httpx (HTTP prober/fingerprinter) — a single Go binary, same ProjectDiscovery
# family as nuclei. Pinned to v1.9.0, NOT the newer v1.10.0 (and NOT
# `go install`/@latest): v1.10.0 makes an UNCONDITIONAL network call on every
# single run (regardless of flags — `-disable-update-check` does NOT gate it) to
# download a ~92MB ML "page type" model from
# huggingface.co/datasets/happyhackingspace/dit — verified by running v1.10.0 with
# minimal flags (`-status-code` alone) and seeing `INFO Model not found,
# downloading url=https://huggingface.co/...`. In the real hardened sandbox
# (egress locked to the single target IP:port), that request is DROPped by the
# firewall, so every recon scan would first stall on a doomed connection to an
# unrelated host before ever probing the target. v1.9.0 was independently
# downloaded, sha256-verified, and confirmed CLEAN (no such call, and its JSON
# `knowledgebase` object has no `PageType` key) with the exact flag set this
# image's recon runner uses. Downloaded from the official GitHub release and
# verified against a pinned sha256 (taken from ProjectDiscovery's own
# httpx_1.9.0_checksums.txt for this exact tag). This is projectdiscovery/httpx
# (the Go prober) — NOT the Python "httpx" library and NOT the Kali
# "httpx-toolkit" apt package.
ARG HTTPX_VERSION=v1.9.0
ARG HTTPX_SHA256=54c6c91d61d3b82ba79f93633df04bb547f0c954d9d9b0fb8bcedf158f85ff2f
RUN curl -fsSL -o /tmp/httpx.zip \
        "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip" \
 && echo "${HTTPX_SHA256}  /tmp/httpx.zip" | sha256sum -c - \
 && unzip -q /tmp/httpx.zip -d /tmp/httpx-extract \
 && install -m 0755 /tmp/httpx-extract/httpx /usr/local/bin/httpx \
 && rm -rf /tmp/httpx.zip /tmp/httpx-extract \
 && httpx -version

# tlsx (TLS/certificate inspector) — a single Go binary, same ProjectDiscovery
# family as nuclei/httpx. Pinned to v1.2.2, the current stable release (NOT
# `go install`/@latest). Downloaded from the official GitHub release and
# verified against a pinned sha256 (taken from ProjectDiscovery's own
# tlsx_1.2.2_checksums.txt for this exact tag).
ARG TLSX_VERSION=v1.2.2
ARG TLSX_SHA256=6c4a0dff8473e954d3aa9b6c0cc9c68047cc7e2fb607fa94359f4ec55ef3f98c
RUN curl -fsSL -o /tmp/tlsx.zip \
        "https://github.com/projectdiscovery/tlsx/releases/download/${TLSX_VERSION}/tlsx_${TLSX_VERSION#v}_linux_amd64.zip" \
 && echo "${TLSX_SHA256}  /tmp/tlsx.zip" | sha256sum -c - \
 && unzip -q /tmp/tlsx.zip -d /tmp/tlsx-extract \
 && install -m 0755 /tmp/tlsx-extract/tlsx /usr/local/bin/tlsx \
 && rm -rf /tmp/tlsx.zip /tmp/tlsx-extract \
 && tlsx -version

# nuclei-templates — the official, pre-signed template set nuclei runs.
# Pinned to v10.4.5 and baked into the image at BUILD time so a scan needs NO
# network to fetch templates and `nuclei -update-templates`/`-ut` never runs.
# Official templates are individually signed (each file carries a trailing
# `# digest:` line, verified against nuclei's own embedded public key at load
# time), so this bundled tag loads and verifies fully offline with no extra
# signing setup on our side.
# Fetched as GitHub's auto-generated source archive for this exact tag —
# byte-identical to (and sha256-verified against) the
# nuclei-templates-10.4.5_checksums.txt entry ProjectDiscovery publishes
# alongside the v10.4.5 release (that release ships no separate binary
# asset; the checksums file itself is the pin).
ARG NUCLEI_TEMPLATES_VERSION=v10.4.5
ARG NUCLEI_TEMPLATES_SHA256=34f5f8a24400a4fff33a57806c2fbc842cdf599589f477430800140845e299cb
RUN curl -fsSL -o /tmp/nuclei-templates.tar.gz \
        "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/${NUCLEI_TEMPLATES_VERSION}" \
 && echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/nuclei-templates \
 && tar -xzf /tmp/nuclei-templates.tar.gz -C /opt/nuclei-templates --strip-components=1 \
 && rm -f /tmp/nuclei-templates.tar.gz

# ffuf (Go web fuzzer / directory brute-forcer) — a single Go binary. Pinned to
# v2.1.0, the current stable release (NOT `go install`/@latest, NOT apt — same
# reproducibility rationale as sqlmap/Dalfox/nuclei above). Downloaded from the
# official GitHub release and verified against a pinned sha256 (taken from
# ffuf's own ffuf_2.1.0_checksums.txt for this exact tag; independently
# re-downloaded and re-hashed locally before pinning here, not just trusting
# the checksums file).
ARG FFUF_VERSION=v2.1.0
ARG FFUF_SHA256=fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5
RUN curl -fsSL -o /tmp/ffuf.tar.gz \
        "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_amd64.tar.gz" \
 && echo "${FFUF_SHA256}  /tmp/ffuf.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/ffuf.tar.gz -C /tmp \
 && install -m 0755 /tmp/ffuf /usr/local/bin/ffuf \
 && rm -f /tmp/ffuf.tar.gz /tmp/ffuf \
 && ffuf -V

# Wordlist for ffuf — a SINGLE small web-content list (NOT a full SecLists
# clone, which is ~1GB). SecLists (github.com/danielmiessler/SecLists) is
# MIT-licensed. Fetched as a raw file pinned to one exact commit (the commit
# the `2026.1` tag resolved to at pin time — a commit sha is immutable even if
# a tag is later moved/deleted, so this is the strongest pin `raw.githubusercontent.com`
# supports for a single file), sha256-verified, independently re-downloaded and
# re-hashed locally before pinning here. ~4750 lines of common directory/file
# names, used offline with no `git clone`/network access at scan time.
ARG SECLISTS_COMMIT=190c6f7bd58c847ceadfe57d9853592737f059e8
ARG SECLISTS_TAG=2026.1
ARG WORDLIST_SHA256=fc320bacd30d93f5080029912b93667cd739401f81634579a7125fc0c027e6d5
RUN mkdir -p /opt/wordlists \
 && curl -fsSL -o /opt/wordlists/common.txt \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Discovery/Web-Content/common.txt" \
 && echo "${WORDLIST_SHA256}  /opt/wordlists/common.txt" | sha256sum -c - \
 && chmod -R a+rX /opt/wordlists

# Parameter-name wordlist for COMMON-PARAMETER SEEDING (D-025/D-026) — the host-side
# orchestrator (engine/params.py) pairs a discovered, parameter-LESS API path with
# these names to build (url, param) injection candidates when the crawler can't see
# a param (JSON API, no HTML form). Bundled here too so the image is the single
# reproducible source of truth for the list (parity with common.txt above).
#   Source:  curated by hand — the highest-signal entries of Arjun's db/params.txt
#            (github.com/s0md3v/Arjun, MIT) + SecLists' burp-parameter-names.txt
#            (github.com/danielmiessler/SecLists, MIT), ordered by signal
#            (search/query params first, then ids, then generic). D-026 SHRANK
#            this from a 297-name list to 25: on an 8 GB host running Juice Shop
#            alongside the scan, seeding more params/paths -> more sandboxed
#            sqlmap/Dalfox runs -> real memory pressure (confirmed: Juice Shop's
#            OWN Node heap OOM'd under a wide seed sweep). 25 still covers every
#            practical param name (q/id/search/... incl. the confirmed
#            /rest/products/search SQLi's `q`) while keeping the caps in
#            modules/scan.py's ScanProfile tight (see _SEED_MAX_* / seed_paths).
#   File:    docker/sandbox/params.txt (ships IN THIS REPO, not downloaded — a
#            curated subset isn't a single upstream file; the repo copy IS the pin).
#   Count:   25 unique names   Sha256 (verified at build):
#            42706bec64083e8c0de713d8be82e69d0a781a8239a17b432dfeee014c078857
COPY params.txt /opt/wordlists/params.txt
RUN echo "42706bec64083e8c0de713d8be82e69d0a781a8239a17b432dfeee014c078857  /opt/wordlists/params.txt" | sha256sum -c - \
 && chmod a+rX /opt/wordlists/params.txt

# Shared ProjectDiscovery config/cache dirs (nuclei, httpx, tlsx). None of these
# Go tools key their state off $HOME — they resolve it via
# $XDG_CONFIG_HOME/$XDG_CACHE_HOME (Go's os.UserConfigDir/UserCacheDir). We point
# BOTH under /tmp and pre-populate them at BUILD time. This one location
# satisfies two very different runtimes:
#
#   1. `-version`/`-tv` self-checks run `docker run --read-only` with NO tmpfs
#      (see docs/nuclei_sandbox.md). There the baked /tmp files are present and
#      read-only-readable, so each tool starts with zero writes and no network.
#      The pre-baked nuclei .templates-config.json tells it the bundled
#      /opt/nuclei-templates IS the installed set at NUCLEI_TEMPLATES_VERSION;
#      `-disable-update-check` (passed on every scan, all three tools) independently
#      blocks any update/version network call.
#
#   2. A REAL scan runs via engine/sandbox.py, which mounts a fresh `--tmpfs /tmp`
#      and sets HOME=/tmp. That tmpfs OVERLAYS (hides) the baked /tmp files with
#      an empty WRITABLE dir, so each tool can create the config/cache files it
#      insists on writing at scan start — nuclei's config.yaml/
#      reporting-config.yaml/uncover provider-config.yaml + template cache
#      index.gob, and httpx's/tlsx's own config.yaml — which a real scan MUST
#      write and could not if XDG pointed at the --read-only rootfs. nuclei scans
#      always pass `-t /opt/nuclei-templates` explicitly, so template resolution
#      never depends on the regenerated config. This is the only writable path
#      the hardened sandbox exposes; do NOT move XDG off /tmp or real scans fail
#      with `could not create config file` on the read-only fs.
#
# The uncover provider-config.yaml is pre-baked because nuclei's bundled uncover
# package unconditionally tries to create it on EVERY startup (regardless of
# flags); it must be a valid (if empty) YAML mapping `{}` — a 0-byte file makes
# nuclei's YAML decoder fail with EOF (both discovered by running as uid 10001,
# not assumed). httpx/tlsx each write their own single config.yaml at startup
# (goflags-generated) — a pre-baked one-line comment file is enough for both (a
# 0-byte file works too, but a real comment line documents intent); confirmed by
# running both read-only that neither rewrites an existing config.yaml (mtime
# unchanged), so the bake is never fought at scan time.
RUN mkdir -p /tmp/.config/nuclei /tmp/.config/uncover /tmp/.config/httpx \
      /tmp/.config/tlsx /tmp/.cache/nuclei \
 && printf '%s' \
      '{"nuclei-templates-directory":"/opt/nuclei-templates",' \
      > /tmp/.config/nuclei/.templates-config.json \
 && printf '%s' \
      '"custom-s3-templates-directory":"/opt/nuclei-templates/s3",' \
      '"custom-github-templates-directory":"/opt/nuclei-templates/github",' \
      '"custom-gitlab-templates-directory":"/opt/nuclei-templates/gitlab",' \
      '"custom-azure-templates-directory":"/opt/nuclei-templates/azure",' \
      "\"nuclei-templates-version\":\"${NUCLEI_TEMPLATES_VERSION}\"," \
      "\"nuclei-latest-version\":\"${NUCLEI_VERSION}\"," \
      "\"nuclei-templates-latest-version\":\"${NUCLEI_TEMPLATES_VERSION}\"}" \
      >> /tmp/.config/nuclei/.templates-config.json \
 && printf '{}\n' > /tmp/.config/uncover/provider-config.yaml \
 && printf '# redsee pre-baked httpx config (goflags-generated)\n' \
      > /tmp/.config/httpx/config.yaml \
 && printf '# redsee pre-baked tlsx config (goflags-generated)\n' \
      > /tmp/.config/tlsx/config.yaml \
 && chmod -R a+rwX /tmp/.config /tmp/.cache \
 && chmod -R a+rX /opt/nuclei-templates
ENV XDG_CONFIG_HOME=/tmp/.config
ENV XDG_CACHE_HOME=/tmp/.cache

# Non-root user — the scanning process never runs as root.
RUN useradd --create-home --uid 10001 redsee
USER 10001:10001
WORKDIR /home/redsee

# sqlmap and curl need a writable HOME; the runner mounts a tmpfs and points
# HOME at it (--env HOME=/tmp) so the root filesystem can stay --read-only.
ENV HOME=/tmp

# No fixed ENTRYPOINT — the runner passes the full argv (e.g. `sqlmap ...`)
# directly, and overrides with `--entrypoint /bin/sh` for the isolation probe.
ENTRYPOINT []
CMD ["sqlmap", "--version"]
