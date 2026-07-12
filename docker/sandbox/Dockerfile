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

# nuclei's config/cache dirs. Unlike sqlmap/dalfox, nuclei does NOT key these
# off $HOME — it resolves them via $XDG_CONFIG_HOME/$XDG_CACHE_HOME (Go's
# os.UserConfigDir/UserCacheDir). We point BOTH under /tmp and pre-populate them
# at BUILD time. This one location satisfies two very different runtimes:
#
#   1. `-tv` / `-version` self-checks run `docker run --read-only` with NO tmpfs
#      (see docs/nuclei_sandbox.md). There the baked /tmp files are present and
#      read-only-readable, so nuclei reports the bundled templates version with
#      zero writes and no network. The pre-baked .templates-config.json tells it
#      the bundled /opt/nuclei-templates IS the installed set at
#      NUCLEI_TEMPLATES_VERSION; `-disable-update-check` (passed on every scan)
#      independently blocks any update/version network call.
#
#   2. A REAL scan runs via engine/sandbox.py, which mounts a fresh `--tmpfs /tmp`
#      and sets HOME=/tmp. That tmpfs OVERLAYS (hides) the baked /tmp files with
#      an empty WRITABLE dir, so nuclei can create the config/cache files it
#      insists on writing at scan start — config.yaml, reporting-config.yaml, the
#      uncover provider-config.yaml, and the template cache index.gob — which a
#      real scan MUST write and could not if XDG pointed at the --read-only
#      rootfs. The scan always passes `-t /opt/nuclei-templates` explicitly, so
#      template resolution never depends on the regenerated config. This is the
#      only writable path the hardened sandbox exposes; do NOT move XDG off /tmp
#      or real scans fail with `could not create config file` on the read-only fs.
#
# The uncover provider-config.yaml is pre-baked because nuclei's bundled uncover
# package unconditionally tries to create it on EVERY startup (regardless of
# flags); it must be a valid (if empty) YAML mapping `{}` — a 0-byte file makes
# nuclei's YAML decoder fail with EOF (both discovered by running as uid 10001,
# not assumed).
RUN mkdir -p /tmp/.config/nuclei /tmp/.config/uncover /tmp/.cache/nuclei \
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
