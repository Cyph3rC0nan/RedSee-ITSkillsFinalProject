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
