#!/usr/bin/env bash
# docker/sandbox/build.sh
# Builds the RedSee sandbox image used by engine/sandbox.py.
# Usage: bash docker/sandbox/build.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building redsee-sandbox:latest from ${DIR}/Dockerfile ..."
docker build -t redsee-sandbox:latest "$DIR"
echo "Done. Image tagged redsee-sandbox:latest"
