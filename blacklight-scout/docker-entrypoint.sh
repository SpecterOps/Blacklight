#!/usr/bin/env bash
# Runs inside the Scout build image against a repo bind-mounted at /src.
set -euo pipefail

if [[ ! -f /src/blacklight-scout/Makefile ]]; then
  echo "error: mount the Blacklight repo at /src (expected blacklight-scout/Makefile)." >&2
  exit 2
fi

cd /src
exec make -C blacklight-scout release-local
