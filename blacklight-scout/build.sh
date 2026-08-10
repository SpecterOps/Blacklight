#!/usr/bin/env bash
# Host wrapper: build Scout Windows/Linux matrix with Docker only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE="${SCOUT_BUILD_IMAGE:-blacklight-scout-build}"
DOCKER="${DOCKER:-docker}"

if ! command -v "${DOCKER}" >/dev/null 2>&1; then
  echo "error: Docker is required (${DOCKER} not found on PATH)." >&2
  exit 2
fi

cd "${REPO_DIR}"
"${DOCKER}" build -t "${IMAGE}" -f blacklight-scout/Dockerfile blacklight-scout
"${DOCKER}" run --rm -v "${REPO_DIR}:/src" -w /src "${IMAGE}"
