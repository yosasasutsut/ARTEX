#!/usr/bin/env bash
# Run ARTEX tests fully isolated from the host (see docker-compose.sandbox.yml).
#
#   hardening/sandbox/run.sh                 # build + vet + test ./...  (go test -p 1)
#   PKG=./hardening/... hardening/sandbox/run.sh    # scope to one package
#   PKG="./hardening/... ./notify" hardening/sandbox/run.sh
#   GOTESTFLAGS="-run Allowlist -p 1 -v" PKG=./hardening/... hardening/sandbox/run.sh
#
#   APPLY_PATCHES=0 hardening/sandbox/run.sh   # test the plain upstream tree
#
# Nothing runs on the host Go toolchain and nothing binds host ports. The test
# network is internal (no internet); modules are pre-fetched into a cache volume.
set -euo pipefail
cd "$(dirname "$0")"

CMP="docker compose -f docker-compose.sandbox.yml -p artex-sandbox"

cleanup() { $CMP down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[sandbox] priming module cache (one network-enabled step)..."
$CMP run --rm modcache

echo "[sandbox] running build + vet + test (internal network, ephemeral postgres)..."
$CMP run --rm tests
