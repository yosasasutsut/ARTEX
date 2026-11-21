#!/usr/bin/env bash
# Build the hardened ARTEX image without changing any upstream file in the
# working tree.
#
#   hardening/build.sh                 # builds artex:local from HEAD + patches
#   ARTEX_VERSION=v0.7.0-mine hardening/build.sh
#   ARTEX_IMAGE=artex:hardened hardening/build.sh
#
# It exports the committed tree to a temporary directory, applies
# hardening/patches/*.patch there, and runs `docker build` on that copy. The
# checkout itself stays identical to what is committed. Needs git and docker;
# no Go or Node toolchain on the host.
#
# Uncommitted changes are NOT included: commit first.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
IMAGE="${ARTEX_IMAGE:-artex:local}"
VERSION="${ARTEX_VERSION:-$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo dev)-hardened}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[hardening] exporting $(git -C "$ROOT" rev-parse --short HEAD) to a temporary build context"
# checkout-index writes every tracked file (git archive would drop the paths the
# upstream .gitattributes marks export-ignore). autocrlf is forced off so the
# files keep LF endings on Windows and the patches apply.
git -C "$ROOT" -c core.autocrlf=false -c core.eol=lf checkout-index --all --force --prefix="$TMP/"

cd "$TMP"
for p in hardening/patches/*.patch; do
  echo "[hardening] applying $p"
  git apply --whitespace=nowarn "$p"
done

echo "[hardening] building $IMAGE (version $VERSION)"
docker build --build-arg "ARTEX_VERSION=$VERSION" -t "$IMAGE" .

echo "[hardening] building artex-egress-fw:local"
docker build -t artex-egress-fw:local hardening/egress-fw

echo "[hardening] done. Start with:"
echo "  docker compose -f docker-compose.yml -f hardening/docker-compose.hardened.yml up -d --no-build"
