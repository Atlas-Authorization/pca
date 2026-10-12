#!/usr/bin/env bash
# Run the REAL-Envoy ext_authz integration tests (HTTP service + gRPC) for @atlasauth/pca-gateway.
#
#   scripts/run-envoy-ext-authz.sh                 # use $PCA_ENVOY_BIN, else download an Envoy (below)
#   PCA_ENVOY_BIN=/path/to/envoy scripts/run-envoy-ext-authz.sh
#   PCA_ENVOY_CAPTURE=$PWD/fixtures scripts/run-envoy-ext-authz.sh   # re-capture CheckRequest fixtures
#                                                                   # (then refresh sha256 in fixtures/PROVENANCE.json)
#
# Envoy has no official macOS/Windows release. When PCA_ENVOY_BIN is unset this fetches the community
# archive (tetratelabs/archive-envoy, the binaries func-e uses) for this OS/arch into $PCA_ENVOY_CACHE
# (default ~/.cache/pca-envoy) and verifies a pinned tarball sha256 (refuses when none is pinned). Nothing is installed globally.
# No Docker is used. The tests bind 127.0.0.1 on ephemeral ports only.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${PCA_ENVOY_VERSION:-v1.39.3}"
CACHE="${PCA_ENVOY_CACHE:-$HOME/.cache/pca-envoy}"

if [ -z "${PCA_ENVOY_BIN:-}" ]; then
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo "unsupported arch $arch" >&2; exit 2 ;; esac
  case "$os" in darwin|linux) ;; *) echo "unsupported OS $os" >&2; exit 2 ;; esac
  name="envoy-${VERSION}-${os}-${arch}"
  dir="$CACHE/$name"
  if [ ! -x "$dir/bin/envoy" ]; then
    mkdir -p "$dir"
    # Pinned sha256 of every tarball this script will unpack (v1.39.3). Any other version/platform is
    # refused unless the caller supplies PCA_ENVOY_SHA256 for the exact tarball they intend to run.
    case "$name" in
      envoy-v1.39.3-darwin-arm64) want="e48fff9d9b88ce7c34150b8af4138e38ae2b83af10ce927e735840023deaf312" ;;
      envoy-v1.39.3-linux-amd64)  want="fdd0c56be9962283ce027123916f868246590e620c7355914ce3f43a7658b151" ;;
      envoy-v1.39.3-linux-arm64)  want="64c0e9c1678c13c032ce909f4e2d046b73528e695e390d6323b3b7b3077797d8" ;;
      *) want="${PCA_ENVOY_SHA256:-}" ;;
    esac
    if [ -z "$want" ]; then
      echo "no pinned sha256 for $name; set PCA_ENVOY_SHA256 or PCA_ENVOY_BIN" >&2
      exit 2
    fi
    url="https://github.com/tetratelabs/archive-envoy/releases/download/${VERSION}/${name}.tar.xz"
    echo "downloading $url" >&2
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/e.tar.xz" "$url"
    if ! echo "$want  $tmp/e.tar.xz" | shasum -a 256 -c - >&2; then
      echo "sha256 mismatch for $name; refusing to unpack" >&2
      rm -rf "$tmp"
      exit 3
    fi
    tar -xJf "$tmp/e.tar.xz" -C "$CACHE"
    rm -rf "$tmp"
  fi
  PCA_ENVOY_BIN="$dir/bin/envoy"
fi

"$PCA_ENVOY_BIN" --version >&2
cd "$HERE"
PCA_ENVOY_BIN="$PCA_ENVOY_BIN" exec npx vitest run src/envoy.integration.test.ts "$@"
