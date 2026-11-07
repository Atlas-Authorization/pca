#!/usr/bin/env bash
# Idempotent: builds the compliance circuit's test fixtures in circuits/build/ if they are missing, so the Groth16 tests
# pass on any Linux x86-64 machine (CI, a build box) without a manual step. Exits non-zero if it cannot (never skips).
#   Uses $CIRCOM, else circom on PATH, else downloads the pinned release below (sha256-checked) into circuits/build/.tools.
#   Other platforms: install circom 2.2.x and set CIRCOM=/path/to/circom.
set -euo pipefail
cd "$(dirname "$0")/.."
B=circuits/build
if [ -f "$B/verification_key.json" ] && [ -f "$B/compliance_final.zkey" ] && [ -f "$B/compliance_js/compliance.wasm" ]; then exit 0; fi

CIRCOM="${CIRCOM:-$(command -v circom || true)}"
if [ -z "$CIRCOM" ]; then
  if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
    echo "circom not found: install circom 2.2.x and set CIRCOM=/path/to/circom (auto-download is Linux x86-64 only)" >&2; exit 1
  fi
  mkdir -p "$B/.tools"; CIRCOM="$B/.tools/circom"
  curl -fsSL -o "$CIRCOM" https://github.com/iden3/circom/releases/download/v2.2.2/circom-linux-amd64
  echo "f3d8d1fdbc123779b80e210c909ee941d7a1e130c70365524646b48b8b0fe9d5  $CIRCOM" | sha256sum -c - >&2
  chmod +x "$CIRCOM"
fi
PCA_DEV_SETUP=1 CIRCOM="$CIRCOM" bash circuits/setup.sh >&2
