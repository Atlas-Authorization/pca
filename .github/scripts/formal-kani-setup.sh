#!/usr/bin/env bash
# formal-kani-setup.sh : cargo-kani at the TOOLCHAIN.lock version (+ `cargo kani setup`, which fetches its pinned nightly and CBMC).
set -euo pipefail
. ./TOOLCHAIN.lock
if ! cargo kani --version 2>/dev/null | grep -q "$KANI_VERSION"; then
  cargo install --locked --force kani-verifier --version "$KANI_VERSION"   # --force: a partial cache may hold the binary
fi
cargo kani setup >/dev/null 2>&1 || cargo kani setup
cargo kani --version
