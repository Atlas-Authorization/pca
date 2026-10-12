#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"; SRC=../../../sdks/stark-pca-plonky3/src/lib.rs
cp "$SRC" src/lib.rs; printf '\n#[cfg(kani)]\nmod proofs;\n' >> src/lib.rs
cp ../../../sdks/stark-pca-plonky3/Cargo.lock . 2>/dev/null || true
echo "lib.rs sha256 (source): $(sha256sum $SRC)"
