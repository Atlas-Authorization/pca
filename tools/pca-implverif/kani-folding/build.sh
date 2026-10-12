#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"; SRC=../../../sdks/folding-pca/src/lib.rs
cp "$SRC" src/lib.rs; printf '\n#[cfg(kani)]\nmod proofs;\n' >> src/lib.rs
cp ../../../sdks/folding-pca/Cargo.lock . 2>/dev/null || true
echo "lib.rs sha256 (source): $(sha256sum $SRC)"
