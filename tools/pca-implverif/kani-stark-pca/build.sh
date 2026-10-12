#!/usr/bin/env bash
# lib.rs = byte-identical copy of sdks/stark-pca/src/lib.rs + one appended line declaring the proof module.
set -euo pipefail
cd "$(dirname "$0")"
SRC=../../../sdks/stark-pca/src/lib.rs
cp "$SRC" src/lib.rs
printf '\n#[cfg(kani)]\nmod proofs;\n' >> src/lib.rs
cp ../../../sdks/stark-pca/Cargo.lock . 2>/dev/null || true
echo "lib.rs sha256 (source): $(shasum -a 256 $SRC 2>/dev/null || sha256sum $SRC)"
