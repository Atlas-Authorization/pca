#!/usr/bin/env bash
# src/ = byte-identical copy of sdks/zkvm-pca/core/src + appended proof-module declarations (lib.rs, chain.rs); library files otherwise untouched.
set -euo pipefail
cd "$(dirname "$0")"; SRC=../../../sdks/zkvm-pca/core/src
for f in $SRC/*.rs; do cp "$f" src/$(basename "$f"); done
printf '\n#[cfg(kani)]\nmod proofs;\n' >> src/lib.rs
printf '\n#[cfg(kani)]\nmod kproofs {\n    use super::*;\n    include!("proofs_chain.rs");\n}\n' >> src/chain.rs
for f in $SRC/*.rs; do echo "$(basename $f) sha256: $(sha256sum $f | cut -d' ' -f1)"; done
