#!/usr/bin/env bash
# Builds the Kani verification crate: src/lib.rs is a BYTE-IDENTICAL copy of sdks/rust-pca/src/lib.rs plus ONE appended
# line declaring the proof module (a child module, so it can see private items). The library is not modified.
# The crate root is src/kroot.rs, which loads lib.rs as a module (#[path]) only to set the macro recursion limit.
set -euo pipefail
cd "$(dirname "$0")"
SRC=../../../sdks/rust-pca/src/lib.rs
cp "$SRC" src/lib.rs
printf '\n#[cfg(kani)]\nmod proofs;\n' >> src/lib.rs
# the crate's other source modules (lib.rs declares them: action_schema, intent_*, predicates, safe_regex, ...), unchanged
for m in ../../../sdks/rust-pca/src/*.rs; do
  case "$(basename "$m")" in lib.rs) ;; *) cp "$m" src/ ;; esac
done
cp ../../../sdks/rust-pca/Cargo.lock . 2>/dev/null || true
echo "lib.rs sha256 (source): $(shasum -a 256 $SRC 2>/dev/null || sha256sum $SRC)"
