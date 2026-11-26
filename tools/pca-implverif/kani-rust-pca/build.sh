#!/usr/bin/env bash
# Builds the Kani verification crate: src/lib.rs is a copy of sdks/rust-pca/src/lib.rs (only its few absolute `crate::` paths
# are rewritten to `crate::pca::`, as for the sibling modules below) plus ONE appended line declaring the proof module (a child
# module, so it can see private items). The library is not modified.
# The crate root is src/kroot.rs, which loads lib.rs as a module (#[path]) only to set the macro recursion limit.
set -euo pipefail
cd "$(dirname "$0")"
SRC=../../../sdks/rust-pca/src/lib.rs
# lib.rs is loaded as module `pca` by kroot.rs, so its own absolute `crate::x` paths (the intent_* delegates) become `crate::pca::x`
perl -pe 's/\bcrate::/crate::pca::/g' "$SRC" > src/lib.rs
printf '\n#[cfg(kani)]\nmod proofs;\n' >> src/lib.rs
# the crate's other source modules (lib.rs declares them: action_schema, intent_*, predicates, safe_regex, ...), unchanged
for m in ../../../sdks/rust-pca/src/*.rs; do
  # lib.rs is loaded as module `pca` by kroot.rs, so the sibling modules' absolute `crate::x` paths become `crate::pca::x`
  case "$(basename "$m")" in lib.rs) ;; *) perl -pe 's/\bcrate::/crate::pca::/g' "$m" > "src/$(basename "$m")" ;; esac
done
# directory modules (e.g. attest/) too, with the same rewrite
rm -rf src/attest
(cd ../../../sdks/rust-pca/src && find . -mindepth 2 -name '*.rs') | while read -r f; do
  mkdir -p "src/$(dirname "$f")"; perl -pe 's/\bcrate::/crate::pca::/g' "../../../sdks/rust-pca/src/$f" > "src/$f"
done
# the data files the library include_str!/include_bytes!s (tzdata, ontologies, circuit keys), byte-identical
(cd ../../../sdks/rust-pca/src && find . -type f ! -name '*.rs') | while read -r f; do
  mkdir -p "src/$(dirname "$f")"; cp "../../../sdks/rust-pca/src/$f" "src/$f"
done
cp ../../../sdks/rust-pca/Cargo.lock . 2>/dev/null || true
echo "lib.rs sha256 (source): $(shasum -a 256 $SRC 2>/dev/null || sha256sum $SRC)"
