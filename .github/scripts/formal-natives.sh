#!/usr/bin/env bash
# formal-natives.sh <ref> : lay the Rust crates the implementation proofs verify (from the pca-rust repo at <ref>) where the
# proof harness crates expect them: sdks/{rust-pca,stark-pca,folding-pca,zkvm-pca}.
set -euo pipefail
REF="$1"; OWNER="${GITHUB_REPOSITORY_OWNER:-Atlas-Authorization}"; W="$RUNNER_TEMP/native-pca-rust"
git clone -q --depth 1 --branch "$REF" "https://github.com/$OWNER/pca-rust.git" "$W" \
  || { echo "::error::pca-rust has no ref '$REF' (push it to the same ref, or dispatch with native_ref)"; exit 1; }
echo "pca-rust @ $(git -C "$W" rev-parse HEAD)"
mkdir -p sdks
for p in atlas-pca:rust-pca stark-pca:stark-pca folding-pca:folding-pca zkvm-pca:zkvm-pca; do
  [ -d "$W/crates/${p%%:*}" ] && cp -R "$W/crates/${p%%:*}" "sdks/${p#*:}"
done
ls sdks
