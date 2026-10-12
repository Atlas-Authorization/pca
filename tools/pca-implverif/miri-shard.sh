#!/usr/bin/env bash
# miri-shard.sh <test> [shard]   Runs ONE rust-pca conformance test (or corpus shard of `vectors`) under Miri on the box.
# Corpus is pre-split (miri/gen-corpus.py -> /work/iv/corpus) because parsing the 2 MB vectors.json under Miri takes tens of minutes.
# Miri flags: -Zmiri-disable-isolation (corpus files), strict provenance ON (symbolic-alignment-check dropped: false positive in memchr, see doc). Overflow checks + debug assertions ON.
set -uo pipefail
export PATH=$HOME/.cargo/bin:$PATH
cd /work/iv/sdks/rust-pca
cp -f /work/iv/sdks/rust-pca/proofs/miri_shard.rs tests/miri_shard.rs
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation -Zmiri-strict-provenance}"
export CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true
export CARGO_TARGET_DIR=/work/target-iv/miri-rp CORPUS_DIR=/work/iv/corpus
T="${1:?test}"; export SHARD="${2:-0}"
cargo +nightly miri test --release --test miri_shard -- --exact "$T"
