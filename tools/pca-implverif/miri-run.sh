#!/usr/bin/env bash
# miri-run.sh <crate-dir-under-/work/iv/sdks> <driver-file-under-tools/pca-implverif/miri> <test|-> [env assignments...]
# Copies the driver into the crate's tests/ (box copy only) and runs it under Miri. '-' runs all tests of the driver.
set -uo pipefail
export PATH=$HOME/.cargo/bin:$PATH
C="$1"; D="$2"; T="$3"; shift 3
cd /work/iv/sdks/$C
n=$(basename "$D" .rs); cp -f /work/iv/tools/pca-implverif/miri/$D tests/miri_$n.rs; cp -f /work/iv/tools/pca-implverif/miri/common.rs tests/miri_common.rs
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation -Zmiri-strict-provenance}"
export CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true
export CARGO_TARGET_DIR=/work/target-iv/miri-$(echo $C | tr / -)
for kv in "$@"; do export "$kv"; done
if [ "$T" = - ]; then cargo +nightly miri test --release ${MIRITARGET:+--target $MIRITARGET} --test miri_$n; else cargo +nightly miri test --release ${MIRITARGET:+--target $MIRITARGET} --test miri_$n -- --exact "$T"; fi
