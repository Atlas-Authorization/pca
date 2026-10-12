#!/usr/bin/env bash
# miri-q.sh <crate dir under sdks/> <driver file under tools/pca-implverif/miri/> [target] [test]   (queue job; run from the repo root)
# [test]: run only that test (exact name) of the driver; '-' or absent = all tests.
# Installs nightly + miri on demand (flock), copies the driver into the crate's tests/ (job-private snapshot only) and runs it under Miri.
set -uo pipefail
export PATH=$HOME/.cargo/bin:$PATH
C="$1"; D="$2"; TGT="${3:-}"; [ "$TGT" = - ] && TGT=; TST="${4:-}"; [ "$TST" = - ] && TST=; R="$(pwd)"; TC="${MIRI_TC:-nightly-2026-10-08}"   # pinned: the toolchain the rust-pca Miri runs used; current nightly ICEs on p3-goldilocks
export XDG_CACHE_HOME=/tmp/xdg-cache   # job-private Miri sysroot (the shared ~/.cache/miri was corrupted by concurrent jobs)
flock $HOME/.miri-install.lock bash -c "
  ok() { cargo +$TC --version >/dev/null 2>&1 && rustup component list --toolchain $TC --installed 2>/dev/null | grep -q '^miri' && rustup component list --toolchain $TC --installed | grep -q '^rust-src'; }
  ok || { rustup toolchain uninstall $TC >/dev/null 2>&1; rustup toolchain install $TC --profile minimal -c cargo -c miri -c rust-src >/dev/null 2>&1; }
  rustup component add --toolchain $TC rustc cargo rust-std rust-src miri >/dev/null 2>&1   # idempotent; repairs a partial install
  rustc +$TC --print sysroot >/dev/null && ls \$(rustc +$TC --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-* >/dev/null 2>&1 || { rustup toolchain uninstall $TC; rustup toolchain install $TC --profile minimal -c cargo -c miri -c rust-src; } >/dev/null 2>&1
  ${TGT:+rustup target add $TGT --toolchain $TC >/dev/null 2>&1;}
  ok && echo toolchain-ok || echo toolchain-BROKEN"
cargo +$TC miri setup ${TGT:+--target $TGT} 2>&1 | tail -1; cargo +$TC miri --version
cd "sdks/$C"; n=$(basename "$D" .rs)
cp -f "$R/tools/pca-implverif/miri/$D" "tests/miri_$n.rs"; cp -f "$R/tools/pca-implverif/miri/common.rs" tests/miri_common.rs
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation -Zmiri-strict-provenance}"
export CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_TARGET_DIR=/tmp/miri-$n
cargo +$TC miri test --release ${TGT:+--target $TGT} --test "miri_$n" -- --test-threads=1 ${TST:+--exact $TST} 2>&1 | grep -a -E "^test |test result|Undefined Behavior|error(\[|:)|panicked|^ *--> " | head -80
exit ${PIPESTATUS[0]}
