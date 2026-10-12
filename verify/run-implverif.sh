#!/usr/bin/env bash
# run-implverif.sh   The parts of the implementation-verification lane that run from THIS repository alone:
#   - Verus proofs of the transliterated fragments (tools/pca-implverif/verus/*.rs)       needs `verus` on PATH
#   - the independent Lean 4 reference model and its differential cross-check              needs elan/lake
# NOT run here: the Kani / CBMC / Miri / valgrind lanes. They verify the SHIPPING Rust/C sources of the native verifiers
# (rust-pca, stark-pca, ...), which live in their own repositories (see verifiers/README.md). Their drivers and recorded
# results are in tools/pca-implverif/ (kani-*/, miri/, results/); the scripts there assume a scratch layout described in
# the headers of kani-queue.sh and miri-run.sh and must be pointed at a checkout of those repositories.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; IV="$ROOT/tools/pca-implverif"; rc=0
if command -v verus >/dev/null; then
  for f in "$IV"/verus/*.rs; do echo "== verus $(basename "$f")"; verus "$f" || rc=1; done
else echo "SKIPPED: verus not on PATH (verify/install-toolchain.sh verus)"; rc=3; fi
if command -v lake >/dev/null; then
  echo "== lean-ref"; (cd "$IV/lean-ref" && lake build) || rc=1
  echo "== lean-xcheck"; (cd "$ROOT/tools/pca-formal/lean-xcheck" && lake build) || rc=1
else echo "SKIPPED: lake not on PATH (verify/install-toolchain.sh lean)"; rc=3; fi
exit $rc
