#!/usr/bin/env bash
# run-all.sh : the whole trusted-base shrinking pipeline on a box that has the pinned Dafny (see formal/dafny/verify-toolchain.sh --install).
#   1 toolchain pin  2 proofs (core + glue contract)  3 generated JS reproducibility  4 diverse compilation (5 targets + bridge, golden + miscompile self-test)
#   5 SBOM freshness  6 [CAMPAIGN=n] million-case campaign   7 [PRIMS=1] N-version primitive + glue contract suites (tools/pca-trustbase/{primitives,glue}/run.sh if present)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; D="$ROOT/formal/dafny"
export PATH="${DAFNY_DIR:-/work/tools/dafny}:$HOME/go/bin:$PATH"; rc=0
step() { echo; echo "=== $*"; }
step "1. toolchain pin";                 "$D/verify-toolchain.sh" --runtimes || rc=1
step "2a. proofs (core)";                (cd "$D" && ./build.sh --verify-only) || rc=1
step "2b. proofs (glue contract)";       (cd "$D" && dafny verify GlueContract.dfy --verify-included-files --allow-warnings --verification-time-limit 120 2>&1 | grep -E "verified|Error") || rc=1
step "3. generated JS == fresh compile"; (cd "$D" && ./build.sh --check) || rc=1
step "4. diverse compilation";           OUT="${OUT:-/work/difft}" TSX="${TSX:-}" "$D/difftargets/ci-check.sh" || rc=1
step "5. SBOM";                          node "$HERE/gen-sbom.mjs" --check || rc=1
[ -n "${CAMPAIGN:-}" ] && { step "6. campaign";  "$D/difftargets/scale-run.sh" "${OUT:-/work/difft}" "$CAMPAIGN" 250000 4 || rc=1; }
if [ -n "${PRIMS:-}" ]; then   # BOX=<id> required (see tools/pca-trustbase/primitives/cloud.sh, glue/run-glue.sh); run from a Mac/CI host with cloud access
  step "7a. primitives"; BOX="$BOX" bash "$HERE/primitives/cloud.sh" run --suite vectors,hash,hmac,edsign,edadv,edrand,pq --n-hash 1100000 --n-ed 150000 --n-pq 100 --adv-per-cat 200 --out /work/pr/run || rc=1
  step "7b. glue monitor"; BOX="$BOX" bash "$HERE/glue/run-glue.sh" 100000 3 || rc=1
fi
[ $rc = 0 ] && echo "ALL TRUSTBASE CHECKS PASSED" || echo "TRUSTBASE CHECK FAILURES" >&2; exit $rc
