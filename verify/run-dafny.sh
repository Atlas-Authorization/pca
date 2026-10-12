#!/usr/bin/env bash
# run-dafny.sh [quick|full]   Verify the Dafny sources with the pinned Dafny (formal/dafny/TOOLCHAIN.lock).
#   quick  the verified decision core only (Common Chain Caveats Threshold Replay Verdict) + the forbidden-construct audit
#   full   quick + the standalone extension components (Wire Merkle Taint Attest PolicyVm Regex) + the glue contract
# `dafny` must be on PATH (or DAFNY_DIR set). The audit rejects assume / {:axiom} / {:extern} / {:verify false}.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; D="$ROOT/formal/dafny"; MODE="${1:-full}"
[ -n "${DAFNY_DIR:-}" ] && export PATH="$DAFNY_DIR:$PATH"
command -v dafny >/dev/null || { echo "dafny not found: run verify/install-toolchain.sh dafny (or set DAFNY_DIR)" >&2; exit 2; }
FLAGS="--allow-warnings --verification-time-limit ${TL:-120} --resource-limit 0"
rc=0; cd "$D"
echo "== toolchain pin"; ./verify-toolchain.sh || rc=1
echo "== core: no assume/axiom/extern"
if grep -nE '^[^/]*(\bassume\b|\{:axiom\}|\{:extern|\bextern\b|\{:verify +false)' ./*.dfy; then echo "FORBIDDEN construct found"; rc=1; fi
echo "== core proofs"; ./build.sh --verify-only || rc=1
if [ "$MODE" = full ]; then
  for c in Wire Merkle Taint Attest PolicyVm Regex; do
    echo "== $c (standalone)"; dafny verify "$c.dfy" $FLAGS || rc=1
  done
  echo "== GlueContract"; dafny verify GlueContract.dfy --verify-included-files $FLAGS || rc=1
fi
[ $rc = 0 ] && echo "DAFNY: ALL VERIFIED" || echo "DAFNY: FAILURES" >&2
exit $rc
