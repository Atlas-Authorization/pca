#!/usr/bin/env bash
# Re-check every machine-checked artefact in formal/computational.
#
#   EasyCrypt files : need `easycrypt` with Why3 provers Alt-Ergo, Z3, CVC5 configured
#                     (easycrypt why3config).  Versions used for the recorded run:
#                     EasyCrypt r2026.09-29-ge7eff05, Why3 1.8.2, Alt-Ergo 2.6.4,
#                     Z3 4.8.12, CVC5 1.1.2, OCaml 4.14.2 (opam switch `ec`).
#   Lean files      : need elan with leanprover/lean4:v4.34.1 (core only, no mathlib);
#                     the project depends on ../pca-lean by path (read only).
#
# Usage: formal/computational/check.sh [ec|lean|leanmath|all]      (default: all)
set -uo pipefail
cd "$(dirname "$0")"
what="${1:-all}"
rc=0

if [ "$what" = ec ] || [ "$what" = all ]; then
  if grep -n -E '^\s*admit\b|\badmit\.' ec/*.ec; then echo "FAIL: admit found"; rc=1; fi
  # dependency order matters (each file only requires the ones before it)
  for f in Sig MU PcaCore PcaMultisig Hybrid HybridSUF PcaPedersen Prime61 PcaSpdz PcaSpdzProto PcaCommitROM PcaRomCollision PcaCommitReveal PcaSpdzROM PcaSpdzSeq PcaPrg SigUniq HybridNest; do
    printf '== easycrypt %s.ec ... ' "$f"
    if (cd ec && easycrypt compile -no-eco -timeout 20 -p Alt-Ergo -p Z3 -p CVC5 -I . "$f.ec") >/tmp/ec-$f.log 2>&1; then
      echo OK
    else
      echo FAILED; tail -20 "/tmp/ec-$f.log"; rc=1
    fi
  done
fi

if [ "$what" = lean ] || [ "$what" = all ]; then
  echo "== lake build (lean/)"
  (cd lean && lake build) || rc=1
  printf 'import PcaComp\n#print axioms PcaComp.Chain.chain_attenuation\n#print axioms PcaComp.Chain.no_widening_after\n#print axioms PcaComp.NonMember.nonmember_sound\n#print axioms PcaComp.Fame.decrypt_exponent\n#print axioms PcaComp.Span.span_program_solved\n' \
    | (cd lean && lake env lean --stdin) || rc=1
fi
if [ "$what" = leanmath ] || [ "$what" = all ]; then
  # Mathlib-based: forking lemma, knowledge soundness, primality of 2^61-1.
  # Needs `lake exe cache get` once (Mathlib v4.34.1 prebuilt oleans), then a build of PcaMath.
  echo "== lake build (leanmath/, Mathlib)"
  (cd leanmath && lake build && lake env lean Axioms.lean) || rc=1
fi
exit $rc
