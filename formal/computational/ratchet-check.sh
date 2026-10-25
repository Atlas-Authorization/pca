#!/usr/bin/env bash
# ratchet-check.sh: build PcaMath.Ratchet (GG-2, Mathlib) and audit its axioms. FARM ONLY:
#   PCAQ_OWNER=crypto-proofs cloud-box tooling/q submit --box sp4 --cores 2 --mem 12 --wall 7200 --prep none \
#     --pull formal/computational/ratchet-check.txt --wait -- bash formal/computational/ratchet-check.sh
set -uo pipefail
R="$(cd "$(dirname "$0")" && pwd)"
OUT="$R/ratchet-check.txt"
export PATH="$HOME/.elan/bin:$PATH"
command -v lake >/dev/null 2>&1 || { curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none >/dev/null; export PATH="$HOME/.elan/bin:$PATH"; }
cd "$R/leanmath"
shared=""
for d in /work/comp/leanmath/.lake/packages /work/cs/leanmath/.lake/packages "$HOME/.cache/pca-intent/packages"; do
  [ -d "$d/mathlib/.lake/build" ] && { shared="$d"; break; }
done
mkdir -p .lake
if [ -n "$shared" ]; then ln -sfn "$shared" .lake/packages
else pk="$HOME/.cache/pca-intent/packages"; mkdir -p "$pk"; ln -sfn "$pk" .lake/packages
  ( flock 9; lake exe cache get 2>&1 | tr '\r' '\n' | tail -3 ) 9>"$HOME/.cache/pca-intent/lock"; fi
{
  echo "# $(date -u +%FT%TZ) host $(hostname); Lean $(lake env lean --version 2>/dev/null | head -1)"
  if grep -nE '\bsorry\b|\badmit\b' PcaMath/Ratchet.lean; then echo "FOUND sorry/admit"; fi
  lake build PcaMath.Ratchet 2>&1 | grep -vE '^(⣿|info:)' | tail -60
  echo "build rc=${PIPESTATUS[0]}"
  printf 'import PcaMath.Ratchet\n#print axioms PcaMath.Ratchet.hybrid\n#print axioms PcaMath.Ratchet.full\n#print axioms PcaMath.Ratchet.expand_factor\n#print axioms PcaMath.Ratchet.gg2\n' | lake env lean --stdin 2>&1
} 2>&1 | tee "$OUT"
grep -q 'build rc=0' "$OUT" && ! grep -q sorryAx "$OUT"
