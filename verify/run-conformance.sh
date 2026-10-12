#!/usr/bin/env bash
# run-conformance.sh [smoke|full] [shard total]   Model-to-code conformance: the executable models in
# tools/pca-formal/conformance are run against the real TypeScript implementation (packages/pca) and must agree on every case;
# then the harness self-test (deliberately broken model mutants must all be killed).
#   smoke  thousands of cases, minutes.   full  ~10^6 random cases + exhaustive small scopes (hours; shard across machines with: full <shard> <total>)
# Output: .verify-work/conformance/*.json (one per stage); the verdict is "disagree": 0 in every file.
# Needs: node >= 20, pnpm install (repo root) so that tsx is available. Differential/sampled testing, NOT a proof.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; P="${1:-smoke}"; S="${2:-0}"; T="${3:-1}"
OUT="$ROOT/.verify-work/conformance"; mkdir -p "$OUT"
TSX="$ROOT/packages/pca/node_modules/.bin/tsx"; [ -x "$TSX" ] || TSX="$(command -v tsx || true)"
[ -n "$TSX" ] || { echo "tsx not found: run 'pnpm install' at the repo root" >&2; exit 2; }
if [ "$P" = full ]; then K1=1; RAND=1300000; SEQR=100000; THR=700000; ATT=60000; else K1=0; RAND=3000; SEQR=300; THR=3000; ATT=500; fi
cd "$ROOT/tools/pca-formal/conformance"
run() { "$TSX" "$@"; }
{ run run.ts single-exh 0 "$S/$T" > "$OUT/single-exh0-$S.json"
  [ "$K1" = 1 ] && run run.ts single-exh 1 "$S/$T" > "$OUT/single-exh1-$S.json"
  run run.ts single-rand "$RAND" $((100+S)) "$S/$T" > "$OUT/single-rand-$S.json"
  run seq.ts exh 2 "$S/$T" > "$OUT/seq-exh2-$S.json"
  run seq.ts rand "$SEQR" $((200+S)) "$S/$T" > "$OUT/seq-rand-$S.json"
  run thr.ts exh "$S/$T" > "$OUT/thr-exh-$S.json"
  run thr.ts rand "$THR" $((300+S)) "$S/$T" > "$OUT/thr-rand-$S.json"
  run att.ts exh > "$OUT/att-exh-$S.json"
  run att.ts rand "$ATT" $((400+S)) > "$OUT/att-rand-$S.json"; } 2> "$OUT/stderr-$S.txt"
python3 "$ROOT/tools/pca-formal/summarize.py" "$OUT" || true
bad=$(grep -l '"disagree": *[1-9]' "$OUT"/*.json 2>/dev/null | wc -l | tr -d ' ')
echo "files with disagreement: $bad"
echo "== harness self-test (mutants must be KILLED)"
bash "$ROOT/tools/pca-formal/mutants.sh" | tee "$OUT/mutants-$S.txt"
survived=$(grep -c SURVIVED "$OUT/mutants-$S.txt" || true)
echo "surviving model mutants: $survived (equivalent ones, if any, are explained in docs/security/formal-verification.md)"
[ "$bad" = 0 ]
