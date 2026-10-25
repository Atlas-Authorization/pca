#!/usr/bin/env bash
# assert-runner.sh -w <workspace> -s <src/x.ts> -t "<test files>" [-j 4] [-o outdir] [-b backlog.txt -g pca/src/x.ts] [-l a-b] [-m mutants.jsonl] [-T timeoutMs]
# See README.md. Copies the workspace j times, applies each mutant to its own copy, runs one-fork vitest (json reporter, NO bail)
# over the given tests, and classifies each mutant: KILLED_ASSERT / KILLED_ERROR / TIMEOUT / SURVIVED / CRASH / NOLOC.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
J=4; OUT=""; BACKLOG=""; TAG=""; LINES=""; MUT=""; TMO=300000
while getopts "w:s:t:j:o:b:g:l:m:T:" o; do case $o in
  w) WS="$(cd "$OPTARG" && pwd)";; s) SRC="$OPTARG";; t) TESTS="$OPTARG";; j) J="$OPTARG";; o) OUT="$OPTARG";; b) BACKLOG="$OPTARG";;
  g) TAG="$OPTARG";; l) LINES="$OPTARG";; m) MUT="$OPTARG";; T) TMO="$OPTARG";; *) sed -n 2,4p "$0"; exit 2;; esac; done
PKG="${PKG:-packages/pca}"
OUT="${OUT:-$(mktemp -d "$HOME/assert-runner-out.XXXX")}"; mkdir -p "$OUT"
if [ -z "$MUT" ]; then
  args=(--pkg-dir "$WS/$PKG" --src "$SRC" --out "$OUT/mutants.jsonl")
  [ -n "$BACKLOG" ] && args+=(--backlog "$BACKLOG" --tag "$TAG")
  [ -n "$LINES" ] && args+=(--lines "$LINES")
  node "$HERE/gen-mutants.mjs" "${args[@]}"
  MUT="$OUT/mutants.jsonl"
fi
# baseline: the tests must pass on the unmodified source
( cd "$WS/$PKG" && ./node_modules/.bin/vitest run --pool=forks --poolOptions.forks.singleFork $TESTS >"$OUT/baseline.log" 2>&1 ) || { echo "baseline FAILS on the unmodified source: see $OUT/baseline.log"; exit 1; }
node -e 'const fs=require("fs");const [mf,o,j]=process.argv.slice(1);const ms=fs.readFileSync(mf,"utf8").trim().split("\n");for(let p=0;p<+j;p++)fs.writeFileSync(o+"/part"+p+".jsonl",ms.filter((_,i)=>i%+j===p).join("\n")+"\n");' "$MUT" "$OUT" "$J"
pids=()
for ((p=0;p<J;p++)); do
  W="$OUT/ws$p"; [ -d "$W" ] || cp -a "$WS" "$W"
  node "$HERE/run-one.cjs" "$W/$PKG" "$SRC" "$OUT/part$p.jsonl" "$OUT/out$p.jsonl" "$TMO" -- $TESTS > "$OUT/worker$p.log" 2>&1 &
  pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid" || true; done
for ((p=0;p<J;p++)); do cmp -s "$WS/$PKG/$SRC" "$OUT/ws$p/$PKG/$SRC" || echo "WARNING: ws$p source differs after the run"; done
cat "$OUT"/out*.jsonl > "$OUT/results.jsonl"
node "$HERE/summarize.cjs" "$OUT/results.jsonl" | tee "$OUT/summary.txt"
[ -n "${KEEP_WS:-}" ] || rm -rf "$OUT"/ws*
echo "results: $OUT/results.jsonl  summary: $OUT/summary.txt"
