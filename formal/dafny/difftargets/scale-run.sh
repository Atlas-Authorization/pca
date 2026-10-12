#!/usr/bin/env bash
# scale-run.sh <outdir> <chunks> <cases-per-chunk> [parallel]   million-case campaign: seed i for chunk i, --big on odd chunks.
# Each chunk is checked against ALL compiled targets and the production bridge. Summary in <outdir>/scale-summary.txt
# env TSX (path to tsx). Requires build-targets.sh to have been run into <outdir>.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
O="$1"; CH="$2"; PER="$3"; PAR="${4:-4}"
mkdir -p "$O/chunks"
one() { i="$1"; f="$O/chunks/c$i.txt"; big=$((i % 2))
  node "$ROOT/packages/pca-verified-core/test/diverse/gen-cases.mjs" --n "$PER" --seed "$((1000 + i))" --big $big --out "$f"
  if "$HERE/crosscheck.sh" "$O" "$f" > "$O/chunks/r$i.log" 2>&1; then echo "chunk $i OK ($PER cases, big=$big)"; else echo "chunk $i DIVERGED"; cp "$f" "$O/chunks/diverged-$i.txt"; fi
  rm -f "$f"; }
export -f one; export O PER HERE ROOT TSX
seq 1 "$CH" | xargs -P "$PAR" -I{} bash -c 'one {}' | tee "$O/scale-summary.txt"
echo "total cases per target: $((CH * PER))" | tee -a "$O/scale-summary.txt"
