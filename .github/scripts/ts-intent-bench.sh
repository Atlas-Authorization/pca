#!/usr/bin/env bash
# ts-intent-bench.sh <out-dir> [min-cases]   (repo root; pnpm install + build done)
# Runs the Intent Fidelity Benchmark (packages/pca-intent: `bench` script, bench/run.ts) with its deterministic seeds, writes
# results.json + REPORT.md to <out-dir>, and fails unless every case's hand label was re-derived exactly (label_ok) and the
# benchmark has at least <min-cases> cases (default 300).
set -euo pipefail
OUT="$1"; MIN="${2:-300}"; mkdir -p "$OUT"
TSX=packages/pca/node_modules/.bin/tsx
[ -x "$TSX" ] || TSX=node_modules/.bin/tsx
( cd packages/pca-intent && "../../$TSX" bench/run.ts "$OUT" ) | tee "$OUT/REPORT.md"
node -e '
const rows = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
const min = Number(process.argv[2]);
const bad = rows.filter((r) => r.label_ok === false).map((r) => r.id);
console.log(`cases: ${rows.length} (minimum ${min}); label check failures: ${bad.length}`);
if (bad.length) { console.error("labels not confirmed: " + bad.join(", ")); process.exit(1); }
if (rows.length < min) { console.error(`the benchmark has ${rows.length} cases, fewer than the required ${min}`); process.exit(1); }
' "$OUT/results.json" "$MIN"
