#!/usr/bin/env bash
# One-shot cross-implementation PCA audit. Usage: tools/pca-diff-fuzz/run.sh [--seed N] [--bases N] [--only go,python,...]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${PCA_FUZZ_OUT:-$HERE/out}"
SEED=20261006; BASES=1000; ONLY=""
while [ $# -gt 0 ]; do case "$1" in --seed) SEED=$2; shift 2;; --bases) BASES=$2; shift 2;; --only) ONLY=$2; shift 2;; *) shift;; esac; done
export PATH="$HOME/.cargo/bin:$PATH"
TSX="$ROOT/packages/pca/node_modules/.bin/tsx"
[ -x "$TSX" ] || { echo "tsx not found at $TSX (run pnpm install)"; exit 2; }
mkdir -p "$OUT"; rm -f "$OUT"/impl-*.jsonl "$OUT"/status-*.txt
want() { [ -z "$ONLY" ] && return 0; case ",$ONLY," in *",$1,"*) return 0;; esac; return 1; }

echo "== generate (seed=$SEED bases=$BASES)"
"$TSX" "$HERE/gen/generate.ts" "$OUT" --seed "$SEED" --bases "$BASES" || exit 1
echo "== oracle (TypeScript source)"
"$TSX" "$HERE/gen/oracle.ts" "$OUT/corpus.jsonl" "$OUT/oracle.jsonl" || exit 1

run_impl() { # name  available-cmd  run-cmd...
  local name=$1; shift; local avail=$1; shift
  want "$name" || return
  if ! eval "$avail" >/dev/null 2>&1; then echo "skipped: toolchain unavailable" >"$OUT/status-$name.txt"; echo "-- $name: SKIPPED (toolchain unavailable)"; return; fi
  local s=$(date +%s)
  if "$@" >"$OUT/impl-$name.log" 2>&1 && [ -s "$OUT/impl-$name.jsonl" ]; then echo ran >"$OUT/status-$name.txt"; echo "-- $name: ran in $(( $(date +%s)-s ))s"
  else echo "failed: see impl-$name.log" >"$OUT/status-$name.txt"; echo "-- $name: FAILED (see $OUT/impl-$name.log)"; fi
}
C="$OUT/corpus.jsonl"
( cd "$HERE/drivers/go" && go build -o "$OUT/go-driver" . ) >"$OUT/build-go.log" 2>&1
run_impl go "test -x '$OUT/go-driver'" "$OUT/go-driver" "$C" "$OUT/impl-go.jsonl" &
run_impl python "python3 -V" python3 -I "$HERE/drivers/python/driver.py" "$C" "$OUT/impl-python.jsonl" &
run_impl ruby "ruby -v" ruby "$HERE/drivers/ruby/driver.rb" "$C" "$OUT/impl-ruby.jsonl" &
run_impl php "php -v" php "$HERE/drivers/php/driver.php" "$C" "$OUT/impl-php.jsonl" &
wait
if want dotnet && command -v dotnet >/dev/null 2>&1; then
  ( cd "$HERE/drivers/dotnet" && dotnet build -c Release -o "$OUT/dotnet-bin" -v q --nologo ) >"$OUT/build-dotnet.log" 2>&1
fi
run_impl dotnet "test -f '$OUT/dotnet-bin/Driver.dll'" dotnet "$OUT/dotnet-bin/Driver.dll" "$C" "$OUT/impl-dotnet.jsonl"
if want rust && command -v cargo >/dev/null 2>&1; then ( cd "$HERE/drivers/rust" && CARGO_TARGET_DIR="$OUT/rust-target" cargo build --release ) >"$OUT/build-rust.log" 2>&1; fi
run_impl rust "test -x '$OUT/rust-target/release/pcadriver'" "$OUT/rust-target/release/pcadriver" "$C" "$OUT/impl-rust.jsonl"
if want java && javac -version >/dev/null 2>&1; then
  mkdir -p "$OUT/java-classes" && javac ${PCA_BC_JAR:+-cp "$PCA_BC_JAR"} -d "$OUT/java-classes" "$ROOT"/sdks/java-pca/src/net/atlasauth/pca/*.java "$HERE/drivers/java/Driver.java" >"$OUT/build-java.log" 2>&1
fi
run_impl java "test -f '$OUT/java-classes/Driver.class'" java -cp "$OUT/java-classes${PCA_BC_JAR:+:$PCA_BC_JAR}" Driver "$C" "$OUT/impl-java.jsonl"
echo "== compare"
node "$HERE/compare.mjs" "$OUT"
node "$HERE/extract-counterexamples.mjs" "$OUT"
echo "== runtime sanity (is this Node's JSON.parse stable? affects only the generator/oracle, which use a spec parser)"
node "$HERE/repro/node-jsonparse-escaped-keys.mjs" | head -1
echo "Report: $OUT/REPORT.md   machine-readable: $OUT/report.json   counterexamples: $HERE/counterexamples/"
