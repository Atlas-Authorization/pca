#!/usr/bin/env bash
# Adversarial canonical-form cross-language convergence audit.
#   tools/pca-canon-fuzz/run.sh [--seed N] [--count N] [--only go,python,...]
# Reuses the pca-diff-fuzz language drivers (they already speak the kind:"canon" protocol).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DRV="$ROOT/tools/pca-diff-fuzz/drivers"
OUT="${PCA_CANON_OUT:-$HERE/out}"
SEED=3735928559; COUNT=60000; ONLY=""
while [ $# -gt 0 ]; do case "$1" in --seed) SEED=$2; shift 2;; --count) COUNT=$2; shift 2;; --only) ONLY=$2; shift 2;; *) shift;; esac; done
export PATH="$HOME/.cargo/bin:$PATH"
TSX="$ROOT/packages/pca/node_modules/.bin/tsx"
[ -x "$TSX" ] || { echo "tsx not found at $TSX (run pnpm install)"; exit 2; }
mkdir -p "$OUT"; rm -f "$OUT"/impl-*.jsonl "$OUT"/status-*.txt "$OUT"/*.log
want() { [ -z "$ONLY" ] && return 0; case ",$ONLY," in *",$1,"*) return 0;; esac; return 1; }
C="$OUT/corpus.jsonl"

echo "== generate (seed=$SEED count=$COUNT)"
node "$HERE/generate.mjs" "$C" --seed "$SEED" --count "$COUNT" || exit 1
echo "== oracle (TypeScript reference via tsx)"
"$TSX" "$HERE/oracle.ts" "$C" "$OUT/oracle.jsonl" || exit 1

run_impl() { local name=$1; shift; local avail=$1; shift
  want "$name" || return
  if ! eval "$avail" >/dev/null 2>&1; then echo "skipped: toolchain unavailable" >"$OUT/status-$name.txt"; echo "-- $name: SKIPPED (toolchain unavailable)"; return; fi
  local s; s=$(date +%s)
  if "$@" >"$OUT/impl-$name.log" 2>&1 && [ -s "$OUT/impl-$name.jsonl" ]; then echo ran >"$OUT/status-$name.txt"; echo "-- $name: ran in $(( $(date +%s)-s ))s"
  else echo "failed: see impl-$name.log" >"$OUT/status-$name.txt"; echo "-- $name: FAILED (see $OUT/impl-$name.log)"; fi
}

if want go && command -v go >/dev/null 2>&1; then ( cd "$DRV/go" && go build -o "$OUT/go-driver" . ) >"$OUT/build-go.log" 2>&1; fi
run_impl go "test -x '$OUT/go-driver'" "$OUT/go-driver" "$C" "$OUT/impl-go.jsonl" &
run_impl python "python3 -V" python3 -I "$DRV/python/driver.py" "$C" "$OUT/impl-python.jsonl" &
run_impl ruby "ruby -v" ruby "$DRV/ruby/driver.rb" "$C" "$OUT/impl-ruby.jsonl" &
run_impl php "php -v" php "$DRV/php/driver.php" "$C" "$OUT/impl-php.jsonl" &
wait
if want dotnet && command -v dotnet >/dev/null 2>&1; then ( cd "$DRV/dotnet" && dotnet build -c Release -o "$OUT/dotnet-bin" -v q --nologo ) >"$OUT/build-dotnet.log" 2>&1; fi
run_impl dotnet "test -f '$OUT/dotnet-bin/Driver.dll'" dotnet "$OUT/dotnet-bin/Driver.dll" "$C" "$OUT/impl-dotnet.jsonl"
if want rust && command -v cargo >/dev/null 2>&1; then ( cd "$DRV/rust" && CARGO_TARGET_DIR="$OUT/rust-target" cargo build --release ) >"$OUT/build-rust.log" 2>&1; fi
run_impl rust "test -x '$OUT/rust-target/release/pcadriver'" "$OUT/rust-target/release/pcadriver" "$C" "$OUT/impl-rust.jsonl"
if want java && javac -version >/dev/null 2>&1; then
  mkdir -p "$OUT/java-classes" && javac ${PCA_BC_JAR:+-cp "$PCA_BC_JAR"} -d "$OUT/java-classes" "$ROOT"/sdks/java-pca/src/net/atlasauth/pca/*.java "$DRV/java/Driver.java" >"$OUT/build-java.log" 2>&1
fi
run_impl java "test -f '$OUT/java-classes/Driver.class'" java -cp "$OUT/java-classes${PCA_BC_JAR:+:$PCA_BC_JAR}" Driver "$C" "$OUT/impl-java.jsonl"

echo "== compare (byte-identical canonical output vs TS oracle)"
node "$HERE/check.mjs" "$OUT"
rc=$?
echo "Report: $OUT/CANON-REPORT.md   machine-readable: $OUT/canon-report.json"
exit $rc
