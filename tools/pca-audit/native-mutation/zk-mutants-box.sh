#!/usr/bin/env bash
# Queue job (run from the repo root of a private snapshot): cargo-mutants over one zk crate, one shard.
#   usage: zk-mutants-box.sh <sdks/crate> <k/n> [extra cargo-mutants args, e.g. -p pca-zkvm-core]
#   e.g.   q submit --cores 4 --mem 12 --wall 7200 --pull /tmp/zkmut -- 'bash tools/pca-audit/native-mutation/zk-mutants-box.sh sdks/stark-pca 0/2'
# ZK_BUDGET_S: optional; stop cargo-mutants after N seconds so partial outcomes are pulled back. Unset/0 = no budget (default).
# Results -> /tmp/zkmut/<crate>-<k>of<n>/mutants.out (missed.txt / timeout.txt / outcomes.json). MJ = parallel mutants (default 2).
set -u
D="${1:?crate dir}"; SH="${2:?shard k/n}"; shift 2
OUT="/tmp/zkmut/$(basename "$D")-${SH%/*}of${SH#*/}"; rm -rf "$OUT"; mkdir -p "$OUT"
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"; unset CARGO_TARGET_DIR
command -v cargo-mutants >/dev/null || cargo install cargo-mutants --locked >/dev/null 2>&1
# cargo-mutants copies the crate to $TMPDIR/cargo-mutants-*.tmp; tests that reach the repo by relative path
# (include_str!("../../../../packages/...") from <crate>/core/tests) need packages/ and tools/ two levels above the copy.
MT="/tmp/zkmut-tmp/a"; mkdir -p "$MT/b"; ln -sfn "$(pwd)/packages" "$MT/packages"; ln -sfn "$(pwd)/tools" "$MT/tools"; export TMPDIR="$MT/b"
cd "$D" || exit 2
TO=(); [ "${ZK_BUDGET_S:-0}" -gt 0 ] && TO=(timeout --signal=INT --kill-after=120 "$ZK_BUDGET_S")
"${TO[@]}" cargo mutants --output "$OUT" --shard "$SH" --no-shuffle -j "${MJ:-2}" --minimum-test-timeout 120 --timeout-multiplier 4 "$@" > "$OUT/run.log" 2>&1
rc=$?
grep -E "^(MISSED|TIMEOUT)|mutants tested" "$OUT/run.log"; echo "MUTRC=$rc"
