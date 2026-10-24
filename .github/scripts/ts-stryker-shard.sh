#!/usr/bin/env bash
# ts-stryker-shard.sh <k> <n> <out-dir>   (repo root; pnpm install + build done; tools/pca-audit npm-installed)
# Runs Stryker (tools/pca-audit/stryker/run.sh: vitest runner, perTest coverage, the audited base config) over shard k of the
# plan from ts-stryker-plan.mjs, one run per package, and copies each JSON report to <out-dir>/<package>__<k>.json.
# Fails if any planned package produced no report (a failing dry run must not look like "no survivors").
set -uo pipefail
export PCA_MUTATION_RUN=1   # wall-clock budgets in a few tests widen on instrumented code (see input-bounds.test.ts)
K="$1"; N="$2"; OUT="$3"; mkdir -p "$OUT"
node .github/scripts/ts-stryker-plan.mjs "$K" "$N" > "$OUT/plan-$K.txt"
echo "shard $K/$N plan:"; awk '{print "  " $1 ": " NF-1 " file(s)"}' "$OUT/plan-$K.txt"
rc=0
# pca-verified-core: the ext-* glue is covered by differential tests that import the sibling packages/pca SOURCE by a relative
# path (../../pca/src/...), which a Stryker sandbox (two levels deeper) breaks: every ext-* mutant was NoCoverage. Those files run
# IN PLACE with the package's own ext-mutation vitest configs (only the differential + kill suites of the ext-* modules; the
# Merkle differential only for ext-merkle). The remaining files keep the sandboxed default run. Reports are merged into one.
run_group() { # name envs... -- files...
  local gname="$1"; shift
  local -a envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
  # shellcheck disable=SC2086
  env "${envs[@]}" bash tools/pca-audit/stryker/run.sh "$gname" "$@"
}
rc=0
while read -r pkg files; do
  [ -n "$pkg" ] || continue
  name="${pkg}__${K}"
  echo "::group::stryker $pkg ($(echo $files | wc -w) files)"
  # (no ignore negations: a '!' pattern makes Stryker copy the symlinked pnpm node_modules into its sandbox -> EISDIR;
  # the tree's .gitignore already keeps the tracked fixture transcripts)
  if [ "$pkg" = "pca-verified-core" ]; then
    merkle=""; regex=""; attest=""; extother=""; rest=""
    for f in $files; do
      case "$f" in
        src/ext-merkle.ts) merkle="$merkle $f" ;;
        src/ext-attest.ts) attest="$attest $f" ;;
        src/ext-regex.ts) regex="$regex $f" ;;
        src/ext-*.ts) extother="$extother $f" ;;
        *) rest="$rest $f" ;;
      esac
    done
    parts=()
    if [ -n "$rest" ]; then run_group "${name}-rest" PKG="$pkg" -- $rest; parts+=("${name}-rest"); fi
    if [ -n "$extother" ]; then run_group "${name}-ext" PKG="$pkg" INPLACE=1 VITEST_CONFIG=vitest.ext-mutation-nomerkle.config.ts -- $extother; parts+=("${name}-ext"); fi
    if [ -n "$attest" ]; then run_group "${name}-attest" PKG="$pkg" INPLACE=1 VITEST_CONFIG=vitest.ext-mutation-attest.config.ts -- $attest; parts+=("${name}-attest"); fi
    if [ -n "$regex" ]; then run_group "${name}-regex" PKG="$pkg" INPLACE=1 VITEST_CONFIG=vitest.ext-mutation-regex.config.ts -- $regex; parts+=("${name}-regex"); fi
    if [ -n "$merkle" ]; then run_group "${name}-merkle" PKG="$pkg" INPLACE=1 VITEST_CONFIG=vitest.ext-mutation.config.ts -- $merkle; parts+=("${name}-merkle"); fi
    node -e '
      const fs=require("fs"); const [out,...ins]=process.argv.slice(1); let base=null;
      for (const f of ins) { if(!fs.existsSync("/tmp/pca-audit-stryker/"+f+".json")) continue; const j=JSON.parse(fs.readFileSync("/tmp/pca-audit-stryker/"+f+".json","utf8")); if(!base) base=j; else Object.assign(base.files,j.files); }
      if (base) fs.writeFileSync("/tmp/pca-audit-stryker/"+out+".json", JSON.stringify(base));' "$name" "${parts[@]}"
    # a group whose dry run failed must not hide behind the merged report of the others
    for g in "${parts[@]}"; do [ -f "/tmp/pca-audit-stryker/$g.json" ] || { echo "::error::no Stryker report for $g (dry run failed?)"; rc=1; }; done
  elif [ "$pkg" = "pca-mpc" ] && echo " $files " | grep -q ' src/otx.ts '; then
    # otx.ts is imported (through ot.ts) by almost every pca-mpc test, so its mutants were covered by the whole suite (31 min dry run,
    # ~1.4 min per mutant: shard 13 ran 5 h 50 min and was cancelled). Its mutants run against the tests that exercise it directly.
    # Measured on the box: 66-test dry run 1 min, 215 mutants in 18 min, 17 survivors = exactly the 17 ledger entries (no kill lost).
    others=$(echo " $files " | sed 's# src/otx.ts # #')
    parts=()
    if [ -n "$(echo $others)" ]; then run_group "${name}-rest" PKG="$pkg" -- $others; parts+=("${name}-rest"); fi
    run_group "${name}-otx" PKG="$pkg" ONLY_TESTS=src/otx.test.ts,src/mutation-kill-otx.test.ts,src/mutation-kill-ot.test.ts,src/otx-tweak-collision.test.ts,src/net/wire-version.test.ts -- src/otx.ts; parts+=("${name}-otx")
    node -e '
      const fs=require("fs"); const [out,...ins]=process.argv.slice(1); let base=null;
      for (const f of ins) { if(!fs.existsSync("/tmp/pca-audit-stryker/"+f+".json")) continue; const j=JSON.parse(fs.readFileSync("/tmp/pca-audit-stryker/"+f+".json","utf8")); if(!base) base=j; else Object.assign(base.files,j.files); }
      if (base) fs.writeFileSync("/tmp/pca-audit-stryker/"+out+".json", JSON.stringify(base));' "$name" "${parts[@]}"
    for g in "${parts[@]}"; do [ -f "/tmp/pca-audit-stryker/$g.json" ] || { echo "::error::no Stryker report for $g (dry run failed?)"; rc=1; }; done
  elif [ "$pkg" = "pca-mpc" ] && echo " $files " | grep -q ' src/net/party-main.ts '; then
    # party-main.ts runs as a child OS process in its test (mutation-kill-party-main.test.ts forwards the active mutant id through
    # the environment): perTest coverage never sees it (every mutant NoCoverage), so it runs with coverage analysis off and only that test.
    others=$(echo " $files " | sed 's# src/net/party-main.ts # #')
    parts=()
    if [ -n "$(echo $others)" ]; then run_group "${name}-rest" PKG="$pkg" -- $others; parts+=("${name}-rest"); fi
    run_group "${name}-pm" PKG="$pkg" COVERAGE_OFF=1 NO_RELATED=1 ONLY_TESTS=src/net/mutation-kill-party-main.test.ts -- src/net/party-main.ts; parts+=("${name}-pm")
    node -e '
      const fs=require("fs"); const [out,...ins]=process.argv.slice(1); let base=null;
      for (const f of ins) { if(!fs.existsSync("/tmp/pca-audit-stryker/"+f+".json")) continue; const j=JSON.parse(fs.readFileSync("/tmp/pca-audit-stryker/"+f+".json","utf8")); if(!base) base=j; else Object.assign(base.files,j.files); }
      if (base) fs.writeFileSync("/tmp/pca-audit-stryker/"+out+".json", JSON.stringify(base));' "$name" "${parts[@]}"
    for g in "${parts[@]}"; do [ -f "/tmp/pca-audit-stryker/$g.json" ] || { echo "::error::no Stryker report for $g (dry run failed?)"; rc=1; }; done
  elif [ "$pkg" = "pca" ] && echo " $files " | grep -q ' src/frost-net-runner.ts '; then
    # frost-net-runner.ts is an OS-process entry point: its main() only runs in the child processes its tests spawn (the test
    # forwards the active mutant id through the environment), which perTest coverage never sees (all 43 mutants NoCoverage).
    # Like pca-mpc's party-main.ts it runs with coverage analysis off against only its own test.
    others=$(echo " $files " | sed 's# src/frost-net-runner.ts # #')
    parts=()
    if [ -n "$(echo $others)" ]; then run_group "${name}-rest" PKG="$pkg" -- $others; parts+=("${name}-rest"); fi
    run_group "${name}-fnr" PKG="$pkg" COVERAGE_OFF=1 NO_RELATED=1 ONLY_TESTS=src/mutation-kill-r13-g1-frost-net-runner.test.ts -- src/frost-net-runner.ts; parts+=("${name}-fnr")
    node -e '
      const fs=require("fs"); const [out,...ins]=process.argv.slice(1); let base=null;
      for (const f of ins) { if(!fs.existsSync("/tmp/pca-audit-stryker/"+f+".json")) continue; const j=JSON.parse(fs.readFileSync("/tmp/pca-audit-stryker/"+f+".json","utf8")); if(!base) base=j; else Object.assign(base.files,j.files); }
      if (base) fs.writeFileSync("/tmp/pca-audit-stryker/"+out+".json", JSON.stringify(base));' "$name" "${parts[@]}"
    for g in "${parts[@]}"; do [ -f "/tmp/pca-audit-stryker/$g.json" ] || { echo "::error::no Stryker report for $g (dry run failed?)"; rc=1; }; done
  else
    # shellcheck disable=SC2086
    PKG="$pkg" bash tools/pca-audit/stryker/run.sh "$name" $files
  fi
  echo "::endgroup::"
  if [ -f "/tmp/pca-audit-stryker/$name.json" ]; then cp "/tmp/pca-audit-stryker/$name.json" "$OUT/$name.json"
  else echo "::error::no Stryker report for $pkg (dry run failed?)"; rc=1; fi
done < "$OUT/plan-$K.txt"
exit "$rc"
