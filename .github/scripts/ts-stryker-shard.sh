#!/usr/bin/env bash
# ts-stryker-shard.sh <k> <n> <out-dir>   (repo root; pnpm install + build done; tools/pca-audit npm-installed)
# Runs Stryker (tools/pca-audit/stryker/run.sh: vitest runner, perTest coverage, the audited base config) over shard k of the
# plan from ts-stryker-plan.mjs, one run per package, and copies each JSON report to <out-dir>/<package>__<k>.json.
# Fails if any planned package produced no report (a failing dry run must not look like "no survivors").
set -uo pipefail
K="$1"; N="$2"; OUT="$3"; mkdir -p "$OUT"
node .github/scripts/ts-stryker-plan.mjs "$K" "$N" > "$OUT/plan-$K.txt"
echo "shard $K/$N plan:"; awk '{print "  " $1 ": " NF-1 " file(s)"}' "$OUT/plan-$K.txt"
rc=0
while read -r pkg files; do
  [ -n "$pkg" ] || continue
  name="${pkg}__${K}"
  echo "::group::stryker $pkg ($(echo $files | wc -w) files)"
  # Stryker leaves .gitignore'd files out of its sandbox; tracked test fixtures that match a public-tree ignore rule
  # (e.g. a captured run.log) must still be copied, or the dry run fails on a missing fixture.
  # shellcheck disable=SC2086
  PKG="$pkg" EXTRA_IGNORE='!**/fixtures/**' bash tools/pca-audit/stryker/run.sh "$name" $files
  echo "::endgroup::"
  if [ -f "/tmp/pca-audit-stryker/$name.json" ]; then cp "/tmp/pca-audit-stryker/$name.json" "$OUT/$name.json"
  else echo "::error::no Stryker report for $pkg (dry run failed?)"; rc=1; fi
done < "$OUT/plan-$K.txt"
exit "$rc"
