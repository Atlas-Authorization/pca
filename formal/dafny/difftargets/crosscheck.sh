#!/usr/bin/env bash
# crosscheck.sh <outdir> <casefile> [targets...]   run every compiled target + the production bridge on one case file and compare transcripts.
# env: PROD=1 (default) also runs packages/pca-verified-core/test/diverse/drive-prod.cts via tsx (needs TSX=/path/to/tsx);
#      SKIP="py" to skip targets. Prints a verdict line per target + md5; exit 1 on ANY difference, writing minimal diffs to $OUT/diff-<t>.txt
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
O="$1"; F="$2"; shift 2; TS="${*:-cs go java py js}"
W="$(mktemp -d)"; rc=0
if [ "${PROD:-1}" = 1 ]; then ( cd "$ROOT/packages/pca-verified-core/test/diverse" && ${TSX:-tsx} drive-prod.cts "$F" > "$W/prod.txt" 2>"$W/prod.err" ) || { echo "prod driver failed"; head -5 "$W/prod.err"; rc=1; }; echo "prod   $(md5sum < "$W/prod.txt" | cut -c1-32) $(wc -l < "$W/prod.txt") lines"; fi
for t in $TS; do case " ${SKIP:-} " in *" $t "*) continue;; esac
  "$HERE/run-target.sh" "$t" "$O" "$F" > "$W/$t.txt" 2>"$W/$t.err"
  echo "$t $(md5sum < "$W/$t.txt" | cut -c1-32) $(wc -l < "$W/$t.txt") lines"
  ref="$W/${REF:-cs}.txt"; [ "${PROD:-1}" = 1 ] && ref="$W/prod.txt"
  if ! cmp -s "$W/$t.txt" "$ref"; then echo "  DIFFERS from reference"; paste -d'\n' "$F" "$W/$t.txt" "$ref" 2>/dev/null | head -0; diff "$ref" "$W/$t.txt" | head -20 > "$O/diff-$t.txt"; rc=1; fi
done
rm -rf "$W"; exit $rc
